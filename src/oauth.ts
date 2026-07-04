import type { GateProvider } from "./gate";

export interface OAuthIdentifyInput {
  accessToken: string;
  /**
   * The token endpoint's full parsed response — for extras like id_token
   * (OIDC IdPs), granted scope, or refresh_token. Shape is IdP-specific.
   */
  tokenResponse: unknown;
}

export interface OAuthProviderConfig<Data extends {}> {
  authorizeEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  /** Must cover whatever identify() fetches — scope and identify are a pair */
  scope?: string;
  /** Extra query params appended on silent re-authorization, e.g. { prompt: "none" } */
  silentParams?: Record<string, string>;
  /** Fetch the data about the visitor that the gate's filter will judge */
  identify(input: OAuthIdentifyInput): Promise<Data | null>;
}

/**
 * Build a GateProvider from a vanilla OAuth2 authorization-code flow.
 * Covers the protocol plumbing (authorize URL, code→token exchange);
 * you supply the endpoints and the data-fetching identify().
 *
 * IdPs with heavier dialects (PKCE-required, custom token auth) are better
 * served by implementing GateProvider directly, e.g. on top of openid-client.
 */
export function oauthProvider<Data extends {}>(
  config: OAuthProviderConfig<Data>,
): GateProvider<Data> {
  return {
    authorizeUrl({ redirectUri, state, silent }) {
      const url = new URL(config.authorizeEndpoint);
      url.searchParams.set("client_id", config.clientId);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("redirect_uri", redirectUri);
      if (config.scope) url.searchParams.set("scope", config.scope);
      url.searchParams.set("state", state);
      if (silent) {
        for (const [key, value] of Object.entries(config.silentParams ?? {})) {
          url.searchParams.set(key, value);
        }
      }
      return url.toString();
    },

    async identify({ code, redirectUri }) {
      const res = await fetch(config.tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          // some IdPs (GitHub) answer form-urlencoded unless asked for JSON
          Accept: "application/json",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          client_id: config.clientId,
          client_secret: config.clientSecret,
          redirect_uri: redirectUri,
        }).toString(),
      });
      if (!res.ok) return null;
      const data: unknown = await res.json();
      if (
        typeof data !== "object" ||
        data === null ||
        !("access_token" in data) ||
        typeof data.access_token !== "string" ||
        data.access_token === ""
      ) {
        return null;
      }

      return config.identify({
        accessToken: data.access_token,
        tokenResponse: data,
      });
    },
  };
}
