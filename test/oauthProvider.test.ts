import { afterEach, describe, expect, it, vi } from "vitest";
import { oauthProvider } from "../src/index";

function makeProvider() {
  return oauthProvider({
    authorizeEndpoint: "https://idp.example/oauth/authorize",
    tokenEndpoint: "https://idp.example/oauth/token",
    clientId: "my-client",
    clientSecret: "my-secret",
    scope: "read:things",
    silentParams: { prompt: "none" },
    identify: async ({ accessToken }) => ({ token: accessToken }),
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("oauthProvider", () => {
  it("builds a standard OAuth2 authorize URL", () => {
    const url = new URL(
      makeProvider().authorizeUrl({
        redirectUri: "https://app.example/auth/callback",
        state: "st1",
        silent: false,
      }),
    );
    expect(url.origin + url.pathname).toBe("https://idp.example/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe("my-client");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example/auth/callback");
    expect(url.searchParams.get("scope")).toBe("read:things");
    expect(url.searchParams.get("state")).toBe("st1");
    expect(url.searchParams.get("prompt")).toBeNull();
  });

  it("appends silentParams only for silent re-authorization", () => {
    const url = new URL(
      makeProvider().authorizeUrl({
        redirectUri: "https://app.example/auth/callback",
        state: "st1",
        silent: true,
      }),
    );
    expect(url.searchParams.get("prompt")).toBe("none");
  });

  it("exchanges the code and hands the access token to identify", async () => {
    const fetchMock = vi.fn(async () => Response.json({ access_token: "tok" }));
    vi.stubGlobal("fetch", fetchMock);

    const data = await makeProvider().identify({
      code: "c1",
      redirectUri: "https://app.example/auth/callback",
    });

    expect(data).toEqual({ token: "tok" });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://idp.example/oauth/token");
    expect(init.method).toBe("POST");
    // GitHub-style token endpoints answer form-urlencoded without this
    expect((init.headers as Record<string, string>).Accept).toBe("application/json");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("c1");
    expect(body.get("client_id")).toBe("my-client");
    expect(body.get("client_secret")).toBe("my-secret");
    expect(body.get("redirect_uri")).toBe("https://app.example/auth/callback");
  });

  it("hands identify the whole token response for id_token-style extras", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ access_token: "tok", id_token: "jwt-here", scope: "s" })),
    );
    const provider = oauthProvider({
      authorizeEndpoint: "https://idp.example/oauth/authorize",
      tokenEndpoint: "https://idp.example/oauth/token",
      clientId: "my-client",
      clientSecret: "my-secret",
      identify: async ({ tokenResponse }) => ({ raw: tokenResponse }),
    });
    const data = await provider.identify({
      code: "c1",
      redirectUri: "https://app.example/auth/callback",
    });
    expect(data).toEqual({
      raw: { access_token: "tok", id_token: "jwt-here", scope: "s" },
    });
  });

  it("returns null when the token exchange fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("bad", { status: 400 })),
    );
    const data = await makeProvider().identify({
      code: "expired",
      redirectUri: "https://app.example/auth/callback",
    });
    expect(data).toBeNull();
  });
});
