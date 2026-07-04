import { sign, verify } from "./cookie";

export interface AuthorizeUrlInput {
  redirectUri: string;
  state: string;
  /**
   * true when re-authorizing a returning visitor whose session just expired.
   * OAuth-style providers may map this to prompt=none for a seamless refresh.
   */
  silent: boolean;
}

export interface IdentifyInput {
  code: string;
  redirectUri: string;
}

/**
 * The pluggable half of the gate: where to send visitors to prove themselves,
 * and how to fetch the data about them that the filter will judge.
 *
 * Contract: authorizeUrl must request whatever scope/claims identify() needs
 * to gather its data — the two are a pair. Providers procure, filters decide.
 */
export interface GateProvider<Data extends {} = {}> {
  /** Build the URL the visitor is redirected to for authorization */
  authorizeUrl(input: AuthorizeUrlInput): string;
  /** Fetch the data about the returning visitor; null = could not identify */
  identify(input: IdentifyInput): Promise<Data | null>;
}

export interface GateFilterContext {
  request: Request;
}

export interface GateConfig<Data extends {} = {}> {
  /** HMAC key for the session and state cookies, e.g. env.COOKIE_SECRET */
  cookieSecret: string;
  provider: GateProvider<Data>;
  /**
   * The authorization decision: given the data the provider identified,
   * decide whether to let the visitor in. Runs on every (re-)login.
   * Omitted = anyone the provider can identify is admitted.
   */
  filter?: (
    data: Data,
    context: GateFilterContext,
  ) => boolean | Promise<boolean>;
  /**
   * Custom 403 response for visitors the provider couldn't identify or the
   * filter rejected. Default: a minimal built-in HTML page.
   */
  denied?: (context: GateFilterContext) => Response | Promise<Response>;
  /**
   * Custom response for non-document requests (fetch/XHR) without a valid
   * session. Default: a plain-text 401. loginUrl carries the returnTo.
   */
  unauthorized?: (context: {
    request: Request;
    loginUrl: string;
  }) => Response | Promise<Response>;
  /**
   * Custom sign-in screen for unauthenticated document requests.
   * Default: redirect straight to the provider's authorize URL.
   * Not consulted for silent re-authorization of expired sessions,
   * which stays a seamless redirect. loginUrl carries the returnTo.
   */
  signin?: (context: {
    request: Request;
    loginUrl: string;
  }) => Response | Promise<Response>;
  loginPath?: string;
  callbackPath?: string;
  logoutPath?: string;
  sessionTtlSeconds?: number;
  cookieName?: string;
  stateCookieName?: string;
}

/**
 * Returns a Response when the gate handles or denies the request
 * (auth routes, redirects, 401/403), and null when the visitor may pass.
 */
export type Gate = (request: Request) => Promise<Response | null>;

interface SessionPayload {
  exp: number;
}

interface StatePayload {
  state: string;
  returnTo: string;
  exp: number;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function redirect(location: string): Response {
  return new Response(null, { status: 302, headers: { Location: location } });
}

function randomState(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function forbiddenHtml(loginPath: string): string {
  return `<!doctype html>
<meta charset="utf-8">
<title>403 Forbidden</title>
<p>You are not authorized to access this application.</p>
<p><a href="${loginPath}">Sign in again</a></p>`;
}

function isSessionPayload(value: unknown): value is SessionPayload {
  return (
    typeof value === "object" &&
    value !== null &&
    "exp" in value &&
    typeof value.exp === "number"
  );
}

function isStatePayload(value: unknown): value is StatePayload {
  return (
    typeof value === "object" &&
    value !== null &&
    "state" in value &&
    typeof value.state === "string" &&
    "returnTo" in value &&
    typeof value.returnTo === "string" &&
    "exp" in value &&
    typeof value.exp === "number"
  );
}

export function createGate<Data extends {}>(config: GateConfig<Data>): Gate {
  const {
    cookieSecret,
    provider,
    filter,
    denied,
    unauthorized,
    signin,
    loginPath = "/auth/login",
    callbackPath = "/auth/callback",
    logoutPath = "/auth/logout",
    sessionTtlSeconds = 60 * 60 * 24,
    cookieName = "__gate",
    stateCookieName = "__gate_state",
  } = config;

  if (!cookieSecret) {
    throw new TypeError("createGate: cookieSecret is empty");
  }

  return async function gate(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    const redirectUri = `${url.origin}${callbackPath}`;

    const readCookie = (name: string): string | null => {
      const header = request.headers.get("Cookie") ?? "";
      for (const part of header.split(/;\s*/)) {
        const eq = part.indexOf("=");
        if (eq > 0 && part.slice(0, eq) === name) return part.slice(eq + 1);
      }
      return null;
    };

    const safeReturnTo = (value: string | null | undefined): string =>
      value?.startsWith("/") && !value.startsWith("//") ? value : "/";

    const startLogin = async (silent: boolean): Promise<Response> => {
      const state = randomState();
      const returnTo = safeReturnTo(url.searchParams.get("returnTo"));
      const stateToken = await sign(
        { state, returnTo, exp: nowSec() + 600 } satisfies StatePayload,
        cookieSecret,
      );
      const res = redirect(provider.authorizeUrl({ redirectUri, state, silent }));
      res.headers.set(
        "Set-Cookie",
        `${stateCookieName}=${stateToken}; Path=${callbackPath}; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
      );
      return res;
    };

    const handleCallback = async (): Promise<Response> => {
      const stateToken = readCookie(stateCookieName);
      const verified = stateToken
        ? await verify(stateToken, cookieSecret)
        : null;
      const statePayload =
        verified && !verified.expired && isStatePayload(verified.payload)
          ? verified.payload
          : null;

      // providers report failed silent re-auth as an error param;
      // fall back to interactive login instead of surfacing it
      if (url.searchParams.get("error")) {
        const returnTo = safeReturnTo(statePayload?.returnTo);
        return redirect(`${loginPath}?returnTo=${encodeURIComponent(returnTo)}`);
      }

      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!statePayload || !code || !state || state !== statePayload.state) {
        return new Response("Invalid OAuth state", { status: 400 });
      }

      const data = await provider.identify({ code, redirectUri });
      // loose != so a sloppy provider resolving undefined fails closed
      const allowed =
        data != null && (filter ? await filter(data, { request }) : true);
      if (!allowed) {
        if (denied) return denied({ request });
        return new Response(forbiddenHtml(loginPath), {
          status: 403,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      const session = await sign(
        { exp: nowSec() + sessionTtlSeconds } satisfies SessionPayload,
        cookieSecret,
      );
      const res = redirect(safeReturnTo(statePayload.returnTo));
      res.headers.append(
        "Set-Cookie",
        `${cookieName}=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${sessionTtlSeconds}`,
      );
      res.headers.append(
        "Set-Cookie",
        `${stateCookieName}=; Path=${callbackPath}; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      );
      return res;
    };

    const logout = (): Response => {
      const res = redirect("/");
      res.headers.set(
        "Set-Cookie",
        `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
      );
      return res;
    };

    switch (url.pathname) {
      case loginPath:
        return startLogin(url.searchParams.get("silent") === "1");
      case callbackPath:
        return handleCallback();
      case logoutPath:
        return logout();
    }

    const sessionToken = readCookie(cookieName);
    const verified = sessionToken
      ? await verify(sessionToken, cookieSecret)
      : null;
    const session =
      verified && isSessionPayload(verified.payload) ? verified.payload : null;
    if (session && !verified?.expired) {
      return null; // authorized — the request is yours
    }

    const returnTo = encodeURIComponent(url.pathname + url.search);
    const loginUrl = `${loginPath}?returnTo=${returnTo}`;

    const isDocument =
      request.headers.get("Sec-Fetch-Dest") === "document" ||
      (request.headers.get("Accept") ?? "").includes("text/html");
    if (!isDocument) {
      if (unauthorized) return unauthorized({ request, loginUrl });
      return new Response("Unauthorized", { status: 401 });
    }

    // a validly-signed but expired session means a returning visitor:
    // silent re-authorization stays a seamless redirect, skipping signin
    if (session) return redirect(`${loginUrl}&silent=1`);

    if (signin) return signin({ request, loginUrl });
    return redirect(loginUrl);
  };
}
