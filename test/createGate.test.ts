import { describe, expect, it, vi } from "vitest";
import { sign, verify } from "../src/cookie";
import { createGate, type GateConfig, type GateProvider } from "../src/index";

const SECRET = "test-cookie-secret-0123456789abcdef";
const ORIGIN = "https://app.example";

type TeamData = { team: string };

function fakeProvider(overrides: Partial<GateProvider<TeamData>> = {}): GateProvider<TeamData> {
  return {
    authorizeUrl: ({ state, silent }) =>
      `https://idp.example/authorize?state=${state}${silent ? "&silent=1" : ""}`,
    identify: async ({ code }) => (code === "good" ? { team: "blue" } : null),
    ...overrides,
  };
}

function makeGate(overrides: Partial<GateConfig<TeamData>> = {}) {
  return createGate<TeamData>({
    cookieSecret: SECRET,
    provider: fakeProvider(),
    ...overrides,
  });
}

function docRequest(path: string, headers: Record<string, string> = {}) {
  return new Request(`https://app.example${path}`, {
    headers: { "Sec-Fetch-Dest": "document", ...headers },
  });
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function stateCookie(state = "st1", returnTo = "/secret") {
  const token = await sign({ state, returnTo, exp: nowSec() + 600 }, SECRET, ORIGIN);
  return `__Host-gate_state=${token}`;
}

describe("unauthorized access", () => {
  it("redirects document navigations to login with returnTo", async () => {
    const res = await makeGate()(docRequest("/secret/page?x=1"));
    expect(res).not.toBeNull();
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, "https://app.example");
    expect(location.pathname).toBe("/auth/login");
    expect(location.searchParams.get("returnTo")).toBe("/secret/page?x=1");
  });

  it("returns 401 for non-document requests such as fetch", async () => {
    const res = await makeGate()(new Request("https://app.example/api/data"));
    expect(res!.status).toBe(401);
  });
});

describe("login start", () => {
  it("redirects to the provider's authorize URL and sets a state cookie", async () => {
    const res = await makeGate()(docRequest("/auth/login?returnTo=%2Fsecret"));
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!);
    expect(location.origin).toBe("https://idp.example");
    expect(location.searchParams.get("state")).toBeTruthy();
    const setCookie = res!.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("__Host-gate_state=");
    expect(setCookie).toContain("HttpOnly");
  });

  it("passes redirectUri and the silent flag to the provider", async () => {
    const authorizeUrl = vi.fn(
      ({ state }: { state: string }) => `https://idp.example/a?state=${state}`,
    );
    await makeGate({ provider: fakeProvider({ authorizeUrl }) })(
      docRequest("/auth/login?silent=1"),
    );
    expect(authorizeUrl).toHaveBeenCalledWith({
      redirectUri: "https://app.example/auth/callback",
      state: expect.any(String),
      silent: true,
    });
  });

  it("ignores external returnTo URLs", async () => {
    const res = await makeGate()(docRequest("/auth/login?returnTo=https%3A%2F%2Fevil.example%2F"));
    expect(res!.status).toBe(302);
    expect(res!.headers.get("Set-Cookie") ?? "").not.toContain("evil.example");
  });
});

describe("callback", () => {
  it("issues a session cookie and redirects when identified and admitted", async () => {
    const res = await makeGate()(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(302);
    expect(res!.headers.get("Location")).toBe("/secret");
    const setCookie = res!.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("__Host-gate=");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Lax");
  });

  it("passes code and redirectUri to the provider", async () => {
    const identify = vi.fn(async () => ({ team: "blue" }));
    await makeGate({ provider: fakeProvider({ identify }) })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(identify).toHaveBeenCalledWith({
      code: "good",
      redirectUri: "https://app.example/auth/callback",
    });
  });

  it("fails closed when a sloppy provider resolves to undefined", async () => {
    const sloppyIdentify = (async () => {
      // a forgotten return statement must deny, never admit
    }) as unknown as GateProvider<TeamData>["identify"];
    const res = await makeGate({
      provider: fakeProvider({ identify: sloppyIdentify }),
    })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
  });

  it("returns 403 when the provider cannot identify the visitor", async () => {
    const res = await makeGate()(
      docRequest("/auth/callback?code=bad&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
  });

  it("returns 400 on state mismatch", async () => {
    const res = await makeGate()(
      docRequest("/auth/callback?code=good&state=WRONG", {
        Cookie: await stateCookie("st1"),
      }),
    );
    expect(res!.status).toBe(400);
  });

  it("returns 400 when the state cookie is missing", async () => {
    const res = await makeGate()(docRequest("/auth/callback?code=good&state=st1"));
    expect(res!.status).toBe(400);
  });

  it("falls back to interactive login on provider errors (e.g. failed silent auth)", async () => {
    const res = await makeGate()(
      docRequest("/auth/callback?error=access_denied", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, "https://app.example");
    expect(location.pathname).toBe("/auth/login");
  });
});

describe("filter", () => {
  it("passes the identified data and context to filter", async () => {
    const filter = vi.fn(() => true);
    const res = await makeGate({ filter })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(302);
    expect(filter).toHaveBeenCalledWith(
      { team: "blue" },
      expect.objectContaining({ request: expect.any(Request) }),
    );
  });

  it("returns 403 when filter rejects", async () => {
    const res = await makeGate({ filter: (data) => data.team === "red" })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
  });

  it("supports async filters", async () => {
    const res = await makeGate({
      filter: async (data) => data.team === "blue",
    })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(302);
  });
});

describe("session", () => {
  it("returns null for requests with a valid session cookie", async () => {
    const token = await sign({ exp: nowSec() + 3600 }, SECRET, ORIGIN);
    const res = await makeGate()(docRequest("/secret", { Cookie: `__Host-gate=${token}` }));
    expect(res).toBeNull();
  });

  it("sends expired sessions to silent re-authorization", async () => {
    const token = await sign({ exp: nowSec() - 10 }, SECRET, ORIGIN);
    const res = await makeGate()(docRequest("/secret", { Cookie: `__Host-gate=${token}` }));
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, "https://app.example");
    expect(location.pathname).toBe("/auth/login");
    expect(location.searchParams.get("silent")).toBe("1");
  });

  it("clears the cookie on logout", async () => {
    const res = await makeGate()(docRequest("/auth/logout"));
    expect(res!.status).toBe(302);
    const setCookie = res!.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("__Host-gate=;");
    expect(setCookie).toContain("Max-Age=0");
  });
});

describe("configuration", () => {
  it("throws immediately when cookieSecret is empty", () => {
    expect(() => makeGate({ cookieSecret: "" })).toThrow(/cookieSecret/);
  });

  it("throws on a cookieSecret shorter than 32 characters", () => {
    expect(() => makeGate({ cookieSecret: "short-secret" })).toThrow(/32 characters/);
  });
});

describe("session hardening", () => {
  it("rejects session cookies issued for a different origin", async () => {
    const token = await sign({ exp: nowSec() + 3600 }, SECRET, "https://other.example");
    const res = await makeGate()(docRequest("/secret", { Cookie: `__Host-gate=${token}` }));
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, ORIGIN);
    expect(location.pathname).toBe("/auth/login");
    // wrong audience is untrusted entirely — no silent re-auth shortcut
    expect(location.searchParams.get("silent")).toBeNull();
  });

  it("stamps the session with aud and sessionVersion on issue", async () => {
    const res = await makeGate({ sessionVersion: 3 })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    const token = (res!.headers.get("Set-Cookie") ?? "").match(/__Host-gate=([^;]+)/)![1]!;
    const verified = await verify(token, SECRET, ORIGIN);
    expect(verified).not.toBeNull();
    expect(verified!.payload).toMatchObject({ v: 3, aud: ORIGIN });
  });

  it("admits sessions carrying the current sessionVersion", async () => {
    const token = await sign({ exp: nowSec() + 3600, v: "2024-policy" }, SECRET, ORIGIN);
    const res = await makeGate({ sessionVersion: "2024-policy" })(
      docRequest("/secret", { Cookie: `__Host-gate=${token}` }),
    );
    expect(res).toBeNull();
  });

  it("sends stale-version sessions back through silent re-authorization", async () => {
    const token = await sign({ exp: nowSec() + 3600, v: 1 }, SECRET, ORIGIN);
    const res = await makeGate({ sessionVersion: 2 })(
      docRequest("/secret", { Cookie: `__Host-gate=${token}` }),
    );
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, ORIGIN);
    expect(location.searchParams.get("silent")).toBe("1");
  });
});

describe("fail-closed on exceptions", () => {
  it("denies with 403 when identify throws", async () => {
    const identify = vi.fn(async (): Promise<TeamData | null> => {
      throw new Error("IdP is down");
    });
    const res = await makeGate({ provider: fakeProvider({ identify }) })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
  });

  it("denies with 403 when filter throws", async () => {
    const res = await makeGate({
      filter: () => {
        throw new Error("policy bug");
      },
    })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
  });
});

describe("__Host- cookies", () => {
  it("defaults to __Host- names with Path=/ so the prefix rules hold", async () => {
    const res = await makeGate()(docRequest("/auth/login"));
    const setCookie = res!.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("__Host-gate_state=");
    expect(setCookie).toContain("Path=/;");
    expect(setCookie).not.toContain("Path=/auth/callback");
  });

  it("narrows the state cookie to the callback path for non-prefixed names", async () => {
    const res = await makeGate({ stateCookieName: "plain_state" })(docRequest("/auth/login"));
    const setCookie = res!.headers.get("Set-Cookie") ?? "";
    expect(setCookie).toContain("plain_state=");
    expect(setCookie).toContain("Path=/auth/callback");
  });
});

describe("custom responses", () => {
  it("uses the signin hook for unauthenticated document requests", async () => {
    const res = await makeGate({
      signin: ({ loginUrl }) =>
        new Response(`<a href="${loginUrl}">Continue with Discord</a>`, {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    })(docRequest("/secret/page?x=1"));
    expect(res!.status).toBe(401);
    const body = await res!.text();
    expect(body).toContain('href="/auth/login?returnTo=%2Fsecret%2Fpage%3Fx%3D1"');
  });

  it("bypasses the signin hook for silent re-authorization of expired sessions", async () => {
    const token = await sign({ exp: nowSec() - 10 }, SECRET, ORIGIN);
    const res = await makeGate({
      signin: () => new Response("should not appear", { status: 401 }),
    })(docRequest("/secret", { Cookie: `__Host-gate=${token}` }));
    expect(res!.status).toBe(302);
    const location = new URL(res!.headers.get("Location")!, "https://app.example");
    expect(location.searchParams.get("silent")).toBe("1");
  });

  it("uses the denied hook when the filter rejects", async () => {
    const res = await makeGate({
      filter: () => false,
      denied: ({ request }) =>
        new Response(`no entry: ${new URL(request.url).pathname}`, {
          status: 403,
        }),
    })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(res!.status).toBe(403);
    expect(await res!.text()).toBe("no entry: /auth/callback");
  });

  it("hands the denied hook a loginUrl that preserves returnTo", async () => {
    const res = await makeGate({
      filter: () => false,
      denied: ({ loginUrl }) => new Response(loginUrl, { status: 403 }),
    })(
      docRequest("/auth/callback?code=good&state=st1", {
        Cookie: await stateCookie("st1", "/secret"),
      }),
    );
    expect(await res!.text()).toBe("/auth/login?returnTo=%2Fsecret");
  });

  it("uses the denied hook when the provider cannot identify", async () => {
    const res = await makeGate({
      denied: () => new Response("who are you", { status: 403 }),
    })(
      docRequest("/auth/callback?code=bad&state=st1", {
        Cookie: await stateCookie(),
      }),
    );
    expect(await res!.text()).toBe("who are you");
  });

  it("uses the unauthorized hook for non-document requests", async () => {
    const res = await makeGate({
      unauthorized: ({ loginUrl }) =>
        Response.json({ error: "login required", loginUrl }, { status: 401 }),
    })(new Request("https://app.example/api/data?x=1"));
    expect(res!.status).toBe(401);
    expect(await res!.json()).toEqual({
      error: "login required",
      loginUrl: "/auth/login?returnTo=%2Fapi%2Fdata%3Fx%3D1",
    });
  });
});
