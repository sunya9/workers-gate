# workers-gate

[![npm](https://img.shields.io/npm/v/workers-gate)](https://www.npmjs.com/package/workers-gate)
[![CI](https://github.com/sunya9/workers-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/sunya9/workers-gate/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/workers-gate)](./LICENSE)

A stateless authorization gate for apps on Cloudflare Workers. Bring your own provider; call the gate where you want it.

Authorization, not authentication: it never asks or stores who the user is. No database, no KV, and a single dependency — cookie signing and verification are delegated to [jose](https://github.com/panva/jose). All that travels is a signed, expiring JWT cookie. Your filter says yes? You're in. Otherwise 403.

## How it works

`createGate(config)` gives you a plain function: `(request) => Promise<Response | null>`.

```
gate(request):
  /auth/login    → Response: redirect to provider.authorizeUrl(...)
  /auth/callback → provider.identify(...) fetches data → your filter(data) decides
                   ├─ true  → Response: signed session cookie + redirect back
                   └─ false → Response: 403
  anything else  → valid session cookie? (signature + expiry, no I/O)
                   ├─ yes → null   ← the request is yours
                   └─ no  → Response: redirect to login (or 401 for non-document requests)
```

You call it inside your own `fetch` and return early when it hands you a Response — the standard middleware contract. No wrapping, no hidden routing, no implicit env reads: every value the gate uses is one you passed it.

## Usage

```ts
// src/worker.ts
import { env } from "cloudflare:workers";
import { createGate, oauthProvider } from "workers-gate";

const gate = createGate({
  cookieSecret: env.COOKIE_SECRET,
  provider: oauthProvider({
    // endpoints, client credentials, scope, identify() —
    // see Providers below; complete configs live in Recipes
  }),
  filter: (data) => data.team === "blue", // your policy, typed by the provider
});

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return (await gate(request)) ?? env.ASSETS.fetch(request);
  },
};
```

- Build the gate once at module scope via the [`cloudflare:workers`](https://developers.cloudflare.com/workers/runtime-apis/bindings/#importing-env-as-a-module) env import (compatibility date 2025-03-10+), or per request inside `fetch` from the handler's `env` — either works the same.
- `filter` receives whatever data `identify` returned — fully typed, re-evaluated on every (re-)login. Omit it to admit anyone the provider can identify.
- The layering encodes ownership: `identify` lives in the provider (shareable, policy-free procurement), `filter` lives in your config (your deployment's policy). Folding the judgment into `identify` (return `null` for "no") is equally valid.
- Public routes are your if-statement: `if (url.pathname === "/healthz") return ok()` before calling `gate(request)`.
- Works with wrangler-generated `Env` types as-is — the gate never touches `env`; you hand it values.

Route every request through the worker so static assets are gated too:

```jsonc
// wrangler.jsonc
{
  "main": "src/worker.ts",
  "assets": {
    "directory": "./dist",
    "binding": "ASSETS",
    "not_found_handling": "single-page-application", // for SPAs
    "run_worker_first": true, // or ["/*", "!/assets/*"] to skip hashed assets
  },
}
```

The gate itself needs one binding: `COOKIE_SECRET` (`openssl rand -hex 32`, via `wrangler secret put`). Everything else belongs to your provider and filter.

Set secrets before the first deploy: `createGate` fails fast on an empty `cookieSecret`, so a worker deployed without its secrets won't pass deploy validation. `wrangler secret put` offers to create a draft Worker when none exists — put the secrets first, then deploy. To keep deployment-specific values out of tracked files, `wrangler deploy --var KEY:value` overrides config vars at deploy time.

## Providers

A provider procures data about the visitor; it makes no decisions. For any vanilla OAuth2 authorization-code IdP, `oauthProvider()` covers the protocol plumbing — you supply two endpoints, client credentials, and an `identify()` that fetches the data your filter judges (see the Discord recipe below for a complete one).

For IdPs with heavier dialects (PKCE-required, custom token-endpoint auth), implement `GateProvider` directly — two functions — on top of whatever client you like ([openid-client](https://github.com/panva/openid-client) for OIDC, [Arctic](https://arcticjs.dev) for 60+ providers; both run on Workers):

```ts
import { type GateProvider } from "workers-gate";

const myProvider: GateProvider<MyData> = {
  // Where visitors go to prove themselves.
  authorizeUrl({ redirectUri, state, silent }) {
    return "https://idp.example/authorize?...";
  },
  // Procure the data about the visitor. null = could not identify.
  async identify({ code, redirectUri }) {
    return {
      /* whatever your filter needs */
    };
  },
};
```

The contract: `authorizeUrl` must request whatever scope/claims `identify` needs to gather its data — the two are a pair. Keep the scope minimal.

`silent` is `true` when a returning visitor's session just expired; OAuth-style providers can translate it to `prompt=none`. If the IdP answers the callback with an `error` param, the gate automatically retries an interactive login. `oauthProvider`'s `identify` also receives the full `tokenResponse` for extras like `id_token`.

## Recipes

The library ships no IdP presets — endpoints, scope, and policy are yours. Both example projects are deployable as-is (wrangler config, `.dev.vars` template, generated types).

### Discord: guild members only — [`examples/discord-guild/`](./examples/discord-guild/)

```ts
provider: oauthProvider({
  authorizeEndpoint: "https://discord.com/oauth2/authorize",
  tokenEndpoint: "https://discord.com/api/v10/oauth2/token",
  clientId: env.DISCORD_CLIENT_ID,
  clientSecret: env.DISCORD_CLIENT_SECRET,
  scope: "guilds.members.read",
  silentParams: { prompt: "none" },
  async identify({ accessToken }) {
    // membership in this one guild, straight from Discord; 404 = not a member
    const res = await fetch(
      `https://discord.com/api/v10/users/@me/guilds/${env.GUILD_ID}/member`,
      { headers: { Authorization: `Bearer ${accessToken}` } },
    );
    if (!res.ok) return null;
    const member: { roles: string[] } = await res.json();
    return member;
  },
}),
// membership itself is the policy; add a filter for finer rules, e.g. roles
```

Prefer the broader `guilds` scope + `GET /users/@me/guilds` if you'd rather not let the app read your nickname/roles in that guild.

### GitHub: org members only — [`examples/github-org/`](./examples/github-org/)

Scope `read:org`, `identify` fetches `GET /user/memberships/orgs/{org}`, and the filter admits only `state === "active"`. The example also ships a denial page with GitHub-specific recovery guidance (GitHub has no `prompt` support, so switching accounts requires signing out of github.com first). An org-owned private GitHub App is the cleanest registration: installing it on the org doubles as the access approval that OAuth Apps need separately.

### Google Workspace: domain members only

OIDC — implement `GateProvider` with openid-client, return the ID-token claims from `identify`, and `filter: (claims) => claims.hd === "example.com"`.

## GateConfig

| Field                                       | Default                                       | Description                                                                      |
| ------------------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------- |
| `cookieSecret`                              | required                                      | HMAC key for session/state cookies, 32+ characters                               |
| `provider`                                  | required                                      | Data procurement: `authorizeUrl` + `identify`                                    |
| `filter`                                    | admit all identified                          | The authorization decision                                                       |
| `signin`                                    | redirect straight to the IdP                  | Custom sign-in screen for unauthenticated document requests; receives `loginUrl` |
| `denied`                                    | built-in minimal 403 page                     | Custom Response for rejected/unidentified visitors; receives `loginUrl`          |
| `unauthorized`                              | plain-text 401                                | Custom Response for sessionless fetch/XHR; receives `loginUrl`                   |
| `sessionTtlSeconds`                         | `86400`                                       | Session cookie lifetime                                                          |
| `loginPath` / `callbackPath` / `logoutPath` | `/auth/login` `/auth/callback` `/auth/logout` | Routes the gate claims                                                           |
| `cookieName` / `stateCookieName`            | `__gate` `__gate_state`                       | Cookie names                                                                     |
| `sessionVersion`                            | unset                                         | Bump to send every outstanding session back through re-authorization             |

## Security notes

- Sessions are bound to the request origin via the JWT `aud` claim: a cookie minted on one hostname does not pass on another, and reusing a `cookieSecret` across apps no longer lets their sessions cross.
- `createGate` rejects a `cookieSecret` shorter than 32 characters.
- `sessionVersion` is the stateless revocation lever: bumping it invalidates every session at once, and holders are silently re-authorized — which re-runs `identify` and your `filter`.
- Exceptions from `identify`/`filter` and malformed token-endpoint responses fail closed to the denied response; the cause is logged via `console.error` (visible in `wrangler tail`).
- For cookie-tossing resistance, set `cookieName: "__Host-gate"` and `stateCookieName: "__Host-gate_state"` — the attributes already qualify, and the state cookie path widens to `/` automatically. Heads-up: some browsers drop `__Host-` cookies on plain-HTTP localhost during `wrangler dev`.

## Screens are yours

The gate ships no UI beyond a fallback 403/401. Every visible surface is replaceable:

- Sign-in screen (`signin`): rendered in place of the default straight-to-IdP redirect for unauthenticated page visits — the URL stays put, your screen shows, its button points at `loginUrl` (which already carries the `returnTo`). Both examples render one. Silent re-authorization of expired sessions bypasses the screen and stays seamless.
- Denied page (`denied`): `denied: ({ loginUrl }) => new Response(myBrandedHtml, { status: 403, headers: { "Content-Type": "text/html" } })`
- API 401 shape (`unauthorized`): `unauthorized: ({ loginUrl }) => Response.json({ error: "login required", loginUrl }, { status: 401 })`

By default there is no login screen at all: unauthenticated visitors are redirected straight to the IdP's own consent page.

## Notes for SPAs

- `not_found_handling: "single-page-application"` keeps client-side routing working: unknown paths serve the (gated) `index.html`.
- Using `@cloudflare/vite-plugin`? Same worker entry, same wrangler config — `vite dev` runs the gate locally. Put the bindings in `.dev.vars` and register the localhost callback URL with your IdP.
- When the session expires mid-visit, background `fetch` calls get `401` instead of a redirect (shape the body with the `unauthorized` hook). The simple recovery is `location.reload()` — the reload goes through silent re-authorization and comes back to the same URL.
- To renew without losing app state, use a popup: top-level navigation carries the `SameSite=Lax` cookies, which hidden iframes and background fetches do not. Serve a self-closing page behind the gate and point the popup's `returnTo` at it:

```ts
// worker: after the gate has passed
if (url.pathname === "/auth/done") {
  return new Response("<script>window.close()</script>", {
    headers: { "Content-Type": "text/html" },
  });
}
```

```ts
// SPA: on 401 — tie this to a click so popup blockers stay calm
const popup = window.open(
  "/auth/login?returnTo=%2Fauth%2Fdone&silent=1",
  "_blank",
  "width=520,height=640",
);
await new Promise<void>((resolve) => {
  const timer = setInterval(() => {
    if (popup?.closed) {
      clearInterval(timer);
      resolve();
    }
  }, 300);
});
// retry the failed request — app state untouched
```

If the silent pass fails (signed out of the IdP), the gate falls back to an interactive login inside the popup; the app keeps running either way.

## Limitations

- Stateless means no per-visitor revocation: someone who no longer satisfies your policy keeps access until their cookie expires (default 24h). Shorten `sessionTtlSeconds`, or bump `sessionVersion` to cut off everyone at once.
- Scope is redirect-and-callback flows (OAuth/OIDC-style). Basic auth or IP allowlists are a different animal.
- A `POST` issued with an expired session is redirected and loses its body — the follow-up navigation re-authorizes.
