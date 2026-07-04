import { env } from "cloudflare:workers";
import { createGate, oauthProvider } from "workers-gate";
import { denied } from "./denied";
import { signin } from "./signin";

const gate = createGate({
  cookieSecret: env.COOKIE_SECRET,
  provider: oauthProvider({
    authorizeEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    clientId: env.GITHUB_CLIENT_ID,
    clientSecret: env.GITHUB_CLIENT_SECRET,
    scope: "read:org", // exactly what identify() needs — nothing more
    // GitHub has no prompt=none; previously-authorized apps redirect straight
    // back anyway, so silent re-authorization needs no extra params.
    async identify({ accessToken }) {
      // 404 = not a member (or membership hidden from this token)
      const res = await fetch(
        `https://api.github.com/user/memberships/orgs/${env.GITHUB_ORG}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "workers-gate-example", // GitHub API rejects UA-less requests
          },
        },
      );
      if (!res.ok) return null;
      const membership: { state: string; role: string } = await res.json();
      return membership;
    },
  }),
  // the filter style, for contrast with the Discord example:
  // identified (member record exists) still isn't admitted unless active
  filter: (membership) => membership.state === "active",
  signin,
  denied,
});

export default {
  async fetch(request: Request): Promise<Response> {
    return (await gate(request)) ?? env.ASSETS.fetch(request);
  },
};
