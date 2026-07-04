import { env } from "cloudflare:workers";
import { createGate, oauthProvider } from "workers-gate";
import { signin } from "./signin";

const gate = createGate({
  cookieSecret: env.COOKIE_SECRET,
  provider: oauthProvider({
    authorizeEndpoint: "https://discord.com/oauth2/authorize",
    tokenEndpoint: "https://discord.com/api/v10/oauth2/token",
    clientId: env.DISCORD_CLIENT_ID,
    clientSecret: env.DISCORD_CLIENT_SECRET,
    scope: "guilds.members.read", // exactly what identify() needs — never asks who the user is
    silentParams: { prompt: "none" },
    async identify({ accessToken }) {
      // asks Discord for our membership in this one guild;
      // 404 = not a member, so the judgment is folded into identify
      const res = await fetch(
        `https://discord.com/api/v10/users/@me/guilds/${env.GUILD_ID}/member`,
        { headers: { Authorization: `Bearer ${accessToken}` } },
      );
      if (!res.ok) return null;
      const member: { roles: string[] } = await res.json();
      return member;
    },
  }),
  // membership itself is the policy here; add a role check if you need one:
  // filter: (member) => member.roles.includes("your-role-id"),
  signin,
});

export default {
  async fetch(request: Request): Promise<Response> {
    return (await gate(request)) ?? env.ASSETS.fetch(request);
  },
};
