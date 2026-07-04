// Custom sign-in screen: without `signin`, visitors are redirected
// straight to Discord's consent page instead.
export function signin({ loginUrl }: { loginUrl: string }): Response {
  const html = `<!doctype html>
<html lang="en">
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Members only</title>
<style>
  body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100dvh; margin: 0; background: #313338; color: #dbdee1; }
  main { text-align: center; padding: 2rem; }
  h1 { font-size: 1.4rem; }
  p { color: #949ba4; }
  a.button { display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; border-radius: 8px; background: #5865f2; color: #fff; text-decoration: none; font-weight: 600; }
  a.button:hover { background: #4752c4; }
</style>
<main>
  <h1>Members only</h1>
  <p>This site is restricted to members of our Discord server.</p>
  <a class="button" href="${loginUrl}">Continue with Discord</a>
</main>
</html>`;

  return new Response(html, {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
