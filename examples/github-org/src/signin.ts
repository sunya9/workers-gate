// Custom sign-in screen: without `signin`, visitors are redirected
// straight to GitHub's consent page instead.
export function signin({ loginUrl }: { loginUrl: string }): Response {
  const html = `<!doctype html>
<html lang="en">
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Org members only</title>
<style>
  body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100dvh; margin: 0; background: #0d1117; color: #e6edf3; }
  main { text-align: center; padding: 2rem; }
  h1 { font-size: 1.4rem; }
  p { color: #8b949e; }
  a.button { display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; border-radius: 8px; background: #238636; color: #fff; text-decoration: none; font-weight: 600; }
  a.button:hover { background: #2ea043; }
</style>
<main>
  <h1>Org members only</h1>
  <p>This site is restricted to members of our GitHub organization.</p>
  <a class="button" href="${loginUrl}">Continue with GitHub</a>
</main>
</html>`;

  return new Response(html, {
    status: 401,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
