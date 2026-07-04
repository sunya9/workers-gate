// GitHub-specific denial guidance. GitHub OAuth has no prompt/select_account
// support: an already-authorized app is re-approved instantly with the SAME
// account, so "just retry" loops forever for the wrong account. Tell the
// visitor how to actually recover instead.
export function denied({ loginUrl }: { loginUrl: string }): Response {
  const html = `<!doctype html>
<html lang="en">
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Not an org member</title>
<style>
  body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100dvh; margin: 0; background: #0d1117; color: #e6edf3; }
  main { max-width: 32rem; padding: 2rem; }
  h1 { font-size: 1.4rem; }
  p, li { color: #8b949e; }
  a { color: #58a6ff; }
  a.button { display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; border-radius: 8px; background: #238636; color: #fff; text-decoration: none; font-weight: 600; }
  a.button:hover { background: #2ea043; }
</style>
<main>
  <h1>Your GitHub account is not an active member of our organization</h1>
  <ul>
    <li>Just joined (or accepted the invitation)? Retry below.</li>
    <li>Wrong account? <a href="https://github.com/logout">Sign out of GitHub</a> first, then retry — GitHub re-uses the signed-in account without asking.</li>
    <li>Member but still denied? Your org may restrict OAuth app access; ask an owner to approve this app.</li>
  </ul>
  <a class="button" href="${loginUrl}">Retry</a>
</main>
</html>`;

  return new Response(html, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
