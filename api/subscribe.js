// POST /api/subscribe {email, slugs[]} -> emails a confirmation link. Same response whether or not the email is known.
const L = require("./_lib");

const OK = { ok: true, message: "Check your inbox: if the address is valid, a confirmation link is on its way (valid for 24 hours)." };

module.exports = L.handler(async (req, res) => {
  const body = await L.readJson(req);
  const email = L.cleanEmail(body.email);
  const slugs = await L.cleanSlugs(body.slugs);
  await L.ensureSchema();
  if (await L.limited("sub-ip", L.clientIp(req), 20)) throw new L.HttpError(429, "too many requests, try again in an hour");
  const [user] = await L.sql(
    `INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id`, [email]);
  await L.addWatches(user.id, slugs, true); // pending until the link is clicked: nobody can edit a list they can't read mail for
  if (await L.limited("mail", email, 3)) return L.send(res, 200, OK);
  const token = L.newToken();
  await L.sql(`UPDATE users SET confirm_hash = $2, confirm_expires = now() + interval '24 hours' WHERE id = $1`, [user.id, L.hash(token)]);
  const unsub = await L.issueToken(user.id, "unsub");
  await L.sendMail({
    to: email,
    subject: "Confirm your mcpwatch watchlist",
    text: `Confirm to start watching ${slugs.length ? slugs.length + " MCP server(s)" : "MCP servers"} with mcpwatch (free beta):\n\n` +
      `${L.SITE}/api/confirm?t=${token}\n\nThe link works once and expires in 24 hours. ` +
      `If you did not ask for this, ignore this email and nothing will be sent to you.\n\n` +
      `Delete this address from mcpwatch now: ${L.unsubLink(unsub)}\n`,
  });
  L.send(res, 200, OK);
});
