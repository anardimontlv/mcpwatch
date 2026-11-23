// GET /api/confirm?t=... only renders a button (mail scanners prefetch GET links and must not consume the token).
// The button (/watch.js) POSTs {t}; that confirms, activates pending watches and returns a fresh manage token,
// which the page puts in the /watch URL fragment (never sent to a server, never in logs).
const L = require("./_lib");

module.exports = L.handler(async (req, res) => {
  if (req.method === "GET" || req.method === "HEAD") {
    return L.htmlPage(res, 200, "Confirm your email", "One click to start watching your MCP servers.", "Confirm and open my watchlist");
  }
  const { t } = await L.readJson(req);
  if (typeof t !== "string" || !L.TOKEN.test(t)) throw new L.HttpError(400, "this link is malformed: start again from the watch page");
  await L.ensureSchema();
  const [user] = await L.sql(
    `UPDATE users SET confirmed = true, confirm_hash = NULL, confirm_expires = NULL
     WHERE confirm_hash = $1 AND confirm_expires > now() RETURNING id`, [L.hash(t)]);
  if (!user) throw new L.HttpError(410, "this link was already used or has expired (links last 24 hours): start again from the watch page");
  await L.sql(`UPDATE watches SET pending = false WHERE user_id = $1`, [user.id]);
  await L.sql(`UPDATE users SET team_owner = invited_by, invited_by = NULL WHERE id = $1 AND invited_by IS NOT NULL`, [user.id]); // accepted a team invite
  const manage = await L.issueToken(user.id, "manage");
  L.send(res, 200, { ok: true, manage });
});
