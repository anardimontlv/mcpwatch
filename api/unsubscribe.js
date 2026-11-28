// GET /api/unsubscribe?t=<unsubscribe token> only renders a button (mail scanners prefetch GET links).
// The button (/watch.js) POSTs {t}: that deletes the user and, through ON DELETE CASCADE, every watch row.
// Accepts only unexpired tokens of kind 'unsub' (90 days): a manage token is never accepted here.
const L = require("./_lib");

module.exports = L.handler(async (req, res) => {
  if (req.method === "GET" || req.method === "HEAD") {
    return L.htmlPage(res, 200, "Unsubscribe", "This deletes your email address and watchlist from mcpwatch right away.", "Unsubscribe and delete my data");
  }
  const { t } = await L.readJson(req);
  if (typeof t !== "string" || !L.TOKEN.test(t)) throw new L.HttpError(400, "this unsubscribe link is malformed");
  await L.ensureSchema();
  if (!(await L.deleteByToken("unsub", t))) throw new L.HttpError(410, "this link has expired or the account is already deleted");
  L.send(res, 200, { ok: true, message: "Unsubscribed. Your email address and watchlist were deleted." });
});
