// POST /api/manage {token, action: list|add|remove|slack|delete_account, slugs?, url?}, or {action: "email_link", email}.
const L = require("./_lib");

const LINK_SENT = { ok: true, message: "If that address has a confirmed watchlist, a new manage link is on its way." };

module.exports = L.handler(async (req, res) => {
  const body = await L.readJson(req);
  const action = body.action;
  if (action === "email_link") {
    const email = L.cleanEmail(body.email);
    await L.ensureSchema();
    if (await L.limited("sub-ip", L.clientIp(req), 20)) throw new L.HttpError(429, "too many requests, try again in an hour");
    if (await L.limited("mail", email, 3)) return L.send(res, 200, LINK_SENT);
    const [user] = await L.sql(`SELECT id FROM users WHERE email = $1 AND confirmed`, [email]);
    if (user) {
      const token = await L.issueToken(user.id, "manage"), unsub = await L.issueToken(user.id, "unsub");
      await L.sendMail({
        to: email,
        subject: "Your mcpwatch manage link",
        text: `Manage your mcpwatch watchlist:\n${L.SITE}/watch#m=${token}\n\nUnsubscribe and delete your data:\n${L.unsubLink(unsub)}\n\n` +
          "Earlier links keep working until they expire (30 days). If you did not ask for it, you can ignore this email.\n",
      });
    }
    return L.send(res, 200, LINK_SENT);
  }
  if (!["list", "add", "remove", "slack", "delete_account"].includes(action)) throw new L.HttpError(400, "unknown action");
  if (typeof body.token !== "string" || !L.TOKEN.test(body.token)) throw new L.HttpError(403, "invalid or expired manage link");
  await L.ensureSchema();
  if (action === "delete_account") {
    if (!(await L.deleteByToken("manage", body.token))) throw new L.HttpError(403, "invalid or expired manage link");
    return L.send(res, 200, { ok: true, deleted: true });
  }
  const user = await L.tokenUser("manage", body.token);
  if (!user) throw new L.HttpError(403, "invalid or expired manage link");
  const limit = L.planLimit(user.plan);
  if (action === "add") {
    const slugs = await L.cleanSlugs(body.slugs);
    const have = new Set((await L.sql(`SELECT slug FROM watches WHERE user_id = $1`, [user.id])).map((r) => r.slug));
    if (have.size + slugs.filter((s) => !have.has(s)).length > limit) throw L.limitError(user.plan, limit);
    await L.addWatches(user.id, slugs, false, limit);
  }
  if (action === "remove") {
    const slugs = await L.cleanSlugs(body.slugs, { checkExists: false });
    if (slugs.length) await L.sql(`DELETE FROM watches WHERE user_id = $1 AND slug IN (SELECT jsonb_array_elements_text($2::jsonb))`, [user.id, slugs]);
  }
  // Slack alerts: free for everyone during the beta, Pro and Team once billing is on. The URL is never sent back.
  const slackAllowed = !L.billingEnabled() || user.plan !== "free";
  let slack = Boolean(user.slack_webhook);
  if (action === "slack") {
    const url = typeof body.url === "string" ? body.url.trim() : "";
    if (url) {
      if (!L.SLACK_HOOK.test(url)) throw new L.HttpError(400, "paste a Slack incoming webhook URL (https://hooks.slack.com/services/...)");
      if (!slackAllowed) throw new L.HttpError(402, "Slack alerts are part of Pro");
      if (await L.limited("slack", user.id, 10)) throw new L.HttpError(429, "too many requests, try again in an hour");
      if (!(await L.slackPost(url, "mcpwatch is connected. You will get a message here when a server you watch changes.")))
        throw new L.HttpError(400, "Slack did not accept a test message: check the webhook URL");
    }
    await L.sql(`UPDATE users SET slack_webhook = $2 WHERE id = $1`, [user.id, url || null]);
    slack = Boolean(url);
  }
  const rows = await L.sql(`SELECT slug FROM watches WHERE user_id = $1 AND NOT pending ORDER BY slug`, [user.id]);
  L.send(res, 200, { ok: true, email: user.email, slugs: rows.map((r) => r.slug), max: limit, limit,
    plan: user.plan, billing_enabled: L.billingEnabled(), slack, slack_allowed: slackAllowed });
});
