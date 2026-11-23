// POST /api/manage {token, action: list|add|remove|slack|invite|remove_member|leave_team|delete_account, slugs?, url?, email?}, or {action: "email_link", email}.
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
  if (!["list", "add", "remove", "slack", "invite", "remove_member", "leave_team", "delete_account"].includes(action)) throw new L.HttpError(400, "unknown action");
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
  // Team seats (owner side): invite by email, remove a member or a pending invite
  const teamOk = L.teamAllowed(user.plan) && !user.team_owner;
  if (action === "invite") {
    if (!teamOk) throw new L.HttpError(user.team_owner ? 400 : 402, user.team_owner ? "leave your current team before inviting people" : "team seats are part of the Team plan");
    const email = L.cleanEmail(body.email);
    if (email === user.email) throw new L.HttpError(400, "you are already on your team");
    const [{ n }] = await L.sql(`SELECT count(*) AS n FROM users WHERE (team_owner = $1 OR invited_by = $1) AND email <> $2`, [user.id, email]);
    if (Number(n) >= L.TEAM_SEATS()) throw new L.HttpError(400, `a team has up to ${L.TEAM_SEATS()} members besides you`);
    if (await L.limited("invite", user.id, 20)) throw new L.HttpError(429, "too many invitations, try again in an hour");
    const [m] = await L.sql(`INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id, team_owner`, [email]);
    if (String(m.team_owner || "") !== String(user.id) && !(await L.limited("mail", email, 3))) {
      const t = L.newToken(), unsub = await L.issueToken(m.id, "unsub");
      await L.sql(`UPDATE users SET invite_hash = $2, invite_expires = now() + interval '7 days', invited_by = $3 WHERE id = $1`, [m.id, L.hash(t), user.id]);
      await L.sendMail({ to: email, subject: "You are invited to an mcpwatch team",
        text: `${user.email} invited you to their mcpwatch team. Members get an alert when an MCP server on the team's watchlist changes.\n\n` +
          `Accept: ${L.SITE}/api/confirm?t=${t}\n\nThe link works once and expires in 7 days. If you do not want this, ignore this email.\n\n` +
          `Delete this address from mcpwatch now: ${L.unsubLink(unsub)}\n` });
    }
  }
  if (action === "remove_member") {
    const email = L.cleanEmail(body.email);
    await L.sql(`UPDATE users SET team_owner = CASE WHEN team_owner = $1 THEN NULL ELSE team_owner END,
      invited_by = CASE WHEN invited_by = $1 THEN NULL ELSE invited_by END,
      invite_hash = CASE WHEN invited_by = $1 THEN NULL ELSE invite_hash END WHERE email = $2`, [user.id, email]);
  }
  if (action === "leave_team") await L.sql(`UPDATE users SET team_owner = NULL WHERE id = $1`, [user.id]);
  const team = action === "leave_team" ? null : user.team_owner;
  const members = teamOk ? await L.sql(`SELECT email, team_owner IS NOT NULL AND team_owner = $1 AS joined FROM users
    WHERE team_owner = $1 OR invited_by = $1 ORDER BY email`, [user.id]) : [];
  const [owner] = team ? await L.sql(`SELECT email FROM users WHERE id = $1`, [team]) : [];
  const rows = await L.sql(`SELECT slug, added_at FROM watches WHERE user_id = $1 AND NOT pending ORDER BY slug`, [user.id]);
  L.send(res, 200, { ok: true, email: user.email, slugs: rows.map((r) => r.slug), since: Object.fromEntries(rows.map((r) => [r.slug, r.added_at])),
    max: limit, limit, plan: user.plan, billing_enabled: L.billingEnabled(), slack, slack_allowed: slackAllowed, team_allowed: L.teamAllowed(user.plan),
    seats: teamOk ? L.TEAM_SEATS() : 0, members: members.map((m) => ({ email: m.email, joined: m.joined === true || m.joined === "t" || m.joined === "true" })),
    team_of: owner ? owner.email : null });
});
