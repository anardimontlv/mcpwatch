// POST /api/report {key, repo, servers: [{slug|null, rules: ["MW004", ...]}]} from `mcpwatch report` (CLI / GitHub Action).
// Team org view: stores the repo's latest result and returns the team policy's violations (the caller fails CI on them).
// Only public server ids and rule codes arrive here: never config contents, server names, URLs or env.
const L = require("./_lib");

const REPO = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;
const RULE = /^MW\d{3}$/;
const MAX_REPOS = 500;

module.exports = L.handler(async (req, res) => {
  const body = await L.readJson(req);
  if (typeof body.key !== "string" || !L.TOKEN.test(body.key)) throw new L.HttpError(403, "invalid report key");
  if (typeof body.repo !== "string" || !REPO.test(body.repo) || body.repo.split("/").some((x) => /^\.+$/.test(x))) throw new L.HttpError(400, "repo must look like owner/name");
  if (!Array.isArray(body.servers) || body.servers.length > L.MAX_SLUGS) throw new L.HttpError(400, `servers must be a list of at most ${L.MAX_SLUGS}`);
  const servers = body.servers.map((s) => {
    const slug = s && s.slug == null ? null : s && s.slug;
    const rules = s && Array.isArray(s.rules) ? [...new Set(s.rules)] : null;
    if ((slug !== null && (typeof slug !== "string" || !/^[a-z0-9-]{10,100}$/.test(slug))) || !rules || rules.length > 20 || !rules.every((r) => typeof r === "string" && RULE.test(r))) {
      throw new L.HttpError(400, "each server needs a slug (or null) and a list of rule codes");
    }
    return { slug, rules: rules.sort() };
  });
  await L.ensureSchema();
  const user = await L.tokenUser("report", body.key);
  if (!user) throw new L.HttpError(403, "invalid report key");
  if (!L.teamAllowed(user.plan)) throw new L.HttpError(402, "the org view is part of the Team plan");
  if (await L.limited("report", user.id, 300)) throw new L.HttpError(429, "too many reports, try again in an hour");
  const slugs = [...new Set(servers.map((s) => s.slug).filter(Boolean))];
  const shards = {};
  try {
    await Promise.all([...new Set(slugs.map((s) => s.slice(-8, -6)))].map(async (sh) => { shards[sh] = await L.deps.fetchJSON(`${L.SITE}/d/${sh}.json`); }));
  } catch (_) {
    throw new L.HttpError(503, "could not reach the index, try again shortly"); // fail closed: the caller treats 5xx as a failed check
  }
  const policy = typeof user.policy === "string" ? JSON.parse(user.policy) : user.policy || {};
  let priv = 0;
  const rows = servers.map((s) => {
    const rec = s.slug ? (shards[s.slug.slice(-8, -6)] || {})[s.slug] : undefined;
    const label = rec ? s.slug : `private server ${++priv}`;
    return { server: label, slug: rec ? s.slug : null, grade: rec ? rec.g || null : null, auth: rec ? rec.a || null : null, rules: s.rules,
      violations: L.policyViolations(policy, label, s.rules, rec) };
  });
  const violations = rows.flatMap((r) => r.violations);
  const [{ n }] = await L.sql(`SELECT count(*) AS n FROM repo_reports WHERE user_id = $1 AND repo <> $2`, [user.id, body.repo]);
  if (Number(n) >= MAX_REPOS) throw new L.HttpError(400, `a team can report up to ${MAX_REPOS} repos`);
  await L.sql(`INSERT INTO repo_reports (user_id, repo, servers, violations) VALUES ($1, $2, $3::jsonb, $4::jsonb)
    ON CONFLICT (user_id, repo) DO UPDATE SET reported_at = now(), servers = EXCLUDED.servers, violations = EXCLUDED.violations`,
    [user.id, body.repo, rows.map(({ violations: _, ...r }) => r), violations]);
  L.send(res, 200, { ok: true, repo: body.repo, servers: rows.length, policy, violations, dashboard: `${L.SITE}/watch` });
});
