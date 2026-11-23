// Maintainer claim + responses, proven by a file in the server's own GitHub repo (the one the MCP registry lists).
//   GET  /api/claim?slug=<id>  -> {claimed, repo, verified_at, responses: {MW005: "intended", ...}}
//   POST /api/claim {slug}     -> re-reads https://raw.githubusercontent.com/<owner>/<repo>/HEAD/.mcpwatch
// The file is the only source of truth: whoever triggers a re-read can't add anything, so no accounts or emails.
//   claim: <server id>                 (one line per server this repo maintains)
//   MW005: intended                    (optional: one of intended | fixing | false-positive, for a current finding)
// Only fixed labels are ever shown on the site: never free text from the file.
const L = require("./_lib");

const STATUSES = new Set(["intended", "fixing", "false-positive"]);
const ID = /^[a-z0-9-]{10,100}$/;
const MAX_FILE = 16 * 1024;

function githubRepo(url) {
  const m = /^https:\/\/github\.com\/([A-Za-z0-9-]{1,39})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?(?:[/?#].*)?$/.exec(String(url || ""));
  return m && !/^\.+$/.test(m[2]) ? `${m[1]}/${m[2]}` : null;
}

function parseClaimFile(text, slug, ruleSet) {
  const claims = new Set(), responses = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    let m;
    if ((m = /^claim:\s*([a-z0-9-]{10,100})$/.exec(line))) claims.add(m[1]);
    else if ((m = /^(MW\d{3}):\s*([a-z-]+)$/.exec(line)) && STATUSES.has(m[2]) && ruleSet.has(m[1])) responses[m[1]] = m[2];
  }
  return claims.has(slug) ? responses : null;
}

function sendCached(res, status, obj) { // public data: let the CDN absorb page views
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=60, s-maxage=300");
  res.end(JSON.stringify(obj));
}

module.exports = L.handler(async (req, res) => {
  if (req.method === "GET") {
    const slug = new URL(req.url, "http://x").searchParams.get("slug") || "";
    if (!ID.test(slug)) throw new L.HttpError(400, "invalid server id");
    await L.ensureSchema();
    const [c] = await L.sql(`SELECT repo, responses, verified_at FROM maintainer_claims WHERE slug = $1`, [slug]);
    if (!c) return sendCached(res, 200, { claimed: false });
    return sendCached(res, 200, { claimed: true, repo: c.repo, verified_at: c.verified_at,
      responses: typeof c.responses === "string" ? JSON.parse(c.responses) : c.responses || {} });
  }
  const body = await L.readJson(req);
  const slug = typeof body.slug === "string" ? body.slug : "";
  if (!ID.test(slug)) throw new L.HttpError(400, "invalid server id");
  await L.ensureSchema();
  // per IP, and per (server, IP): nobody can use up a maintainer's budget for their own server
  if (await L.limited("claim-ip", L.clientIp(req), 30) || await L.limited("claim", slug + "|" + L.clientIp(req), 10)) {
    throw new L.HttpError(429, "too many checks, try again in an hour");
  }
  let rec;
  try {
    rec = (await L.deps.fetchJSON(`${L.SITE}/d/${slug.slice(-8, -6)}.json`))[slug];
  } catch (_) {
    throw new L.HttpError(503, "could not reach the index, try again shortly");
  }
  if (!rec) throw new L.HttpError(404, "unknown server id");
  const repo = githubRepo(rec.r);
  if (!repo) throw new L.HttpError(400, "the registry lists no GitHub repository for this server, so it can't be claimed this way: open an issue instead");
  // io.github.<owner>/... names were verified against that GitHub owner by the registry: the repo must belong to them
  const ns = /^io\.github\.([^/]+)\//i.exec(String(rec.n || ""));
  if (ns && ns[1].toLowerCase() !== repo.split("/")[0].toLowerCase()) {
    throw new L.HttpError(400, "the listed repository is not owned by the GitHub account in this server's registry name: open an issue instead");
  }
  let text;
  try {
    text = await L.deps.fetchText(`https://raw.githubusercontent.com/${repo}/HEAD/.mcpwatch`, MAX_FILE);
  } catch (_) {
    throw new L.HttpError(503, "could not reach GitHub, try again shortly");
  }
  const responses = text == null ? null : parseClaimFile(text, slug, new Set((rec.f || []).map((f) => f[1])));
  if (!responses) {
    await L.sql(`DELETE FROM maintainer_claims WHERE slug = $1`, [slug]); // claim file gone or no longer lists this server
    throw new L.HttpError(404, `no .mcpwatch file in ${repo} (default branch) with the line "claim: ${slug}". GitHub can take ~5 minutes to serve a new file`);
  }
  // unchanged since a verification in the last 24 hours: nothing the page shows can change, so no GitHub call or budget
  // (any edit to the file goes through the full identity check below)
  // identity is still re-checked at least daily, so a hijacked repo serving a copied file can't hold a claim forever
  const [cur] = await L.sql(`SELECT repo, responses, verified_at > now() - interval '24 hours' AS fresh FROM maintainer_claims WHERE slug = $1`, [slug]);
  const stable = (o) => JSON.stringify(Object.keys(o || {}).sort().map((k) => [k, o[k]]));
  if (cur && [true, "t", "true"].includes(cur.fresh) && cur.repo === repo && stable(typeof cur.responses === "string" ? JSON.parse(cur.responses) : cur.responses) === stable(responses)) {
    return L.send(res, 200, { ok: true, claimed: true, repo, responses, unchanged: true });
  }
  // only a real claim file reaches the GitHub API; each server gets its own small budget, and a global cap keeps us
  // under GitHub's quota (60/hour unauthenticated, 5,000 with GITHUB_TOKEN)
  if (await L.limited("claim-gh-slug", slug, 3)) throw new L.HttpError(429, "this server was checked recently, try again in an hour");
  if (await L.limited("claim-gh", "global", process.env.GITHUB_TOKEN ? 4000 : 50)) throw new L.HttpError(429, "too many claim checks right now, try again in an hour");
  let info;
  try {
    info = await L.deps.githubRepoInfo(repo);
  } catch (_) {
    throw new L.HttpError(503, "could not reach GitHub, try again shortly");
  }
  if (!info) throw new L.HttpError(404, "the listed repository does not exist on GitHub");
  // pins outlive claims (revoking never deletes them): a re-registered name has new numeric ids and stays refused
  await L.sql(`INSERT INTO claim_pins (slug, repo_id, owner_id) VALUES ($1, $2, $3) ON CONFLICT (slug) DO NOTHING`, [slug, info.id, info.owner_id]);
  const [pin] = await L.sql(`SELECT repo_id, owner_id FROM claim_pins WHERE slug = $1`, [slug]);
  if (pin.repo_id !== info.id || pin.owner_id !== info.owner_id) {
    await L.sql(`DELETE FROM maintainer_claims WHERE slug = $1`, [slug]);
    throw new L.HttpError(409, "this repository is not the one that first claimed this server: open an issue if you are the maintainer");
  }
  await L.sql(`INSERT INTO maintainer_claims (slug, repo, responses, verified_at) VALUES ($1, $2, $3::jsonb, now())
    ON CONFLICT (slug) DO UPDATE SET repo = EXCLUDED.repo, responses = EXCLUDED.responses, verified_at = now()`, [slug, repo, responses]);
  L.send(res, 200, { ok: true, claimed: true, repo, responses });
});
module.exports.parseClaimFile = parseClaimFile;
module.exports.githubRepo = githubRepo;
