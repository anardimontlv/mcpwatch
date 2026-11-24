// GET /api/cron/scan (Vercel Cron, daily): backup trigger for the daily index workflow, because GitHub's own `schedule`
// never fired for this repo. Starts the workflow only if no run was created today (UTC), so it never doubles up with a
// GitHub-scheduled or manual run. Only Vercel Cron can call it: it sends `Authorization: Bearer $CRON_SECRET`.
// Needs GH_DISPATCH_TOKEN: a fine-grained token on anardimontlv/mcpwatch with Actions read & write, nothing else.
const crypto = require("crypto");
const L = require("../_lib");

const API = "https://api.github.com/repos/anardimontlv/mcpwatch/actions/workflows/index.yml";

const gh = (path, init = {}) => fetch(API + path, { ...init, redirect: "error", signal: AbortSignal.timeout(10000),
  headers: { Authorization: `Bearer ${process.env.GH_DISPATCH_TOKEN}`, Accept: "application/vnd.github+json", "User-Agent": "mcpwatch-cron",
    ...(init.body ? { "Content-Type": "application/json" } : {}) } });

function authorized(req) {
  const secret = process.env.CRON_SECRET, got = String(req.headers.authorization || "");
  if (!secret) return false;
  const a = Buffer.from(got), b = Buffer.from(`Bearer ${secret}`);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = L.handler(async (req, res) => {
  if (!authorized(req)) throw new L.HttpError(401, "unauthorized");
  if (!process.env.GH_DISPATCH_TOKEN) throw new L.HttpError(503, "GH_DISPATCH_TOKEN is not set");
  const today = new Date().toISOString().slice(0, 10);
  const runs = await L.deps.ghFetch(`/runs?created=>=${today}&per_page=5`);
  if (!runs.ok) throw new L.HttpError(502, `github: HTTP ${runs.status}`);
  const n = (await runs.json()).total_count || 0;
  if (n > 0) return L.send(res, 200, { ok: true, dispatched: false, reason: `${n} run(s) already today` });
  const d = await L.deps.ghFetch("/dispatches", { method: "POST", body: JSON.stringify({ ref: "main" }) });
  if (d.status !== 204) throw new L.HttpError(502, `github dispatch: HTTP ${d.status}`);
  L.send(res, 200, { ok: true, dispatched: true });
});
L.deps.ghFetch = L.deps.ghFetch || gh;
module.exports.authorized = authorized;
