// Shared helpers for the watchlist beta. Files starting with "_" are not deployed as functions by Vercel.
// No dependencies: Neon's SQL-over-HTTP endpoint and Resend's REST API are called with global fetch.
// Tests swap the I/O through `deps` (sql, sendMail, fetchJSON).
const crypto = require("crypto");

const SITE = "https://www.mcpwatch.io"; // fixed production host: never derived from the request
const SLUG = /^[a-z0-9-]{10,100}$/;
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const MAX_SLUGS = 200;
const MAX_BODY = 16 * 1024;

// Neon serverless driver protocol (src/shims/net fetchEndpoint + src/http/index.ts): POST https://api.<host minus first label>/sql
async function neonSql(query, params) {
  const conn = process.env.DATABASE_URL;
  if (!conn) throw new Error("DATABASE_URL not set");
  const host = new URL(conn).hostname.replace(/^[^.]+\./, "api.");
  const r = await fetch(`https://${host}/sql`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Neon-Connection-String": conn, "Neon-Raw-Text-Output": "true", "Neon-Array-Mode": "true" },
    body: JSON.stringify({ query, params }),
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok) throw new Error(`db error (HTTP ${r.status})`); // body may echo the query: never log it
  const j = await r.json();
  const names = j.fields.map((f) => f.name);
  return j.rows.map((row) => Object.fromEntries(row.map((v, i) => [names[i], v]))); // values are text (or null)
}

async function resendSend({ to, subject, text, html }) {
  if (!process.env.RESEND_API_KEY) return false;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: process.env.MAIL_FROM || "mcpwatch <alerts@mcpwatch.io>", to: [to], subject, text, ...(html ? { html } : {}) }),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) console.error(`mail send failed: HTTP ${r.status}`);
    return r.ok;
  } catch (e) {
    console.error("mail send failed: network");
    return false;
  }
}

async function fetchJSON(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
  if (r.status === 404) return {};
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ---- Paddle Billing REST (no SDK, no Paddle.js). Shapes checked against developer.paddle.com and the official
// node SDK source (github.com/PaddleHQ/paddle-node-sdk: src/internal/api/constants.ts for base URLs, client.ts for auth).
const PADDLE_BASE = { production: "https://api.paddle.com", sandbox: "https://sandbox-api.paddle.com" };
async function paddleFetch(method, path, body) {
  const base = PADDLE_BASE[process.env.PADDLE_ENV === "production" ? "production" : "sandbox"];
  const r = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${process.env.PADDLE_API_KEY}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000),
  });
  if (!r.ok) { // never log bodies: they carry customer data
    console.error(`paddle ${method} ${path.split("?")[0].replace(/\/(ctm|sub|txn)_[a-z0-9]+/g, "/$1_…")}: HTTP ${r.status}`);
    throw new HttpError(502, "the billing provider is unavailable, try again shortly");
  }
  return r.json();
}

// Slack incoming webhooks only: the host is fixed by SLACK_HOOK, so a user-supplied URL can't point us anywhere else.
const SLACK_HOOK = /^https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]{4,40}\/[A-Za-z0-9_-]{4,40}\/[A-Za-z0-9_-]{8,80}$/;
async function slackPost(url, text) {
  if (!SLACK_HOOK.test(url)) return false;
  try {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }),
      redirect: "error", signal: AbortSignal.timeout(8000) });
    return r.ok;
  } catch (_) { return false; } // never log the URL: it is the credential
}

const deps = { sql: neonSql, sendMail: resendSend, fetchJSON, paddle: paddleFetch, slackPost };
const sql = (query, params = []) =>
  deps.sql(query, params.map((p) => (p == null ? null : typeof p === "object" ? JSON.stringify(p) : String(p))));
const sendMail = (m) => deps.sendMail(m);

let schema = null; // once per warm instance
function ensureSchema() {
  schema = schema || (async () => {
    for (const q of [
      `CREATE TABLE IF NOT EXISTS users (id bigserial PRIMARY KEY, email text UNIQUE NOT NULL, confirmed boolean NOT NULL DEFAULT false,
        created_at timestamptz NOT NULL DEFAULT now(), confirm_hash text, confirm_expires timestamptz)`,
      // pending: added by an unauthenticated subscribe, active only after the emailed link is confirmed
      `CREATE TABLE IF NOT EXISTS watches (user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE, slug text NOT NULL,
        added_at timestamptz NOT NULL DEFAULT now(), pending boolean NOT NULL DEFAULT false, PRIMARY KEY (user_id, slug))`,
      // many live tokens per user and kind: issuing a new link never breaks an older one (unsub >= 30 days, CAN-SPAM).
      // Kinds are separate: a manage token (URL fragments only) can't unsubscribe, an unsubscribe token can't manage.
      `CREATE TABLE IF NOT EXISTS tokens (user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('manage', 'unsub')), hash text PRIMARY KEY,
        created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL)`,
      `CREATE INDEX IF NOT EXISTS tokens_user_kind ON tokens (user_id, kind, created_at)`,
      `ALTER TABLE users DROP COLUMN IF EXISTS manage_hash, DROP COLUMN IF EXISTS unsub_hash`, // superseded by tokens
      `DELETE FROM tokens WHERE expires_at < now()`, // opportunistic prune (also done by each digest run)
      // never-confirmed sign-ups are deleted after 7 days: we keep no email we were not asked to keep
      `DELETE FROM users WHERE NOT confirmed AND created_at < now() - interval '7 days'`,
      `CREATE INDEX IF NOT EXISTS watches_slug ON watches (slug)`,
      `CREATE TABLE IF NOT EXISTS ratelimit (k text NOT NULL, at timestamptz NOT NULL DEFAULT now())`,
      // billing (inert unless BILLING_ENABLED): plan is what was bought, plan_status gates it (see EFFECTIVE_PLAN)
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS plan text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'team')),
        ADD COLUMN IF NOT EXISTS paddle_customer_id text, ADD COLUMN IF NOT EXISTS paddle_subscription_id text UNIQUE,
        ADD COLUMN IF NOT EXISTS plan_status text, ADD COLUMN IF NOT EXISTS plan_updated_at timestamptz,
        ADD COLUMN IF NOT EXISTS past_due_since timestamptz`,
      `CREATE TABLE IF NOT EXISTS webhook_events (event_id text PRIMARY KEY, received_at timestamptz NOT NULL DEFAULT now())`,
      `DELETE FROM webhook_events WHERE received_at < now() - interval '90 days'`,
      `CREATE INDEX IF NOT EXISTS ratelimit_k_at ON ratelimit (k, at)`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS slack_webhook text`, // optional Slack incoming-webhook URL (a credential)
      // Team seats: a member gets the owner's watchlist alerts. invited_by is set until the emailed link is confirmed.
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS team_owner bigint REFERENCES users(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS invited_by bigint REFERENCES users(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS invite_hash text, ADD COLUMN IF NOT EXISTS invite_expires timestamptz`, // own slot: never clobbers a sign-up link
      // Team org view: per-repo results sent by `mcpwatch report` with a report key, checked against users.policy
      // widen the token kinds once (skips the table lock when already done)
      `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tokens_kind_check' AND pg_get_constraintdef(oid) LIKE '%report%') THEN
        ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_kind_check, ADD CONSTRAINT tokens_kind_check CHECK (kind IN ('manage', 'unsub', 'report')); END IF; END $$`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS policy jsonb`,
      `CREATE TABLE IF NOT EXISTS repo_reports (user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE, repo text NOT NULL,
        reported_at timestamptz NOT NULL DEFAULT now(), servers jsonb NOT NULL, violations jsonb NOT NULL, PRIMARY KEY (user_id, repo))`,
    ]) await sql(q);
  })().catch((e) => { schema = null; throw e; });
  return schema;
}

const unsubLink = (token) => `${SITE}/api/unsubscribe?t=${token}`;
const newToken = () => crypto.randomBytes(32).toString("base64url");
const hash = (t) => crypto.createHash("sha256").update(String(t)).digest("hex");

const TOKEN_TTL = { manage: "30 days", unsub: "90 days", report: "365 days" };
// Stores only the hash. No per-user cap on purpose: a cap would let anyone who knows an address push that user's real,
// older links out by requesting new ones. Growth is bounded by the mail rate limit and expiry + pruning.
async function issueToken(userId, kind) {
  const t = newToken();
  await sql(`INSERT INTO tokens (user_id, kind, hash, expires_at) VALUES ($1, $2, $3, now() + $4::interval)`,
    [userId, kind, hash(t), TOKEN_TTL[kind]]);
  return t;
}
// The plan a user gets right now, enforced by subscription status: canceled/paused (Paddle flips the status at the
// period end) mean free; past_due keeps the plan for a 7-day grace. mcpwatch/digest.py has the same expression.
const EFFECTIVE_PLAN = `CASE WHEN u.plan <> 'free' AND (u.plan_status IN ('active', 'trialing')
  OR (u.plan_status = 'past_due' AND u.past_due_since > now() - interval '7 days')) THEN u.plan ELSE 'free' END`;
// Team policy: which checks fail a repo's report. Unknown keys are dropped; grades compare A (best) to F.
const POLICY_KEYS = ["no_plain_http", "require_pinned", "no_secrets", "require_auth", "indexed_only"];
function cleanPolicy(v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new HttpError(400, "policy must be an object");
  const out = {};
  for (const k of POLICY_KEYS) if (v[k] === true) out[k] = true;
  if (v.min_grade != null && v.min_grade !== "") {
    if (!/^[A-F]$/.test(v.min_grade)) throw new HttpError(400, "min_grade must be A to F");
    out.min_grade = v.min_grade;
  }
  return out;
}
// One violation per broken rule per server. `rec` is the public index record (or undefined for a private server).
function policyViolations(policy, label, rules, rec) {
  const p = policy || {}, v = [];
  const has = (r) => rules.includes(r);
  if (p.no_plain_http && has("MW004")) v.push({ server: label, rule: "no_plain_http", message: "remote server over plain HTTP" });
  if (p.require_pinned && has("MW002")) v.push({ server: label, rule: "require_pinned", message: "package version is not pinned" });
  if (p.no_secrets && has("MW001")) v.push({ server: label, rule: "no_secrets", message: "plaintext secret in the config" });
  if (p.indexed_only && !rec) v.push({ server: label, rule: "indexed_only", message: "server is not in the public MCP registry index" });
  if (rec && p.require_auth && rec.a === "open") v.push({ server: label, rule: "require_auth", message: "endpoint lists its tools to anyone without credentials" });
  if (rec && p.min_grade && /^[A-F]$/.test(rec.g || "") && rec.g > p.min_grade) {
    v.push({ server: label, rule: "min_grade", message: `grade ${rec.g} is below the team minimum ${p.min_grade}` });
  }
  return v;
}

// Team features: open to everyone in the free beta, the team plan once billing is on.
const TEAM_SEATS = () => envInt("TEAM_SEATS", 10);
const teamAllowed = (plan) => !billingEnabled() || plan === "team";
const billingEnabled = () => /^(1|true|yes|on)$/i.test(process.env.BILLING_ENABLED || "");
const envInt = (k, d) => (/^\d+$/.test(process.env[k] || "") ? Number(process.env[k]) : d);
function planLimit(plan) {
  if (!billingEnabled()) return MAX_SLUGS;
  return Math.min(MAX_SLUGS, { free: envInt("FREE_WATCH_LIMIT", 3), pro: envInt("PRO_WATCH_LIMIT", 50), team: envInt("TEAM_WATCH_LIMIT", 200) }[plan] ?? 3);
}

// The user behind an unexpired token of exactly this kind (with effective plan), or undefined.
const tokenUser = async (kind, t) => (await sql(
  `SELECT u.id, u.email, ${EFFECTIVE_PLAN} AS plan, u.paddle_customer_id, u.paddle_subscription_id, u.slack_webhook, u.team_owner, u.policy
   FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.hash = $1 AND t.kind = $2 AND t.expires_at > now()`,
  [hash(t), kind]))[0];
// Deletes the user behind an unexpired token of this kind; tokens and watches go with it (ON DELETE CASCADE).
const deleteByToken = async (kind, t) => (await sql(
  `DELETE FROM users WHERE id = (SELECT user_id FROM tokens WHERE hash = $1 AND kind = $2 AND expires_at > now()) RETURNING id`,
  [hash(t), kind])).length > 0;

// true when over the limit. Keys are hashed (no raw IPs or emails in the table) and rows expire after an hour.
async function limited(kind, value, max) {
  const rows = await sql(
    `WITH gc AS (DELETE FROM ratelimit WHERE at < now() - interval '1 hour'), ins AS (INSERT INTO ratelimit (k) VALUES ($1))
     SELECT count(*) AS n FROM ratelimit WHERE k = $1 AND at > now() - interval '1 hour'`, [hash(kind + ":" + value)]);
  return Number(rows[0].n) >= max; // the snapshot excludes this request's own row
}

const clientIp = (req) => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function readJson(req) {
  if (req.method !== "POST") throw new HttpError(405, "POST only");
  if (!/^application\/json\s*(;|$)/i.test(String(req.headers["content-type"] || ""))) throw new HttpError(415, "send application/json");
  if (Number(req.headers["content-length"] || 0) > MAX_BODY) throw new HttpError(413, "body too large");
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > MAX_BODY) throw new HttpError(413, "body too large");
    chunks.push(Buffer.from(c));
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (v && typeof v === "object" && !Array.isArray(v)) return v;
  } catch (_) { /* fall through */ }
  throw new HttpError(400, "invalid JSON body");
}

function cleanEmail(v) {
  const e = typeof v === "string" ? v.trim().toLowerCase() : "";
  if (e.length > 254 || !EMAIL.test(e)) throw new HttpError(400, "enter a valid email address");
  return e;
}

// Format check, dedupe, cap, and existence in the public index (static shard on the production host).
async function cleanSlugs(v, { checkExists = true } = {}) {
  if (v == null) return [];
  if (!Array.isArray(v) || v.length > MAX_SLUGS) throw new HttpError(400, `slugs must be a list of at most ${MAX_SLUGS}`);
  const slugs = [...new Set(v)];
  if (!slugs.every((s) => typeof s === "string" && SLUG.test(s))) throw new HttpError(400, "invalid server id");
  if (!checkExists) return slugs;
  const shards = {};
  try {
    await Promise.all([...new Set(slugs.map((s) => s.slice(-8, -6)))].map(async (sh) => { shards[sh] = await deps.fetchJSON(`${SITE}/d/${sh}.json`); }));
  } catch (_) {
    throw new HttpError(503, "could not reach the index, try again shortly");
  }
  const unknown = slugs.filter((s) => !(shards[s.slice(-8, -6)] || {})[s]);
  if (unknown.length) throw new HttpError(400, `unknown server id: ${unknown.slice(0, 5).join(", ")}`);
  return slugs;
}

// Adds slugs up to `limit` watches in total (pending included). pending=true for unauthenticated adds (activated by
// the confirm link). Silently truncates: callers that can say so (manage) check first with overLimit().
const addWatches = (userId, slugs, pending, limit = MAX_SLUGS) => slugs.length ? sql(
  // slugs already watched go first and only the user's *other* rows count against the limit, so re-adding an existing
  // slug never pushes a new one out
  `INSERT INTO watches (user_id, slug, pending)
   SELECT $1, x.s, $3::boolean FROM jsonb_array_elements_text($2::jsonb) WITH ORDINALITY AS x(s, i)
   ORDER BY EXISTS (SELECT 1 FROM watches w WHERE w.user_id = $1 AND w.slug = x.s) DESC, x.i
   LIMIT GREATEST(0, $4::int - (SELECT count(*) FROM watches w WHERE w.user_id = $1
     AND w.slug NOT IN (SELECT jsonb_array_elements_text($2::jsonb))))
   ON CONFLICT (user_id, slug) DO UPDATE SET pending = watches.pending AND EXCLUDED.pending`, [userId, slugs, pending, limit]) : null;

function limitError(plan, limit) {
  if (!billingEnabled()) return new HttpError(400, `you can watch up to ${limit} servers`);
  return new HttpError(402, plan === "free" ? `the free plan watches up to ${limit} servers: upgrade to Pro to watch up to ${planLimit("pro")}`
    : `your plan watches up to ${limit} servers`);
}

function send(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(obj));
}

// Static HTML for link landings; `text` is a constant chosen by the handler, never request data.
// `button`: a button that /watch.js (same-origin static script) wires to POST the URL's token as JSON.
const PAGE_CSS = ":root{--bg:#fff;--fg:#0e1417;--mut:#55616b;--line:#e2e8ec;--acc:#0f766e;--on:#fff}" +
  "@media (prefers-color-scheme:dark){:root{--bg:#0b0f12;--fg:#e6edf0;--mut:#9aa7b0;--line:#1f2a30;--acc:#2dd4bf;--on:#04201d}}" +
  "body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,sans-serif}" +
  "header{border-bottom:1px solid var(--line)}header a{display:inline-flex;gap:8px;align-items:center;padding:16px;color:var(--fg);font-weight:700;text-decoration:none}" +
  "main{max-width:560px;margin:48px auto;padding:0 16px}h1{font-size:1.8rem;line-height:1.2}p{color:var(--mut)}a{color:var(--acc)}" +
  "button{font:inherit;font-weight:600;min-height:44px;padding:0 18px;border-radius:8px;border:1px solid var(--acc);background:var(--acc);color:var(--on);cursor:pointer}" +
  "button:focus-visible{outline:2px solid var(--acc);outline-offset:2px}";
const MARK = `<svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#0f766e"/>` +
  `<circle cx="12" cy="12" r="6.5" fill="none" stroke="#fff" stroke-width="2" stroke-dasharray="30 11"/><path d="M12 12l5-4" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>`;

// Static HTML for link landings; `text` is a constant chosen by the handler, never request data.
// `button`: a button that /watch.js (same-origin static script) wires to POST the URL's token as JSON.
function htmlPage(res, status, title, text, button) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex"><title>${title}: mcpwatch</title><style>${PAGE_CSS}</style></head>` +
    `<body><header><a href="/">${MARK}mcpwatch</a></header><main><h1>${title}</h1><p>${text}</p>` +
    (button ? `<p><button type="button" id="link-btn">${button}</button></p><p id="link-msg" aria-live="polite"></p>` +
      `<script src="/watch.js"></script>` : "") +
    `<p><a href="/watch">Back to mcpwatch</a></p></main></body></html>`);
}

// Wraps a handler: maps HttpError to JSON, everything else to a generic 500 (no user data in logs).
const handler = (fn) => async (req, res) => {
  try {
    await fn(req, res);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(`${req.url && req.url.split("?")[0]}: internal error: ${e && e.message ? String(e.message).slice(0, 80) : "unknown"}`);
    send(res, 500, { error: "something went wrong, try again later" });
  }
};

module.exports = { deps, teamAllowed, cleanPolicy, policyViolations, POLICY_KEYS, TEAM_SEATS, SLACK_HOOK, slackPost: (...a) => deps.slackPost(...a), EFFECTIVE_PLAN, billingEnabled, planLimit, limitError, paddle: (...a) => deps.paddle(...a), unsubLink, issueToken, tokenUser, deleteByToken, sql, sendMail, ensureSchema, newToken, hash, limited, clientIp, readJson, cleanEmail, cleanSlugs, addWatches,
  send, htmlPage, handler, HttpError, SITE, TOKEN, MAX_SLUGS, _resetSchema: () => { schema = null; } };
