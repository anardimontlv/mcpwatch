// GET /api/v1/lookup?url=https://...  |  ?package=npm:@scope/name (npm, pypi, oci)  |  ?id=<server id>
// Public lookup API for registries, agent platforms and IDEs: is this MCP server in the index, and how does it grade?
// Default-deny like the MCP server: identifiers, grades and rule codes only, never third-party text (titles,
// descriptions, tool text), so the answer is safe to hand to a model. 60 lookups/hour per IP; a Team report key in
// `Authorization: Bearer <key>` raises that to 5,000/hour per team.
const crypto = require("crypto");
const L = require("../_lib");
let S;
try { S = require("../../site/scan.js"); } catch (_) { S = require("../../web/scan.js"); } // site/ on Vercel, web/ in the repo

const ID = /^[a-z0-9-]{10,100}$/;
const IDENT = /^[A-Za-z0-9@/._:-]{1,214}$/;
const RULES_DOC = "https://github.com/anardimontlv/mcpwatch#scanner-rules";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
}

function keyOf(q) {
  if (typeof q.url === "string") {
    if (q.url.length > 2048 || !/^https?:\/\//i.test(q.url)) throw new L.HttpError(400, "url must be an http(s) URL");
    return S.urlKey(q.url);
  }
  if (typeof q.package === "string") {
    const [kind, ...rest] = q.package.split(":");
    const ident = rest.join(":");
    if (!["npm", "pypi", "oci"].includes(kind) || !IDENT.test(ident)) throw new L.HttpError(400, "package must look like npm:name, pypi:name or oci:image");
    return S.pkgKey(kind, ident);
  }
  throw new L.HttpError(400, "give one of url, package or id");
}

const shardOf = (k) => crypto.createHash("sha256").update(k).digest("hex").slice(0, 2);

module.exports = L.handler(async (req, res) => {
  cors(res);
  if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
  if (req.method !== "GET") throw new L.HttpError(405, "GET only");
  const q = Object.fromEntries(new URL(req.url, "http://x").searchParams);
  let id = typeof q.id === "string" ? q.id : null;
  if (id !== null && !ID.test(id)) throw new L.HttpError(400, "invalid id");
  const key = id ? null : keyOf(q);
  if (!id && !key) throw new L.HttpError(400, "could not derive a lookup key");
  await L.ensureSchema();
  const auth = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(String(req.headers.authorization || ""));
  const team = auth ? await L.tokenUser("report", auth[1]) : null;
  if (auth && !(team && L.teamAllowed(team.plan))) throw new L.HttpError(403, "invalid API key");
  if (await L.limited("api", team ? "team:" + team.id : L.clientIp(req), team ? 5000 : 60)) {
    throw new L.HttpError(429, team ? "rate limit: 5,000 lookups/hour" : "rate limit: 60 lookups/hour without a key");
  }
  let shard;
  try {
    if (!id) {
      const m = (await L.deps.fetchJSON(`${L.SITE}/m/${shardOf(key)}.json`))[key];
      if (Array.isArray(m)) return L.send(res, 409, { error: "several index entries claim this server; look it up by id", ids: m.slice(0, 10) });
      if (typeof m !== "string") return L.send(res, 404, { error: "not in the index (private, local, or not in the official MCP registry)", key });
      id = m;
    }
    shard = await L.deps.fetchJSON(`${L.SITE}/d/${id.slice(-8, -6)}.json`);
  } catch (_) {
    throw new L.HttpError(503, "could not reach the index, try again shortly");
  }
  const r = shard[id];
  if (!r) return L.send(res, 404, { error: "unknown id" });
  L.send(res, 200, {
    id, name: r.n, grade: r.g, score: Number(r.s), auth: r.a || null, last_verified: r.vd || null, rules_version: r.rv || null,
    tools_fingerprinted: r.h ? true : false,
    findings: (r.f || []).map((f) => ({ severity: f[0], rule: f[1] })), rules_doc: RULES_DOC,
    page: `${L.SITE}/s/${id}`, badge: `${L.SITE}/badge/${id}.svg`,
    note: "Automated signals, not an audit.",
  });
});
