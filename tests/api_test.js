// Exercises the api/ handlers with an in-memory fake of the SQL they issue and a fake mailer. No network.
// Run: node --test tests/api_test.js (tests/test_api.py runs it under unittest).
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const L = require(path.join(__dirname, "..", "api", "_lib"));
const subscribe = require(path.join(__dirname, "..", "api", "subscribe"));
const confirm = require(path.join(__dirname, "..", "api", "confirm"));
const manage = require(path.join(__dirname, "..", "api", "manage"));
const unsubscribe = require(path.join(__dirname, "..", "api", "unsubscribe"));

const KNOWN = ["alpha-server-0a1b2c3d", "beta-server-0a9f8e7d", "gamma-server-7c000000"];
let db, mails, mailOk, queries, errors, fetchFails;

function fakeSql(q, p) {
  queries.push(q);
  const now = db.now;
  const user = (pred) => db.users.find(pred);
  const del = (u) => { // ON DELETE CASCADE
    db.users = db.users.filter((x) => x !== u);
    db.watches = db.watches.filter((w) => w.user_id !== u.id);
    db.tokens = db.tokens.filter((t) => t.user_id !== u.id);
  };
  const live = (h, kind) => db.tokens.find((t) => t.hash === h && t.kind === kind && t.expires_at > now);
  if (/^\s*(CREATE|ALTER)/.test(q)) return [];
  if (q.startsWith("DELETE FROM tokens WHERE expires_at < now()")) { db.tokens = db.tokens.filter((t) => t.expires_at >= now); return []; }
  if (q.startsWith("DELETE FROM users WHERE NOT confirmed")) { // 7-day purge of never-confirmed sign-ups
    db.users.filter((u) => !u.confirmed && u.created_at < now - 7 * 864e5).forEach(del); return [];
  }
  if (q.includes("INTO ratelimit")) {
    db.rl = db.rl.filter((r) => r.at >= now - 3600e3);
    const n = db.rl.filter((r) => r.k === p[0]).length;
    db.rl.push({ k: p[0], at: now });
    return [{ n: String(n) }];
  }
  if (q.includes("INSERT INTO users")) {
    let u = user((x) => x.email === p[0]);
    if (!u) db.users.push((u = { id: String(++db.seq), email: p[0], confirmed: false, created_at: now }));
    return [{ id: u.id }];
  }
  if (q.includes("INSERT INTO watches")) {
    const [uid, json, pending] = p;
    const room = Math.max(0, L.MAX_SLUGS - db.watches.filter((w) => w.user_id === uid).length);
    for (const s of JSON.parse(json).slice(0, room)) {
      const w = db.watches.find((x) => x.user_id === uid && x.slug === s);
      if (w) w.pending = w.pending && pending === "true";
      else db.watches.push({ user_id: uid, slug: s, pending: pending === "true" });
    }
    return [];
  }
  if (q.includes("SET confirm_hash = $2")) {
    Object.assign(user((x) => x.id === p[0]), { confirm_hash: p[1], confirm_expires: now + 24 * 3600e3 });
    return [];
  }
  if (q.includes("INSERT INTO tokens")) {
    const [uid, kind, h, ttl] = p;
    db.tokens.push({ user_id: uid, kind, hash: h, seq: ++db.seq, expires_at: now + Number(/^(\d+) days$/.exec(ttl)[1]) * 86400e3 });
    return [];
  }
  if (q.includes("SELECT u.id, u.email FROM tokens t")) {
    const t = live(p[0], p[1]);
    const u = t && user((x) => x.id === t.user_id);
    return u ? [{ id: u.id, email: u.email }] : [];
  }
  if (q.includes("DELETE FROM users WHERE id = (SELECT user_id FROM tokens")) {
    const t = live(p[0], p[1]);
    const u = t && user((x) => x.id === t.user_id);
    if (!u) return [];
    del(u);
    return [{ id: u.id }];
  }
  if (q.includes("SELECT id FROM users WHERE email = $1 AND confirmed")) {
    const u = user((x) => x.email === p[0] && x.confirmed);
    return u ? [{ id: u.id }] : [];
  }
  if (q.includes("SET confirmed = true")) {
    const u = user((x) => x.confirm_hash === p[0] && x.confirm_expires > now);
    if (!u) return [];
    Object.assign(u, { confirmed: true, confirm_hash: null, confirm_expires: null });
    return [{ id: u.id }];
  }
  if (q.includes("UPDATE watches SET pending = false")) { db.watches.forEach((w) => { if (w.user_id === p[0]) w.pending = false; }); return []; }
  if (q.includes("DELETE FROM watches WHERE user_id = $1")) {
    const s = JSON.parse(p[1]);
    db.watches = db.watches.filter((w) => !(w.user_id === p[0] && s.includes(w.slug)));
    return [];
  }
  if (q.includes("SELECT slug FROM watches WHERE user_id = $1 AND NOT pending")) {
    return db.watches.filter((w) => w.user_id === p[0] && !w.pending).map((w) => ({ slug: w.slug })).sort((a, b) => a.slug.localeCompare(b.slug));
  }
  throw new Error("fake sql: unexpected query: " + q.slice(0, 60));
}

const origError = console.error;
test.beforeEach(() => {
  db = { users: [], watches: [], rl: [], tokens: [], seq: 0, now: Date.parse("2026-11-22T10:00:00Z") };
  mails = []; mailOk = true; queries = []; errors = []; fetchFails = false;
  L.deps.sql = async (q, p) => fakeSql(q, p);
  L.deps.sendMail = async (m) => { mails.push(m); return mailOk; };
  L.deps.fetchJSON = async (url) => {
    if (fetchFails) throw new Error("down");
    const sh = /\/d\/([0-9a-f]{2})\.json$/.exec(url)[1];
    return Object.fromEntries(KNOWN.filter((s) => s.slice(-8, -6) === sh).map((s) => [s, { t: s }]));
  };
  L._resetSchema();
  console.error = (...a) => errors.push(a.join(" "));
});
test.afterEach(() => {
  console.error = origError;
  for (const e of errors) assert.doesNotMatch(e, /@example\.com/, "no user data in logs");
});

let ipSeq = 0;
async function call(h, { method = "POST", url = "/api/x", body, type = "application/json", ip } = {}) {
  const raw = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
  const req = {
    method, url, headers: { "content-type": type, "x-forwarded-for": `${ip || "10.0.0." + ++ipSeq}, 172.16.0.1` },
    async *[Symbol.asyncIterator]() { if (raw) yield Buffer.from(raw); },
  };
  const res = { statusCode: 200, headers: {}, body: "", setHeader(k, v) { this.headers[k.toLowerCase()] = v; }, end(b) { this.body = b || ""; } };
  await h(req, res);
  let json = null;
  try { json = JSON.parse(res.body); } catch (_) { /* html */ }
  return { status: res.statusCode, json, body: res.body, headers: res.headers };
}
const tokenIn = (text, re) => (re.exec(text) || [])[1];
const confirmTok = (m) => tokenIn(m.text, /\/api\/confirm\?t=([A-Za-z0-9_-]{43})/);
const unsubTok = (m) => tokenIn(m.text, /\/api\/unsubscribe\?t=([A-Za-z0-9_-]{43})/);

async function signUp(email, slugs) {
  await call(subscribe, { body: { email, slugs } });
  const r = await call(confirm, { url: "/api/confirm", body: { t: confirmTok(mails.at(-1)) } });
  assert.equal(r.status, 200);
  return r.json.manage;
}

test("subscribe: confirmation email, token stored only as a hash, slugs pending", async () => {
  const r = await call(subscribe, { body: { email: "  New@Example.com ", slugs: [KNOWN[0], KNOWN[0]] } });
  assert.equal(r.status, 200);
  assert.equal(mails.length, 1);
  assert.equal(mails[0].to, "new@example.com");
  const t = confirmTok(mails[0]);
  assert.ok(t);
  assert.equal(db.users[0].confirm_hash, L.hash(t));
  assert.ok(!JSON.stringify(db).includes(t), "raw token never stored");
  assert.deepEqual(db.watches, [{ user_id: "1", slug: KNOWN[0], pending: true }]);
});

test("no enumeration: identical response for a new and an existing confirmed email", async () => {
  const a = await call(subscribe, { body: { email: "fresh@example.com", slugs: [] } });
  const manageTok = await signUp("old@example.com", [KNOWN[0]]);
  const b = await call(subscribe, { body: { email: "old@example.com", slugs: [KNOWN[1]] } });
  assert.equal(a.status, b.status);
  assert.equal(a.body, b.body);
  // an unauthenticated subscribe cannot change a confirmed user's active list
  const l = await call(manage, { body: { token: manageTok, action: "list" } });
  assert.deepEqual(l.json.slugs, [KNOWN[0]]);
});

test("content type, method, size and JSON checks", async () => {
  assert.equal((await call(subscribe, { body: "email=a@example.com", type: "application/x-www-form-urlencoded" })).status, 415);
  assert.equal((await call(subscribe, { body: "{}", type: "text/plain" })).status, 415);
  assert.equal((await call(subscribe, { method: "GET" })).status, 405);
  assert.equal((await call(subscribe, { body: JSON.stringify({ email: "a@example.com", pad: "x".repeat(17000) }) })).status, 413);
  assert.equal((await call(subscribe, { body: "{nope" })).status, 400);
  assert.equal((await call(subscribe, { body: "[1]" })).status, 400);
  assert.equal((await call(manage, { body: "{}", type: "text/plain" })).status, 415);
  assert.equal((await call(unsubscribe, { url: "/api/unsubscribe?t=x", body: "", type: "application/x-www-form-urlencoded" })).status, 415);
  assert.equal(mails.length, 0);
});

test("email validation", async () => {
  for (const email of ["", "no-at", "a@b", "a b@example.com", "x".repeat(250) + "@example.com", 5, null]) {
    assert.equal((await call(subscribe, { body: { email, slugs: [] } })).status, 400, String(email));
  }
});

test("slug validation: format, existence, cap, index outage", async () => {
  const sub = (slugs) => call(subscribe, { body: { email: "s@example.com", slugs } });
  assert.equal((await sub(["UPPER-case-slug-0a1b2c3d"])).status, 400);
  assert.equal((await sub(["short"])).status, 400);
  assert.equal((await sub(["a".repeat(101)])).status, 400);
  assert.equal((await sub([1])).status, 400);
  assert.equal((await sub("alpha-server-0a1b2c3d")).status, 400);
  assert.equal((await sub(["valid-but-unknown-0a1b2c3d"])).status, 400);
  assert.equal((await sub(Array.from({ length: 201 }, (_, i) => `server-number-${i}-0a1b2c3d`))).status, 400);
  fetchFails = true;
  assert.equal((await sub([KNOWN[0]])).status, 503);
  assert.equal(db.users.length, 0);
  assert.equal(mails.length, 0);
});

test("rate limits: 3 confirmation emails per address per hour, 20 requests per IP per hour", async () => {
  for (let i = 0; i < 5; i++) {
    const r = await call(subscribe, { body: { email: "rl@example.com", slugs: [] } });
    assert.equal(r.status, 200); // over the mail limit still looks the same
  }
  assert.equal(mails.length, 3);
  db.now += 3601e3;
  await call(subscribe, { body: { email: "rl@example.com", slugs: [] } });
  assert.equal(mails.length, 4);
  for (let i = 0; i < 20; i++) assert.equal((await call(subscribe, { ip: "203.0.113.9", body: { email: `ip${i}@example.com` } })).status, 200);
  assert.equal((await call(subscribe, { ip: "203.0.113.9", body: { email: "ip21@example.com" } })).status, 429);
  assert.equal((await call(subscribe, { ip: "203.0.113.10", body: { email: "ip22@example.com" } })).status, 200);
  assert.ok(!JSON.stringify(db.rl).includes("203.0.113.9"), "rate-limit keys are hashed");
});

test("confirm: GET never consumes; token is single-use and expires after 24h", async () => {
  await call(subscribe, { body: { email: "c@example.com", slugs: [KNOWN[0]] } });
  const t = confirmTok(mails[0]);
  const g = await call(confirm, { method: "GET", url: `/api/confirm?t=${t}` });
  assert.equal(g.status, 200);
  assert.match(g.body, /<script src="\/watch\.js"><\/script>/);
  assert.ok(!g.body.includes(t), "token not echoed into the page");
  assert.equal(db.users[0].confirmed, false);
  const r = await call(confirm, { url: "/api/confirm", body: { t } });
  assert.equal(r.status, 200);
  assert.ok(db.tokens.some((x) => x.kind === "manage" && x.hash === L.hash(r.json.manage)));
  assert.ok(!JSON.stringify(db).includes(r.json.manage), "raw manage token never stored");
  assert.equal(db.watches[0].pending, false);
  assert.equal((await call(confirm, { url: "/api/confirm", body: { t } })).status, 410);
  await call(subscribe, { body: { email: "late@example.com", slugs: [] } });
  db.now += 24 * 3600e3 + 1000;
  assert.equal((await call(confirm, { url: "/api/confirm", body: { t: confirmTok(mails.at(-1)) } })).status, 410);
  assert.equal((await call(confirm, { url: "/api/confirm", body: { t: "bad" } })).status, 400);
});

test("a newer confirmation email invalidates the older link", async () => {
  await call(subscribe, { body: { email: "two@example.com" } });
  await call(subscribe, { body: { email: "two@example.com" } });
  assert.equal((await call(confirm, { url: "/api/confirm", body: { t: confirmTok(mails[0]) } })).status, 410);
  assert.equal((await call(confirm, { url: "/api/confirm", body: { t: confirmTok(mails[1]) } })).status, 200);
});

test("manage: list, add, remove; unconfirmed or wrong tokens rejected", async () => {
  const tok = await signUp("m@example.com", [KNOWN[0]]);
  const op = (body) => call(manage, { body: { token: tok, ...body } });
  assert.deepEqual((await op({ action: "list" })).json.slugs, [KNOWN[0]]);
  assert.deepEqual((await op({ action: "add", slugs: [KNOWN[1], KNOWN[2]] })).json.slugs, [KNOWN[0], KNOWN[1], KNOWN[2]].sort());
  assert.equal((await op({ action: "add", slugs: ["valid-but-unknown-0a1b2c3d"] })).status, 400);
  assert.deepEqual((await op({ action: "remove", slugs: [KNOWN[0]] })).json.slugs, [KNOWN[1], KNOWN[2]].sort());
  assert.equal((await op({ action: "nope" })).status, 400);
  assert.equal((await call(manage, { body: { token: "x".repeat(43), action: "list" } })).status, 403);
  assert.equal((await call(manage, { body: { token: 5, action: "list" } })).status, 403);
});

test("unsubscribe: GET does not delete; POST with the unsubscribe token deletes the user and cascades", async () => {
  const manageTok = await signUp("u@example.com", [KNOWN[0], KNOWN[1]]);
  const unsub = unsubTok(mails[0]);
  assert.ok(unsub && unsub !== manageTok);
  queries.length = 0;
  const g = await call(unsubscribe, { method: "GET", url: `/api/unsubscribe?t=${unsub}` });
  assert.equal(g.status, 200);
  assert.ok(!g.body.includes(unsub));
  assert.equal(db.users.length, 1);
  assert.deepEqual(queries, [], "GET issued no query at all");
  // tokens are not interchangeable
  assert.equal((await call(unsubscribe, { url: "/api/unsubscribe", body: { t: manageTok } })).status, 410);
  assert.equal((await call(manage, { body: { token: unsub, action: "list" } })).status, 403);
  assert.equal((await call(manage, { body: { token: unsub, action: "delete_account" } })).status, 403);
  assert.equal(db.users.length, 1);
  const r = await call(unsubscribe, { url: "/api/unsubscribe", body: { t: unsub } });
  assert.equal(r.status, 200);
  assert.ok(queries.some((q) => q.startsWith("DELETE FROM users WHERE id = (SELECT user_id FROM tokens")));
  assert.deepEqual([db.users, db.watches, db.tokens], [[], [], []]);
  assert.equal((await call(unsubscribe, { url: "/api/unsubscribe", body: { t: unsub } })).status, 410);
});

test("delete_account deletes the user row (watches cascade)", async () => {
  const tok = await signUp("d@example.com", [KNOWN[0]]);
  const r = await call(manage, { body: { token: tok, action: "delete_account" } });
  assert.deepEqual(r.json, { ok: true, deleted: true });
  assert.ok(queries.some((q) => q.startsWith("DELETE FROM users WHERE id = (SELECT user_id FROM tokens")));
  assert.ok(!queries.some((q) => q.startsWith("DELETE FROM watches")), "relies on ON DELETE CASCADE");
  assert.deepEqual([db.users, db.watches, db.tokens], [[], [], []]);
  assert.equal((await call(manage, { body: { token: tok, action: "list" } })).status, 403);
});

test("email_link: generic response; new tokens leave older links valid; manage token only in a fragment", async () => {
  const old = await signUp("e@example.com", [KNOWN[0]]);
  const oldUnsub = unsubTok(mails[0]);
  const unknown = await call(manage, { body: { action: "email_link", email: "nobody@example.com" } });
  const n = mails.length;
  const known = await call(manage, { body: { action: "email_link", email: "e@example.com" } });
  assert.equal(unknown.body, known.body);
  assert.equal(mails.length, n + 1);
  const text = mails.at(-1).text;
  const tok = tokenIn(text, /\/watch#m=([A-Za-z0-9_-]{43})/);
  assert.ok(tok);
  assert.ok(!text.includes("?t=" + tok), "manage token never in a query string");
  assert.notEqual(unsubTok(mails.at(-1)), tok);
  assert.equal((await call(manage, { body: { token: old, action: "list" } })).status, 200, "older manage link still works");
  assert.equal((await call(manage, { body: { token: tok, action: "list" } })).status, 200);
  assert.equal((await call(manage, { body: { action: "email_link", email: "bad" } })).status, 400);
  // the older unsubscribe link still works after a newer one was issued
  assert.equal((await call(unsubscribe, { url: "/api/unsubscribe", body: { t: oldUnsub } })).status, 200);
  assert.equal(db.users.length, 0);
});

test("tokens expire: manage after 30 days, unsubscribe after 90", async () => {
  const tok = await signUp("x30@example.com", [KNOWN[0]]);
  const unsub = unsubTok(mails[0]);
  db.now += 29 * 86400e3;
  assert.equal((await call(manage, { body: { token: tok, action: "list" } })).status, 200);
  db.now += 2 * 86400e3;
  assert.equal((await call(manage, { body: { token: tok, action: "list" } })).status, 403);
  assert.equal((await call(manage, { body: { token: tok, action: "delete_account" } })).status, 403);
  db.now += 60 * 86400e3; // day 91
  assert.equal((await call(unsubscribe, { url: "/api/unsubscribe", body: { t: unsub } })).status, 410);
  assert.equal(db.users.length, 1);
});

test("requesting many new links never evicts a user's older, unexpired links", async () => {
  const first = await signUp("cap@example.com", [KNOWN[0]]);
  const uid = db.users[0].id;
  for (let i = 0; i < 40; i++) await L.issueToken(uid, "manage"); // e.g. an attacker spamming email_link
  assert.equal((await call(manage, { body: { token: first, action: "list" } })).status, 200);
  db.now += 31 * 864e5; // ...until it expires on its own
  assert.equal((await call(manage, { body: { token: first, action: "list" } })).status, 403);
});

test("a failed email send still returns the generic success", async () => {
  mailOk = false;
  const r = await call(subscribe, { body: { email: "f@example.com", slugs: [] } });
  assert.equal(r.status, 200);
  assert.equal(r.json.ok, true);
});

test("database errors become a generic 500 without user data", async () => {
  L.deps.sql = async () => { throw new Error("db error (HTTP 400)"); };
  const r = await call(subscribe, { body: { email: "x@example.com", slugs: [] } });
  assert.equal(r.status, 500);
  assert.ok(!r.body.includes("x@example.com"));
  assert.equal(errors.length, 1);
});


test("never-confirmed sign-ups are purged after 7 days; confirmed users are kept", async () => {
  await call(subscribe, { body: { email: "ghost@example.com", slugs: [KNOWN[0]] } });
  const manage = await signUp("kept@example.com", [KNOWN[0]]);
  assert.ok(manage);
  db.now += 8 * 864e5;
  L._resetSchema();
  await L.ensureSchema();
  assert.deepEqual(db.users.map((u) => u.email).sort(), ["kept@example.com"]);
  assert.equal(db.watches.filter((w) => !db.users.some((u) => u.id === w.user_id)).length, 0); // cascade
});
