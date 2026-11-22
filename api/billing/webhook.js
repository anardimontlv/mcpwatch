// POST /api/billing/webhook: Paddle Billing notifications. Verified 2026-11-22:
//   signature: header `Paddle-Signature: ts=<unix>;h1=<hex>`, h1 = HMAC-SHA256(secret, `${ts}:${rawBody}`), compare in
//   constant time, reject stale ts. https://developer.paddle.com/webhooks/signature-verification
//   (and paddle-node-sdk src/notifications/helpers/webhooks-validator.ts; the SDK allows 5 s of skew, we allow 5 min
//   both ways, which the replay dedupe below makes safe)
//   envelope {event_id, event_type, occurred_at, data}: paddle-node-sdk src/types/events/events-response.ts
//   subscription data {id, status: active|canceled|past_due|paused|trialing, customer_id, items[].price.id, custom_data}:
//   https://developer.paddle.com/webhooks/subscriptions/subscription-updated (+ SDK subscription-notification-response.ts)
//   transaction data {subscription_id, customer_id, items[].price_id, custom_data}:
//   https://developer.paddle.com/webhooks/transactions/transaction-completed (+ SDK transaction-notification-response.ts)
//   respond 2xx within 5 s or Paddle retries; delivery order is not guaranteed:
//   https://developer.paddle.com/webhooks/respond-to-webhooks
// Never logs the body or the signature.
const crypto = require("crypto");
const L = require("../_lib");
const { planOfPrices } = require("./_common");

const MAX_RAW = 512 * 1024;
const SKEW_S = 300;

async function rawBody(req) {
  const chunks = [];
  let n = 0;
  for await (const c of req) {
    n += c.length;
    if (n > MAX_RAW) throw new L.HttpError(413, "body too large");
    chunks.push(Buffer.from(c));
  }
  return Buffer.concat(chunks);
}

// true only for a fresh, correctly signed body. Several h1 values are accepted (secret rotation overlap).
function verify(raw, header, secret, nowMs = Date.now()) {
  if (!secret || typeof header !== "string") return false;
  let ts = null;
  const h1 = [];
  for (const part of header.split(";")) {
    const [k, v] = part.split("=", 2).map((x) => (x || "").trim());
    if (k === "ts" && /^\d{1,12}$/.test(v)) ts = v;
    if (k === "h1" && /^[0-9a-f]{64}$/i.test(v)) h1.push(Buffer.from(v.toLowerCase(), "hex"));
  }
  if (!ts || !h1.length || Math.abs(nowMs / 1000 - Number(ts)) > SKEW_S) return false;
  const want = crypto.createHmac("sha256", secret).update(`${ts}:`).update(raw).digest();
  return h1.reduce((ok, h) => crypto.timingSafeEqual(h, want) || ok, false);
}

const SUB_EVENTS = new Set(["subscription.created", "subscription.updated", "subscription.activated", "subscription.canceled",
  "subscription.past_due", "subscription.paused", "subscription.resumed", "subscription.trialing"]);

// Which of our users an event is for: custom_data.user_id (set by our checkout), then ids we already stored, then the
// Paddle customer's email only if exactly one confirmed user has it.
async function bindUser(d) {
  const uid = d.custom_data && d.custom_data.user_id;
  if (typeof uid === "string" && /^\d{1,18}$/.test(uid)) {
    const rows = await L.sql(`SELECT id FROM users WHERE id = $1 AND confirmed`, [uid]);
    if (rows.length) return rows[0].id;
  }
  const sub = d.subscription_id || (d.id && String(d.id).startsWith("sub_") ? d.id : null);
  const rows = await L.sql(`SELECT id FROM users WHERE (paddle_subscription_id = $1 OR paddle_customer_id = $2) AND confirmed`,
    [sub, d.customer_id || null]);
  if (rows.length === 1) return rows[0].id;
  if (!d.customer_id) return null;
  const c = await L.paddle("GET", `/customers/${encodeURIComponent(d.customer_id)}`); // https://developer.paddle.com/api-reference/customers/get-customer
  const email = c && c.data && typeof c.data.email === "string" ? c.data.email.trim().toLowerCase() : "";
  if (!email) return null;
  const byEmail = await L.sql(`SELECT id FROM users WHERE email = $1 AND confirmed`, [email]);
  return byEmail.length === 1 ? byEmail[0].id : null;
}

// Applies one event as a snapshot; an older event than the last one applied changes nothing (out-of-order delivery).
async function apply(ev) {
  const d = ev.data || {};
  let status, subId, prices;
  if (SUB_EVENTS.has(ev.event_type)) {
    status = d.status;
    subId = d.id;
    prices = (d.items || []).map((i) => i && i.price && i.price.id).filter(Boolean);
  } else if (ev.event_type === "transaction.completed" && d.subscription_id) {
    status = "active"; // a completed payment for a subscription
    subId = d.subscription_id;
    prices = (d.items || []).map((i) => i && (i.price_id || (i.price && i.price.id))).filter(Boolean);
  } else {
    return "ignored";
  }
  const plan = planOfPrices(prices);
  if (!plan || !["active", "trialing", "past_due", "paused", "canceled"].includes(status)) return "ignored";
  const userId = await bindUser(d);
  if (!userId) { console.error(`billing webhook: ${ev.event_type} matched no user`); return "unbound"; }
  const at = typeof ev.occurred_at === "string" && !Number.isNaN(Date.parse(ev.occurred_at)) ? ev.occurred_at : new Date().toISOString();
  await L.sql(
    `UPDATE users SET plan = $2, plan_status = $3, paddle_subscription_id = $4, paddle_customer_id = COALESCE($5, paddle_customer_id),
       plan_updated_at = $6::timestamptz,
       past_due_since = CASE WHEN $3 = 'past_due' THEN COALESCE(past_due_since, $6::timestamptz) ELSE NULL END
     WHERE id = $1 AND (plan_updated_at IS NULL OR plan_updated_at < $6::timestamptz)`,
    [userId, plan, status, subId, d.customer_id || null, at]);
  return "applied";
}

module.exports = L.handler(async (req, res) => {
  if (!L.billingEnabled()) throw new L.HttpError(404, "not found");
  if (req.method !== "POST") throw new L.HttpError(405, "POST only");
  const raw = await rawBody(req);
  if (!verify(raw, req.headers["paddle-signature"], process.env.PADDLE_WEBHOOK_SECRET)) throw new L.HttpError(401, "invalid signature");
  let ev;
  try { ev = JSON.parse(raw.toString("utf8")); } catch (_) { throw new L.HttpError(400, "invalid JSON"); }
  if (!ev || typeof ev.event_id !== "string" || !ev.event_id || ev.event_id.length > 100) throw new L.HttpError(400, "missing event_id");
  await L.ensureSchema();
  const fresh = await L.sql(`INSERT INTO webhook_events (event_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING event_id`, [ev.event_id]);
  if (!fresh.length) return L.send(res, 200, { ok: true, duplicate: true });
  try {
    L.send(res, 200, { ok: true, result: await apply(ev) });
  } catch (e) {
    // let Paddle's retry run it again: forget the event id, answer non-2xx
    await L.sql(`DELETE FROM webhook_events WHERE event_id = $1`, [ev.event_id]).catch(() => {});
    throw e;
  }
});
module.exports.verify = verify;
module.exports.apply = apply;
