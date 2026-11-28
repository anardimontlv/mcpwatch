// POST /api/billing/portal {token (manage)} -> {url} of a Paddle customer portal session (cancel, card, invoices).
// POST /customers/{customer_id}/portal-sessions {subscription_ids?} -> data.urls.general.overview. Sessions are short-lived:
// create one per click, never store it. Verified 2026-11-22:
//   https://developer.paddle.com/api-reference/customer-portals/create-customer-portal-session
//   (and paddle-node-sdk src/resources/customer-portal-sessions/index.ts, src/entities/customer-portal-session/general.ts)
const L = require("../_lib");
const { billingUser } = require("./_common");

module.exports = L.handler(async (req, res) => {
  const { user } = await billingUser(req);
  if (!user.paddle_customer_id) throw new L.HttpError(409, "no billing account yet: upgrade first");
  const s = (await L.paddle("POST", `/customers/${encodeURIComponent(user.paddle_customer_id)}/portal-sessions`,
    user.paddle_subscription_id ? { subscription_ids: [user.paddle_subscription_id] } : {})).data;
  const url = s && s.urls && s.urls.general && s.urls.general.overview;
  if (!url || !/^https:\/\//.test(url)) throw new L.HttpError(502, "the billing provider is unavailable, try again shortly");
  L.send(res, 200, { ok: true, url });
});
