// POST /api/billing/checkout {token (manage), plan: "pro"|"team"} -> {url} of a Paddle checkout for that price.
// Paddle API (verified 2026-11-22):
//   customers: GET /customers?email=..., POST /customers {email}
//     https://developer.paddle.com/api-reference/customers/list-customers
//     https://developer.paddle.com/api-reference/customers/create-customer
//   transactions: POST /transactions {items:[{price_id, quantity}], customer_id, custom_data} -> data.id, data.checkout.url
//     https://developer.paddle.com/api-reference/transactions/create-transaction
//   custom_data set on the transaction is copied to the subscription it creates:
//     https://developer.paddle.com/build/transactions/custom-data
// Checkout without Paddle.js on our pages: PADDLE_CHECKOUT_URL is a Paddle *hosted checkout* launch URL
// (https://pay.paddle.io/checkout/hsc_..., Paddle > Settings > Hosted checkouts), opened with ?transaction_id=txn_...
//   https://developer.paddle.com/paddle-js/about/hosted-checkout/ (live use needs Paddle's approval: sellers@paddle.com)
// Without it we fall back to data.checkout.url, which is the account's default payment link + ?_ptxn=; that page
// must load Paddle.js (https://developer.paddle.com/build/transactions/pass-transaction-checkout).
const L = require("../_lib");
const { PLAN_PRICE, billingUser } = require("./_common");

module.exports = L.handler(async (req, res) => {
  const { body, user } = await billingUser(req);
  const price = PLAN_PRICE(body.plan);
  if (!["pro", "team"].includes(body.plan) || !price) throw new L.HttpError(400, "unknown plan");
  if (user.plan !== "free") throw new L.HttpError(409, "you already have a paid plan: use Manage billing to change it");
  let customer = user.paddle_customer_id;
  if (!customer) {
    const found = await L.paddle("GET", `/customers?email=${encodeURIComponent(user.email)}`);
    customer = found.data && found.data[0] ? found.data[0].id : (await L.paddle("POST", "/customers", { email: user.email })).data.id;
    await L.sql(`UPDATE users SET paddle_customer_id = $2 WHERE id = $1`, [user.id, customer]);
  }
  const txn = (await L.paddle("POST", "/transactions", {
    items: [{ price_id: price, quantity: 1 }], customer_id: customer, custom_data: { user_id: String(user.id) },
  })).data;
  const hosted = process.env.PADDLE_CHECKOUT_URL;
  const url = hosted ? `${hosted}${hosted.includes("?") ? "&" : "?"}transaction_id=${encodeURIComponent(txn.id)}` : txn.checkout && txn.checkout.url;
  if (!url || !/^https:\/\//.test(url)) throw new L.HttpError(503, "checkout is not available yet");
  L.send(res, 200, { ok: true, url });
});
