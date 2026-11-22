// Shared by /api/billing/*: everything here is unreachable unless BILLING_ENABLED is set.
const L = require("../_lib");

const PLAN_PRICE = (plan) => ({ pro: process.env.PADDLE_PRICE_PRO, team: process.env.PADDLE_PRICE_TEAM }[plan]);

// price id -> plan; team wins if a subscription somehow carries both
function planOfPrices(priceIds) {
  if (process.env.PADDLE_PRICE_TEAM && priceIds.includes(process.env.PADDLE_PRICE_TEAM)) return "team";
  if (process.env.PADDLE_PRICE_PRO && priceIds.includes(process.env.PADDLE_PRICE_PRO)) return "pro";
  return null;
}

// POST bodies for checkout/portal: billing on, valid manage token. Disabled looks like a missing route.
async function billingUser(req) {
  if (!L.billingEnabled()) throw new L.HttpError(404, "not found");
  const body = await L.readJson(req);
  if (typeof body.token !== "string" || !L.TOKEN.test(body.token)) throw new L.HttpError(403, "invalid or expired manage link");
  await L.ensureSchema();
  if (await L.limited("bill-ip", L.clientIp(req), 30)) throw new L.HttpError(429, "too many requests, try again in an hour");
  const user = await L.tokenUser("manage", body.token);
  if (!user) throw new L.HttpError(403, "invalid or expired manage link");
  return { body, user };
}

module.exports = { PLAN_PRICE, planOfPrices, billingUser };
