#!/usr/bin/env python3
"""Daily billing reconciliation: make every user's plan agree with Paddle (repairs missed or failed webhooks).

  python -m mcpwatch.billing_sync [--dry-run]

Lists subscriptions from Paddle, then fixes users whose plan/status disagree. Users we think are paid but whose
subscription is missing from the list are fetched one by one (it may be canceled). Skips cleanly without PADDLE_API_KEY
or DATABASE_URL, and never fails the pipeline (sanitized message, exit 0). Stdlib only.

Paddle API (verified 2026-11-22):
  GET /subscriptions?status=...&per_page=200, paginated by meta.pagination.{has_more,next}
    https://developer.paddle.com/api-reference/subscriptions/list-subscriptions
    https://developer.paddle.com/api-reference/about/pagination
  GET /subscriptions/{subscription_id}
    https://developer.paddle.com/api-reference/subscriptions/get-subscription
  subscription {id, status, customer_id, items[].price.id, custom_data}: paddle-node-sdk src/types/subscription
"""
import argparse, json, os, re, sys, urllib.parse, urllib.request

from mcpwatch.digest import neon_query

BASES = {"production": "https://api.paddle.com", "sandbox": "https://sandbox-api.paddle.com"}
LISTED = ("active", "trialing", "past_due", "paused")


def paddle_get(path_or_url):
    base = BASES["production" if os.environ.get("PADDLE_ENV") == "production" else "sandbox"]
    url = path_or_url if path_or_url.startswith(base + "/") else base + path_or_url  # `next` links are absolute
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {os.environ['PADDLE_API_KEY']}", "User-Agent": "mcpwatch-billing-sync/0.1"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def plan_of(sub, prices):
    ids = [((i or {}).get("price") or {}).get("id") for i in sub.get("items") or []]
    for plan in ("team", "pro"):
        if prices.get(plan) and prices[plan] in ids:
            return plan
    return None


def list_subscriptions(get):
    subs, url = [], f"/subscriptions?status={','.join(LISTED)}&per_page=200"
    while url:
        page = get(url)
        subs += page.get("data") or []
        pg = (page.get("meta") or {}).get("pagination") or {}
        url = pg.get("next") if pg.get("has_more") else None
    return subs


def reconcile(query, get, prices, dry_run=False):
    """Returns the number of users fixed. `query` and `get` are injected (tests use fakes)."""
    users = query("SELECT id, plan, plan_status, paddle_subscription_id, paddle_customer_id FROM users "
                  "WHERE confirmed AND (paddle_subscription_id IS NOT NULL OR plan <> 'free')", [])
    by_sub = {u["paddle_subscription_id"]: u for u in users if u.get("paddle_subscription_id")}
    by_id = {u["id"]: u for u in users}
    seen, fixes = set(), []
    for s in list_subscriptions(get):
        plan = plan_of(s, prices)
        if not plan:
            continue  # not one of our prices
        u = by_sub.get(s["id"])
        uid = str(((s.get("custom_data") or {}).get("user_id")) or "")
        if not u and re.fullmatch(r"\d{1,18}", uid):
            u = by_id.get(uid) or {"id": uid}  # paid but never recorded (webhook missed): bind by our own custom_data
            if not by_id.get(uid) and not query("SELECT id FROM users WHERE id = $1 AND confirmed", [uid]):
                continue
        if not u:
            continue
        seen.add(s["id"])
        if (u.get("plan"), u.get("plan_status"), u.get("paddle_subscription_id")) != (plan, s.get("status"), s["id"]):
            fixes.append((u["id"], plan, s.get("status"), s["id"], s.get("customer_id")))
    for sub_id, u in by_sub.items():  # paid in our DB but not listed as live: ask for that subscription directly
        if sub_id in seen or u.get("plan_status") == "canceled":
            continue
        s = (get(f"/subscriptions/{urllib.parse.quote(sub_id)}") or {}).get("data") or {}
        if s.get("status") and s["status"] != u.get("plan_status"):
            fixes.append((u["id"], plan_of(s, prices) or u.get("plan") or "free", s["status"], sub_id, s.get("customer_id")))
    for uid, plan, status, sub_id, cust in fixes:
        if not dry_run:
            query("UPDATE users SET plan = $2, plan_status = $3, paddle_subscription_id = $4, "
                  "paddle_customer_id = COALESCE($5, paddle_customer_id), plan_updated_at = now(), "
                  "past_due_since = CASE WHEN $3 = 'past_due' THEN COALESCE(past_due_since, now()) ELSE NULL END WHERE id = $1",
                  [uid, plan, status, sub_id, cust])
    print(f"billing-sync: {len(fixes)} user(s) {'would be ' if dry_run else ''}fixed")
    return len(fixes)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if not os.environ.get("PADDLE_API_KEY") or not os.environ.get("DATABASE_URL"):
        print("billing-sync: PADDLE_API_KEY or DATABASE_URL not set, skipping")
        return 0
    try:
        reconcile(neon_query, paddle_get, {"pro": os.environ.get("PADDLE_PRICE_PRO"), "team": os.environ.get("PADDLE_PRICE_TEAM")}, a.dry_run)
    except Exception as e:  # sanitized: never print bodies, keys or addresses
        print(f"billing-sync: failed ({type(e).__name__}{': HTTP ' + str(e.code) if hasattr(e, 'code') else ''})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
