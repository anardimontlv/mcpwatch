#!/usr/bin/env python3
"""Watchlist digest: one email per confirmed user whose watched servers changed.

  python -m mcpwatch.digest --changes site/changes.json [--dry-run]

Billing off (BILLING_ENABLED unset, the free beta): everyone gets a daily digest of today's changes.
Billing on: Pro/Team get the daily digest; Free gets a weekly one on Mondays (UTC) covering the last 7 days.

Runs after the index publishes. It must never fail the pipeline: on any DB or email error it prints a sanitized
message and exits 0. Needs DATABASE_URL (Neon) and RESEND_API_KEY; without them it skips. Stdlib only.
"""
import argparse, hashlib, json, os, secrets, sys, urllib.parse, urllib.request
import re
from datetime import date, datetime, timedelta, timezone

SITE = "https://www.mcpwatch.io"
UA = "mcpwatch-digest/0.1"


def neon_query(query, params):
    """Neon SQL-over-HTTP (the @neondatabase/serverless protocol). Rows as dicts of text values."""
    conn = os.environ["DATABASE_URL"]
    host = urllib.parse.urlsplit(conn).hostname.split(".", 1)[1]
    req = urllib.request.Request(f"https://api.{host}/sql", data=json.dumps({"query": query, "params": params}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA, "Neon-Connection-String": conn,
                                          "Neon-Raw-Text-Output": "true", "Neon-Array-Mode": "true"})
    with urllib.request.urlopen(req, timeout=30) as r:
        j = json.load(r)
    names = [f["name"] for f in j["fields"]]
    return [dict(zip(names, row)) for row in j["rows"]]


def resend_send(to, subject, text, key):
    req = urllib.request.Request("https://api.resend.com/emails", method="POST", data=json.dumps(
        {"from": os.environ.get("MAIL_FROM") or "mcpwatch <alerts@mcpwatch.io>", "to": [to], "subject": subject, "text": text}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA, "Authorization": f"Bearer {os.environ['RESEND_API_KEY']}",
                 "Idempotency-Key": key})  # a re-run of the same day's job must not double-send
    with urllib.request.urlopen(req, timeout=30) as r:
        return 200 <= r.status < 300


# same as EFFECTIVE_PLAN in api/_lib.js: canceled/paused = free, past_due keeps the plan for 7 days
EFFECTIVE_PLAN = ("CASE WHEN u.plan <> 'free' AND (u.plan_status IN ('active', 'trialing') "
                  "OR (u.plan_status = 'past_due' AND u.past_due_since > now() - interval '7 days')) THEN u.plan ELSE 'free' END")


def watchers(slugs, query):
    """{email: {"id", "plan", "slugs"}} for confirmed users watching any of `slugs`. One query."""
    rows = query("SELECT u.id, u.email, w.slug, " + EFFECTIVE_PLAN + " AS plan FROM users u JOIN watches w ON w.user_id = u.id "
                 "WHERE u.confirmed AND NOT w.pending AND w.slug IN (SELECT jsonb_array_elements_text($1::jsonb)) "
                 "ORDER BY u.email, w.slug", [json.dumps(sorted(slugs))])
    out = {}
    for r in rows:
        u = out.setdefault(r["email"], {"id": r["id"], "plan": r.get("plan") or "free", "slugs": set()})
        u["slugs"].add(r["slug"])
    return out


def pick(items, slugs):
    its = [it for it in items if it["slug"] in slugs]
    its.sort(key=lambda it: (not it.get("notable"), it.get("name", ""), it.get("date", "")))  # notable first, as on the radar
    return its


# same as api/_lib.js issueToken: hash-only storage, 90-day unsubscribe tokens, no cap (a cap would let others evict
# a user's older links); expired rows are pruned on every run
ISSUE_UNSUB = "INSERT INTO tokens (user_id, kind, hash, expires_at) VALUES ($1, 'unsub', $2, now() + interval '90 days')"


def render(date, items, unsub_url, since=None):
    n = len(items)
    if since:  # weekly: items carry their own date
        subject = f"mcpwatch weekly: {n} change{'s' if n != 1 else ''} to servers you watch ({since} to {date})"
        lines = [f"Changes from {since} to {date} to MCP servers you watch with mcpwatch.", ""]
    else:
        subject = f"mcpwatch: {n} watched server{'s' if n != 1 else ''} changed on {date}"
        lines = [f"Changes on {date} to MCP servers you watch with mcpwatch.", ""]
    for it in items:
        lines.append(f"{it.get('name', it['slug'])}" + (f" ({it['date']})" if since and it.get("date") else ""))
        lines.append(f"  {SITE}/s/{it['slug']}")
        for why in it.get("notable") or []:
            lines.append(f"  Notable: {why}")
        for c in it.get("changes", []):
            lines.append(f"  - {str(c.get('kind', '')).replace('_', ' ')}: {c.get('detail', '')} ({c.get('sev', '')})")
        lines.append("")
    lines += ["Changes are detected automatically from public data. A change is not by itself a sign of wrongdoing.", "",
              f"Manage your watchlist: {SITE}/watch (ask for a manage link with your email)",
              f"Unsubscribe and delete your data: {unsub_url}", ""]
    return subject, "\n".join(lines)


def run(changes, today, query, send, dry_run=False, billing=False):
    """Returns (sent, failed). `query(sql, params)` and `send(to, subject, text, idempotency_key)` are injected."""
    changes = changes or []
    daily = (changes[0].get("items") or []) if changes and changes[0].get("date") == today else []
    since = (date.fromisoformat(today) - timedelta(days=6)).isoformat()
    weekly = [dict(it, date=d["date"]) for d in changes if isinstance(d.get("date"), str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d["date"])
              and since <= d["date"] <= today for it in d.get("items") or []] if billing and date.fromisoformat(today).weekday() == 0 else []
    if not daily and not weekly:
        print(f"digest: no changes to send for {today}")
        return 0, 0
    if not dry_run:
        query("DELETE FROM tokens WHERE expires_at < now()", [])  # prune; older unsubscribe links stay valid until they expire
    users = {}
    for email, u in watchers({it["slug"] for it in daily + weekly}, query).items():
        week = billing and u["plan"] == "free"
        its = pick(weekly if week else daily, u["slugs"])
        if its:
            users[email] = (u["id"], its, since if week else None)
    sent = failed = 0
    for email, (uid, its, wk) in users.items():
        if dry_run:
            sent += 1
            continue
        try:
            # a fresh unsubscribe token per digest (only its hash is stored, so an old one can't be re-sent);
            # earlier digests' links keep working for 90 days
            tok = secrets.token_urlsafe(32)
            query(ISSUE_UNSUB, [uid, hashlib.sha256(tok.encode()).hexdigest()])
            subject, text = render(today, its, f"{SITE}/api/unsubscribe?t={tok}", wk)
            key = f"digest-{today}-{hashlib.sha256(email.encode()).hexdigest()[:24]}"
            if send(email, subject, text, key):
                sent += 1
            else:
                failed += 1
        except Exception as e:  # one bad send must not stop the others; never print the address
            failed += 1
            print(f"digest: send failed ({type(e).__name__}{': HTTP ' + str(e.code) if hasattr(e, 'code') else ''})")
    print(f"digest: {len(users)} recipient(s), {sent} {'would be ' if dry_run else ''}sent, {failed} failed")
    return sent, failed


def billing_enabled():
    return (os.environ.get("BILLING_ENABLED") or "").strip().lower() in ("1", "true", "yes", "on")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--changes", default="site/changes.json")
    ap.add_argument("--dry-run", action="store_true", help="query recipients but send nothing")
    a = ap.parse_args(argv)
    if not os.environ.get("DATABASE_URL") or not (a.dry_run or os.environ.get("RESEND_API_KEY")):
        print("digest: DATABASE_URL or RESEND_API_KEY not set, skipping")
        return 0
    try:
        with open(a.changes, encoding="utf-8") as fh:
            changes = json.load(fh)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        run(changes, today, neon_query, resend_send, a.dry_run, billing_enabled())
    except Exception as e:  # sanitized: exception text can carry the connection string or an address
        print(f"digest: failed ({type(e).__name__}{': HTTP ' + str(e.code) if hasattr(e, 'code') else ''}); the index is unaffected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
