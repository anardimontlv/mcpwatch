#!/usr/bin/env python3
"""Radar bot: after the daily scan, post today's aggregate radar summary to Bluesky and Mastodon,
and (on Mondays) a weekly "This week in MCP security" article to dev.to.

  python3 -m mcpwatch.announce --site site [--dry-run]

Aggregates only: public posts never name a server (named details live on the site, next to the dispute link).
Each channel is skipped unless its secrets are set, and a failure on one channel never fails the pipeline.
Posts are idempotent per day via a marker file in the history branch checkout (--state).
"""
import argparse, datetime, json, os, sys, urllib.error, urllib.request
from mcpwatch.explain import EXPLAIN

SITE = "https://www.mcpwatch.io"
UA = "mcpwatch-announce/0.1 (+https://www.mcpwatch.io)"


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def summary(stats, changes):
    """Today's numbers from the published site. Returns None when there is nothing to say."""
    if not changes:
        return None
    day = changes[0]
    items = day.get("items", [])
    reasons = {}
    for it in items:
        for w in it.get("notable") or []:
            key = w.split(" (")[0]
            reasons[key] = reasons.get(key, 0) + 1
    return {"date": day.get("date"), "changed": len(items), "notable": sum(1 for i in items if i.get("notable")),
            "reasons": reasons, "servers": stats.get("servers"), "open": stats.get("open")}


LABELS = [("endpoint stopped requiring credentials", "stopped requiring auth"),
          ("a newly added tool can execute commands or delete data", "added exec/delete tools"),
          ("grade dropped", "dropped a grade"),
          ("new tool text matches a tool-poisoning pattern", "new text matching a tool-poisoning pattern"),
          ("new tool text contains invisible characters", "new invisible Unicode in tool text")]


def short_post(s):
    """<= 300 chars (Bluesky limit), plain text, no server names."""
    parts = [f"{n} {label}" for key, label in LABELS if (n := s["reasons"].get(key))]
    lines = [f"MCP radar {s['date']}: {s['changed']:,} of {s['servers']:,} servers changed their tools; {s['notable']} notable."]
    if parts:
        lines.append("Notable: " + "; ".join(parts) + ".")
    lines.append(f"{SITE}/changes")
    lines.append("(automated daily post)")
    text = "\n".join(lines)
    while len(text) > 300 and parts:  # drop the least important detail until it fits
        parts.pop()
        lines[1] = ("Notable: " + "; ".join(parts) + ".") if parts else ""
        text = "\n".join(l for l in lines if l)
    return text[:300]


def http(method, url, body=None, headers=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    h = {"User-Agent": UA, **({"Content-Type": "application/json"} if data else {}), **(headers or {})}
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h, method=method), timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def link_facets(text):
    """Bluesky link facets for every URL in the text (byte offsets in UTF-8)."""
    import re
    out, b = [], text.encode()
    for m in re.finditer(r"https?://[^\s)]+", text):
        url = m.group(0).rstrip(".,;:")
        start = len(text[:m.start()].encode())
        out.append({"index": {"byteStart": start, "byteEnd": start + len(url.encode())},
                    "features": [{"$type": "app.bsky.richtext.facet#link", "uri": url}]})
    return out


def post_bluesky(text):
    handle, pw = os.environ.get("BLUESKY_HANDLE"), os.environ.get("BLUESKY_APP_PASSWORD")
    if not (handle and pw):
        return "skipped (no credentials)"
    # https://docs.bsky.app/docs/advanced-guides/posts : createSession, then createRecord app.bsky.feed.post
    sess = http("POST", "https://bsky.social/xrpc/com.atproto.server.createSession", {"identifier": handle, "password": pw})
    record = {"$type": "app.bsky.feed.post", "text": text,
              "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}
    if facets := link_facets(text):  # make URLs clickable
        record["facets"] = facets
    http("POST", "https://bsky.social/xrpc/com.atproto.repo.createRecord",
         {"repo": sess["did"], "collection": "app.bsky.feed.post", "record": record},
         {"Authorization": f"Bearer {sess['accessJwt']}"})
    return "posted"


def post_mastodon(text, key):
    inst, token = os.environ.get("MASTODON_INSTANCE", "").rstrip("/"), os.environ.get("MASTODON_TOKEN")
    if not (inst and token):
        return "skipped (no credentials)"
    if not inst.startswith("https://"):
        return "skipped (instance must be https)"
    # https://docs.joinmastodon.org/methods/statuses/#create ; Idempotency-Key prevents duplicates on retry
    http("POST", f"{inst}/api/v1/statuses", {"status": text, "visibility": "public"},
         {"Authorization": f"Bearer {token}", "Idempotency-Key": key})
    return "posted"


def weekly_article(stats, changes):
    week = changes[:7]
    if not week:
        return None
    total = sum(len(d.get("items", [])) for d in week)
    reasons = {}
    for d in week:
        for it in d.get("items", []):
            for w in it.get("notable") or []:
                k = w.split(" (")[0]
                reasons[k] = reasons.get(k, 0) + 1
    rows = "\n".join(f"| {label} | {reasons.get(key, 0):,} |" for key, label in LABELS)
    first, last = week[-1].get("date"), week[0].get("date")
    meaning = "".join(f"**{label[0].upper() + label[1:]}.** {EXPLAIN[key]['why']} *What to do:* {EXPLAIN[key]['do']}\n\n"
                      for key, label in LABELS if reasons.get(key) and key in EXPLAIN)
    meaning = "## What these mean\n\n" + meaning if meaning else ""
    body = f"""Automated weekly summary from the [mcpwatch rug-pull radar]({SITE}/changes), {first} to {last}.

mcpwatch checks every server in the official MCP registry daily ({stats.get('servers', 0):,} servers this week) and fingerprints the tools of every remote server it can reach without credentials ({stats.get('open', 0):,}). When a tool's description or input schema changes, it shows up on the radar.

## This week

- **{total:,}** server-days with tool changes across {len(week)} daily scans.

| Notable change | Count |
|---|---|
{rows}

{meaning}Most changes are routine (reworded descriptions, new features). Notable ones are changes that affect what your agent can do or who can call a server. Server-level details, with a dispute link for maintainers, are on [the radar]({SITE}/changes).

## What to do

- Pin the tools you trust: `pipx install mcpwatch-io && mcpwatch lock .mcp.json`, then run `mcpwatch check` in CI ([GitHub Action](https://github.com/marketplace/actions/mcpwatch-mcp-security-check)).
- Get an email when a server you depend on changes: [free beta]({SITE}/watch).

*This post is generated automatically from public data. Grades are automated signals, not audits.*
"""
    return {"article": {"title": f"This week in MCP security: {last}", "body_markdown": body, "published": True,
                        "tags": ["mcp", "security", "ai", "devops"], "canonical_url": f"{SITE}/changes"}}


def post_devto(article):
    key = os.environ.get("DEVTO_API_KEY")
    if not key:
        return "skipped (no credentials)"
    # https://developers.forem.com/api/v1#tag/articles/operation/createArticle
    http("POST", "https://dev.to/api/articles", article, {"api-key": key, "Accept": "application/vnd.forem.api-v1+json"})
    return "posted"


def changelog_entry(path, version):
    """The paragraph under '## <version>' in CHANGELOG.md, or None."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError:
        return None
    v = version.lstrip("v")
    parts = text.split(f"\n## {v}\n", 1)
    if len(parts) < 2:
        return None
    return parts[1].split("\n## ", 1)[0].strip() or None


def release_post(version, entry):
    """<= 300 chars: version, what's new, how to get it."""
    tail = f"\n\npipx install -U mcpwatch-io\n{SITE}"
    head = f"mcpwatch {version}: "
    room = 300 - len(head) - len(tail)
    body = entry if len(entry) <= room else entry[:room - 1].rsplit(" ", 1)[0] + "\u2026"
    return head + body + tail


def announce_release(version, changelog, dry_run=False):
    entry = changelog_entry(changelog, version)
    if not entry:
        print(f"announce: no CHANGELOG entry for {version}; nothing posted")
        return 0
    text = release_post(version, entry)
    if dry_run:
        print(text)
        return 0
    results = {}
    for name, fn in (("bluesky", lambda: post_bluesky(text)), ("mastodon", lambda: post_mastodon(text, f"mcpwatch-release-{version}"))):
        try:
            results[name] = fn()
        except urllib.error.HTTPError as e:
            results[name] = f"failed (HTTP {e.code})"
        except Exception as e:
            results[name] = f"failed ({type(e).__name__})"
    print("announce release:", ", ".join(f"{k}={v}" for k, v in results.items()))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", default="site")
    ap.add_argument("--state", default="hist", help="dir where per-day 'posted' markers are kept")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--release", help="post a release announcement for this tag (e.g. v0.3.1) instead of the radar")
    ap.add_argument("--changelog", default="CHANGELOG.md")
    a = ap.parse_args(argv)
    if a.release:
        return announce_release(a.release, a.changelog, a.dry_run)
    try:
        stats, changes = load(f"{a.site}/stats.json"), load(f"{a.site}/changes.json")
    except (OSError, ValueError) as e:
        print(f"announce: cannot read site data: {e}")
        return 0
    s = summary(stats, changes)
    if not s:
        print("announce: no radar data yet; nothing to post")
        return 0
    marker = os.path.join(a.state, f".announced-{s['date']}")
    if os.path.exists(marker):
        print(f"announce: already posted for {s['date']}")
        return 0
    text = short_post(s)
    is_monday = datetime.date.fromisoformat(s["date"]).weekday() == 0 if s["date"] else False
    article = weekly_article(stats, changes) if is_monday else None
    if a.dry_run:
        print(text)
        print(f"--- weekly article: {'yes' if article else 'no (not Monday)'}")
        return 0
    results = {}
    for name, fn in (("bluesky", lambda: post_bluesky(text)), ("mastodon", lambda: post_mastodon(text, f"mcpwatch-{s['date']}")),
                     ("devto", (lambda: post_devto(article)) if article else (lambda: "skipped (not Monday)"))):
        try:
            results[name] = fn()
        except urllib.error.HTTPError as e:
            results[name] = f"failed (HTTP {e.code})"  # never print bodies: they can echo credentials
        except Exception as e:
            results[name] = f"failed ({type(e).__name__})"
    print("announce:", ", ".join(f"{k}={v}" for k, v in results.items()))
    if any(v == "posted" for v in results.values()):
        os.makedirs(a.state, exist_ok=True)
        open(marker, "w").close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
