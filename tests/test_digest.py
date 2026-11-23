"""mcpwatch.digest: grouping, rendering and failure handling with a fake DB and mailer (no network)."""
import io, json, os, tempfile, unittest
from contextlib import redirect_stdout
from unittest import mock
from mcpwatch import digest

TODAY = "2026-11-22"
A = {"slug": "alpha-0a1b2c3d", "name": "io.example/alpha", "notable": [],
     "changes": [{"kind": "tool_added", "sev": "medium", "detail": "search"}]}
B = {"slug": "beta-0b1b2c3d", "name": "io.example/beta", "notable": ["endpoint stopped requiring credentials"],
     "changes": [{"kind": "auth_dropped", "sev": "high", "detail": "endpoint stopped requiring credentials"}]}
C = {"slug": "gamma-0c1b2c3d", "name": "io.example/gamma", "notable": [], "changes": [{"kind": "tool_removed", "sev": "medium", "detail": "x"}]}
CHANGES = [{"date": TODAY, "items": [B, A, C]}, {"date": "2026-11-21", "items": [A]}]


class FakeDB:
    def __init__(self, watches, confirmed=("ann@example.com", "bob@example.com"), plans=None, slack=None, members=None):
        self.watches, self.confirmed, self.queries, self.unsub, self.plans = watches, set(confirmed), [], {}, plans or {}
        self.slack, self.members = slack or {}, members or {}  # members: {member email: owner email}
        self.ids = {e: str(i) for i, e in enumerate(sorted({e for e, _ in watches}), 1)}

    def __call__(self, q, params):
        self.queries.append((q, params))
        if q.startswith("SELECT u.id, u.email"):
            wanted = set(json.loads(params[0]))
            assert "AS plan" in q and "past_due_since > now() - interval '7 days'" in q  # plan is enforced by status in SQL
            assert "UNION" in q and "m.team_owner = u.id" in q
            row = lambda e, s, plan_of: {"id": self.ids.get(e, e), "email": e, "slug": s, "plan": self.plans.get(plan_of, "free"),
                                         "slack_webhook": self.slack.get(e)}
            own = [row(e, s, e) for e, s in sorted(self.watches) if s in wanted and e in self.confirmed]
            team = [row(m, s, o) for m, o in self.members.items() for e, s in sorted(self.watches)
                    if e == o and s in wanted and m in self.confirmed and o in self.confirmed]
            return sorted(own + team, key=lambda r: (r["email"], r["slug"]))
        if q.startswith("INSERT INTO tokens") and "'unsub'" in q:
            self.unsub.setdefault(params[0], []).append(params[1])  # older tokens are kept, not replaced
            return []
        if q.startswith("DELETE FROM tokens WHERE expires_at < now()"):
            return []
        raise AssertionError("unexpected query " + q)


HOOK = "https://hooks.slack.com/services/T0ABC123/B0DEF456/abcdefghijKLMNOP1234"


class Team(unittest.TestCase):
    def test_members_get_the_owners_watchlist_at_the_owners_plan(self):
        db = FakeDB([("ann@example.com", A["slug"]), ("ann@example.com", B["slug"])],
                    confirmed=("ann@example.com", "mia@example.com", "zed@example.com"), plans={"ann@example.com": "team"},
                    members={"mia@example.com": "ann@example.com", "pat@example.com": "ann@example.com"})
        sent = []
        with redirect_stdout(io.StringIO()):
            digest.run(CHANGES, TODAY, db, lambda to, *a: sent.append(to) or True, billing=True)
        self.assertEqual(sent, ["ann@example.com", "mia@example.com"], "confirmed member gets it daily; unconfirmed invitee does not")


class Slack(unittest.TestCase):
    def test_posts_to_users_with_a_webhook_escaped_and_plan_gated(self):
        evil = dict(A, name="<!channel> & <https://x.example|click>")
        db = FakeDB([("ann@example.com", A["slug"]), ("bob@example.com", B["slug"])], slack={"ann@example.com": HOOK},
                    plans={"bob@example.com": "pro"})
        posts = []
        changes = [{"date": TODAY, "items": [evil, B]}]
        with redirect_stdout(io.StringIO()) as out:
            digest.run(changes, TODAY, db, lambda *a: True, slack=lambda u, t: posts.append((u, t)) or True)
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][0], HOOK)
        self.assertNotIn("<!channel>", posts[0][1])
        self.assertIn("&lt;!channel&gt; &amp;", posts[0][1])
        self.assertIn(f"<https://www.mcpwatch.io/s/{A['slug']}|", posts[0][1])
        self.assertNotIn("hooks.slack.com", out.getvalue(), "webhook URL never logged")
        # billing on: a free user's webhook is not used
        posts.clear()
        with redirect_stdout(io.StringIO()):
            digest.run(changes, TODAY, FakeDB([("ann@example.com", A["slug"])], slack={"ann@example.com": HOOK}), lambda *a: True,
                       billing=True, slack=lambda u, t: posts.append(u) or True)
        self.assertEqual(posts, [])

    def test_slack_failure_does_not_affect_email(self):
        db = FakeDB([("ann@example.com", A["slug"])], slack={"ann@example.com": HOOK})
        def boom(u, t):
            raise OSError(HOOK)
        with redirect_stdout(io.StringIO()) as out:
            res = digest.run([{"date": TODAY, "items": [A]}], TODAY, db, lambda *a: True, slack=boom)
        self.assertEqual(res, (1, 0))
        self.assertIn("slack 0 sent, 1 failed", out.getvalue())
        self.assertNotIn("hooks.slack.com", out.getvalue())

    def test_slack_post_refuses_other_hosts(self):
        self.assertFalse(digest.slack_post("https://evil.example.com/services/T0ABC123/B0DEF456/abcdefghijKLMNOP1234", "x"))
        self.assertFalse(digest.slack_post(None, "x"))


class Digest(unittest.TestCase):
    def run_digest(self, db, send=None, **kw):
        sent = []
        send = send or (lambda to, subject, text, key: sent.append((to, subject, text, key)) or True)
        with redirect_stdout(io.StringIO()) as out:
            res = digest.run(CHANGES, TODAY, db, send, **kw)
        return res, sent, out.getvalue()

    def test_groups_per_user_notable_first_and_skips_unwatched(self):
        db = FakeDB([("ann@example.com", A["slug"]), ("ann@example.com", B["slug"]), ("bob@example.com", C["slug"]),
                     ("cat@example.com", "unrelated-0d1b2c3d")])
        (n_sent, failed), sent, out = self.run_digest(db)
        self.assertEqual((n_sent, failed), (2, 0))
        self.assertEqual([s[0] for s in sent], ["ann@example.com", "bob@example.com"])
        self.assertEqual(sum(q.startswith("SELECT") for q, _ in db.queries), 1, "one join query")
        ann = sent[0][2]
        self.assertEqual(sent[0][1], f"mcpwatch: 2 watched servers changed on {TODAY}")
        self.assertLess(ann.index("io.example/beta"), ann.index("io.example/alpha"), "notable first")
        self.assertIn("Notable: endpoint stopped requiring credentials", ann)
        self.assertIn("https://www.mcpwatch.io/s/beta-0b1b2c3d", ann)
        self.assertIn("tool added: search (medium)", ann)
        self.assertNotIn("gamma", ann)
        self.assertIn("https://www.mcpwatch.io/watch", ann)
        self.assertNotIn("@example.com", out, "no addresses in logs")

    def test_unsubscribe_token_is_fresh_and_stored_hashed(self):
        import hashlib, re
        db = FakeDB([("ann@example.com", A["slug"])])
        _, sent, _ = self.run_digest(db)
        _, sent2, _ = self.run_digest(db)
        toks = [re.search(r"/api/unsubscribe\?t=([A-Za-z0-9_-]{43})", s[2]).group(1) for s in sent + sent2]
        self.assertNotEqual(toks[0], toks[1])
        self.assertEqual(db.unsub[db.ids["ann@example.com"]], [hashlib.sha256(t.encode()).hexdigest() for t in toks])
        self.assertTrue(any(q.startswith("DELETE FROM tokens WHERE expires_at") for q, _ in db.queries), "prunes expired tokens")
        self.assertNotIn("#m=", sent[0][2], "no manage token in digests")

    def test_nothing_sent_for_stale_or_empty_days_or_dry_run(self):
        db = FakeDB([("ann@example.com", A["slug"])])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(digest.run(CHANGES, "2026-11-23", db, None), (0, 0))  # baseline day: yesterday's file is first
            self.assertEqual(digest.run([{"date": TODAY, "items": []}], TODAY, db, None), (0, 0))
            self.assertEqual(digest.run([], TODAY, db, None), (0, 0))
        (n, _), sent, _ = self.run_digest(db, dry_run=True)
        self.assertEqual((n, sent, db.unsub), (1, [], {}))

    def test_send_failures_are_counted_not_raised(self):
        db = FakeDB([("ann@example.com", A["slug"]), ("bob@example.com", B["slug"])])

        def send(to, *a):
            if to.startswith("ann"):
                raise OSError("connection refused to ann@example.com")
            return False
        (n, failed), _, out = self.run_digest(db, send=send)
        self.assertEqual((n, failed), (0, 2))
        self.assertNotIn("@example.com", out)

    def test_main_never_fails_the_pipeline(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "changes.json")
            with open(p, "w") as fh:
                json.dump(CHANGES, fh)
            with mock.patch.dict(os.environ, {"DATABASE_URL": "", "RESEND_API_KEY": ""}), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(digest.main(["--changes", p]), 0)
            self.assertIn("skipping", out.getvalue())
            secret_url = "postgresql://u:hunter2@ep-x.example.neon.tech/db"
            with mock.patch.dict(os.environ, {"DATABASE_URL": secret_url, "RESEND_API_KEY": "re_x"}), \
                    mock.patch.object(digest, "datetime") as dt, \
                    mock.patch.object(digest, "neon_query", side_effect=RuntimeError(secret_url)), redirect_stdout(io.StringIO()) as out:
                dt.now.return_value.strftime.return_value = TODAY
                self.assertEqual(digest.main(["--changes", p]), 0)
            self.assertIn("failed", out.getvalue())
            self.assertNotIn("hunter2", out.getvalue())
            with mock.patch.dict(os.environ, {"DATABASE_URL": secret_url, "RESEND_API_KEY": "re_x"}), redirect_stdout(io.StringIO()):
                self.assertEqual(digest.main(["--changes", os.path.join(d, "missing.json")]), 0)



MONDAY = "2026-11-23"
OLD = {"slug": "old-0e1b2c3d", "name": "io.example/old", "notable": [], "changes": [{"kind": "tool_added", "sev": "medium", "detail": "z"}]}
WEEK = [{"date": MONDAY, "items": [A]}, {"date": "2026-11-20", "items": [B]}, {"date": "2026-11-17", "items": [C]},
        {"date": "2026-11-16", "items": [OLD]}]


class DigestPlans(unittest.TestCase):
    """BILLING_ENABLED: Pro/Team daily, Free weekly on Mondays (last 7 days); billing off: everyone daily."""

    def go(self, db, changes, today, billing):
        sent = []
        with redirect_stdout(io.StringIO()):
            digest.run(changes, today, db, lambda to, subject, text, key: sent.append((to, subject, text)) or True, billing=billing)
        return {to: (subject, text) for to, subject, text in sent}

    def db(self):
        w = [(e, s["slug"]) for e in ("free@example.com", "pro@example.com", "team@example.com") for s in (A, B, C, OLD)]
        return FakeDB(w, confirmed=("free@example.com", "pro@example.com", "team@example.com"),
                      plans={"pro@example.com": "pro", "team@example.com": "team"})

    def test_monday_free_gets_weekly_paid_get_daily(self):
        got = self.go(self.db(), WEEK, MONDAY, True)
        self.assertEqual(set(got), {"free@example.com", "pro@example.com", "team@example.com"})
        subject, text = got["free@example.com"]
        self.assertIn("weekly", subject)
        self.assertIn("2026-11-17 to 2026-11-23", subject)
        for it in (A, B, C):
            self.assertIn(it["name"], text)
        self.assertNotIn(OLD["name"], text, "older than 7 days")
        self.assertIn("io.example/beta (2026-11-20)", text)
        self.assertLess(text.index("io.example/beta"), text.index("io.example/alpha"), "notable first")
        for paid in ("pro@example.com", "team@example.com"):
            subject, text = got[paid]
            self.assertNotIn("weekly", subject)
            self.assertIn(A["name"], text)
            self.assertNotIn(B["name"], text, "daily = today only")

    def test_other_days_free_gets_nothing_paid_get_daily(self):
        changes = [{"date": TODAY, "items": [A]}] + WEEK[1:]
        got = self.go(self.db(), changes, TODAY, True)  # a Sunday
        self.assertEqual(set(got), {"pro@example.com", "team@example.com"})

    def test_monday_weekly_even_without_a_change_file_today(self):
        got = self.go(self.db(), WEEK[1:], MONDAY, True)
        self.assertEqual(set(got), {"free@example.com"})

    def test_billing_off_everyone_daily(self):
        got = self.go(self.db(), WEEK, MONDAY, False)
        self.assertEqual(set(got), {"free@example.com", "pro@example.com", "team@example.com"})
        self.assertTrue(all("weekly" not in s and B["name"] not in t for s, t in got.values()))

    def test_flag_parsing(self):
        for v, want in (("true", True), ("1", True), ("on", True), ("", False), ("false", False), ("0", False)):
            with mock.patch.dict(os.environ, {"BILLING_ENABLED": v}):
                self.assertEqual(digest.billing_enabled(), want, v)

if __name__ == "__main__":
    unittest.main()
