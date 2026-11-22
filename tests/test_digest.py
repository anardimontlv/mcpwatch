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
    def __init__(self, watches, confirmed=("ann@example.com", "bob@example.com")):
        self.watches, self.confirmed, self.queries, self.unsub = watches, set(confirmed), [], {}
        self.ids = {e: str(i) for i, e in enumerate(sorted({e for e, _ in watches}), 1)}

    def __call__(self, q, params):
        self.queries.append((q, params))
        if q.startswith("SELECT u.id, u.email"):
            wanted = set(json.loads(params[0]))
            return [{"id": self.ids[e], "email": e, "slug": s} for e, s in sorted(self.watches) if s in wanted and e in self.confirmed]
        if q.startswith("WITH ins AS (INSERT INTO tokens") and "'unsub'" in q:
            self.unsub.setdefault(params[0], []).append(params[1])  # older tokens are kept, not replaced
            return []
        if q.startswith("DELETE FROM tokens WHERE expires_at < now()"):
            return []
        raise AssertionError("unexpected query " + q)


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


if __name__ == "__main__":
    unittest.main()
