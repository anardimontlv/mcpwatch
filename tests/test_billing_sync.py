"""mcpwatch.billing_sync: reconciliation against Paddle with fakes (no network)."""
import io, os, unittest
from contextlib import redirect_stdout
from unittest import mock
from mcpwatch import billing_sync

PRICES = {"pro": "pri_pro", "team": "pri_team"}


def sub(sid, status="active", price="pri_pro", uid=None):
    return {"id": sid, "status": status, "customer_id": "ctm_" + sid, "items": [{"price": {"id": price}}],
            "custom_data": {"user_id": uid} if uid else None}


class FakeDB:
    def __init__(self, users):
        self.users, self.updates = {u["id"]: dict(u) for u in users}, []

    def __call__(self, q, p):
        if q.startswith("SELECT id, plan, plan_status"):
            return [dict(u) for u in self.users.values() if u.get("confirmed", True) and (u.get("paddle_subscription_id") or u["plan"] != "free")]
        if q.startswith("SELECT id FROM users WHERE id = $1 AND confirmed"):
            return [{"id": p[0]}] if p[0] in self.users and self.users[p[0]].get("confirmed", True) else []
        if q.startswith("UPDATE users SET plan = $2"):
            self.updates.append(p)
            self.users[p[0]].update(plan=p[1], plan_status=p[2], paddle_subscription_id=p[3])
            return []
        raise AssertionError(q)


class FakePaddle:
    def __init__(self, pages, single=None):
        self.pages, self.single, self.calls = pages, single or {}, []

    def __call__(self, path):
        self.calls.append(path)
        if path.startswith("/subscriptions?"):
            return self.pages[0]
        if path.startswith("https://"):  # a `next` link
            return self.pages[int(path.rsplit("=", 1)[1])]
        return {"data": self.single[path.rsplit("/", 1)[1]]}


class Reconcile(unittest.TestCase):
    def run_sync(self, db, paddle, **kw):
        with redirect_stdout(io.StringIO()) as out:
            n = billing_sync.reconcile(db, paddle, PRICES, **kw)
        return n, out.getvalue()

    def test_fixes_mismatched_plans_across_pages(self):
        db = FakeDB([
            {"id": "1", "plan": "free", "plan_status": None, "paddle_subscription_id": "sub_a"},     # missed activation
            {"id": "2", "plan": "pro", "plan_status": "active", "paddle_subscription_id": "sub_b"},  # upgraded to team, missed
            {"id": "3", "plan": "pro", "plan_status": "active", "paddle_subscription_id": "sub_c"},  # correct already
            {"id": "4", "plan": "pro", "plan_status": "active", "paddle_subscription_id": "sub_d"},  # canceled, not listed
            {"id": "5", "plan": "free", "plan_status": None, "paddle_subscription_id": None},       # never recorded; custom_data binds
        ])
        pages = [{"data": [sub("sub_a"), sub("sub_b", price="pri_team")],
                  "meta": {"pagination": {"has_more": True, "next": "https://sandbox-api.paddle.com/subscriptions?after=1"}}},
                 {"data": [sub("sub_c"), sub("sub_e", uid="5"), sub("sub_x", price="pri_other", uid="3")],
                  "meta": {"pagination": {"has_more": False, "next": None}}}]
        paddle = FakePaddle(pages, single={"sub_d": sub("sub_d", status="canceled")})
        n, out = self.run_sync(db, paddle)
        self.assertEqual(n, 4)
        self.assertEqual({k: (u["plan"], u["plan_status"], u["paddle_subscription_id"]) for k, u in db.users.items()}, {
            "1": ("pro", "active", "sub_a"), "2": ("team", "active", "sub_b"), "3": ("pro", "active", "sub_c"),
            "4": ("pro", "canceled", "sub_d"), "5": ("pro", "active", "sub_e")})
        self.assertIn("status=active,trialing,past_due,paused", paddle.calls[0])
        self.assertIn("/subscriptions/sub_d", paddle.calls)

    def test_dry_run_and_unknown_users_change_nothing(self):
        db = FakeDB([{"id": "1", "plan": "free", "plan_status": None, "paddle_subscription_id": "sub_a"},
                     {"id": "9", "plan": "free", "confirmed": False}])
        pages = [{"data": [sub("sub_a"), sub("sub_z", uid="9"), sub("sub_y", uid="77")], "meta": {"pagination": {"has_more": False}}}]
        n, _ = self.run_sync(db, FakePaddle(pages), dry_run=True)
        self.assertEqual((n, db.updates), (1, []))

    def test_main_skips_without_key_and_never_raises(self):
        with mock.patch.dict(os.environ, {"PADDLE_API_KEY": "", "DATABASE_URL": "x"}), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(billing_sync.main([]), 0)
        self.assertIn("skipping", out.getvalue())
        with mock.patch.dict(os.environ, {"PADDLE_API_KEY": "pdl_secret_key", "DATABASE_URL": "postgresql://u:hunter2@h/db"}), \
                mock.patch.object(billing_sync, "neon_query", side_effect=RuntimeError("postgresql://u:hunter2@h/db pdl_secret_key")), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(billing_sync.main([]), 0)
        self.assertNotIn("hunter2", out.getvalue())
        self.assertNotIn("pdl_secret_key", out.getvalue())


if __name__ == "__main__":
    unittest.main()
