import io, json, os, re, tempfile, unittest
from contextlib import redirect_stdout
from unittest import mock
from mcpwatch import announce as a

STATS = {"servers": 69322, "open": 27865}
def changes(date="2026-11-23", names=("x.y/one", "x.y/two")):
    items = [{"name": n, "slug": "s", "changes": [{"kind": "auth_dropped"}], "notable": ["endpoint stopped requiring credentials"]} for n in names]
    items.append({"name": "z/routine", "slug": "r", "changes": [{"kind": "tool_changed"}], "notable": []})
    return [{"date": date, "items": items}]


class AnnounceTest(unittest.TestCase):
    def test_post_never_names_servers_and_fits(self):
        t = a.short_post(a.summary(STATS, changes()))
        self.assertLessEqual(len(t), 300)
        for n in ("x.y/one", "x.y/two", "z/routine"):
            self.assertNotIn(n, t)
        self.assertIn("2 stopped requiring auth", t)
        self.assertIn("automated", t)

    def test_long_reason_list_is_truncated_to_fit(self):
        s = {"date": "2026-11-23", "changed": 123456, "notable": 99999, "servers": 999999, "open": 1,
             "reasons": {k: 99999 for k, _ in a.LABELS}}
        self.assertLessEqual(len(a.short_post(s)), 300)

    def test_skips_without_credentials_and_posts_once_per_day(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(f"{d}/site")
            json.dump(STATS, open(f"{d}/site/stats.json", "w")); json.dump(changes(), open(f"{d}/site/changes.json", "w"))
            env = {k: "" for k in ("BLUESKY_HANDLE", "BLUESKY_APP_PASSWORD", "MASTODON_TOKEN", "MASTODON_INSTANCE", "DEVTO_API_KEY")}
            with mock.patch.dict(os.environ, env), mock.patch.object(a, "http") as h:
                self.assertEqual(a.main(["--site", f"{d}/site", "--state", f"{d}/st"]), 0)
                h.assert_not_called()  # nothing configured: nothing sent, no marker
            self.assertFalse(os.path.exists(f"{d}/st/.announced-2026-11-23"))
            with mock.patch.dict(os.environ, {**env, "MASTODON_INSTANCE": "https://m.example", "MASTODON_TOKEN": "t"}), \
                 mock.patch.object(a, "http", return_value={}) as h:
                a.main(["--site", f"{d}/site", "--state", f"{d}/st"])
                a.main(["--site", f"{d}/site", "--state", f"{d}/st"])
                self.assertEqual(h.call_count, 1)  # second run sees the marker

    def test_failure_on_one_channel_does_not_raise(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(f"{d}/site")
            json.dump(STATS, open(f"{d}/site/stats.json", "w")); json.dump(changes(), open(f"{d}/site/changes.json", "w"))
            def boom(*x, **k):
                raise urllib.error.HTTPError("u", 401, "no", {}, None)
            with mock.patch.dict(os.environ, {"MASTODON_INSTANCE": "https://m.example", "MASTODON_TOKEN": "t"}), mock.patch.object(a, "http", boom):
                self.assertEqual(a.main(["--site", f"{d}/site", "--state", f"{d}/st"]), 0)

    def test_weekly_article_has_no_server_names(self):
        art = a.weekly_article(STATS, changes())["article"]["body_markdown"]
        self.assertNotIn("x.y/one", art)


class Release(unittest.TestCase):
    def test_release_post_from_changelog(self):
        from mcpwatch import announce
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "CHANGELOG.md")
            open(p, "w").write("# Changelog\n\n## 0.3.1\nShort note about pins.\n\n## 0.3.0\nOlder.\n")
            self.assertEqual(announce.changelog_entry(p, "v0.3.1"), "Short note about pins.")
            self.assertIsNone(announce.changelog_entry(p, "v9.9.9"))
            text = announce.release_post("v0.3.1", "x " * 400)
            self.assertLessEqual(len(text), 300)
            self.assertTrue(text.startswith("mcpwatch v0.3.1: ") and text.endswith("https://www.mcpwatch.io"))
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(announce.main(["--release", "v9.9.9", "--changelog", p]), 0)
            self.assertIn("no CHANGELOG entry", out.getvalue())

    def test_every_url_is_clickable_on_bluesky(self):
        from mcpwatch import announce
        t = "café demo: https://github.com/a/b/tree/main/x and https://www.mcpwatch.io."
        f = announce.link_facets(t)
        self.assertEqual([x["features"][0]["uri"] for x in f], ["https://github.com/a/b/tree/main/x", "https://www.mcpwatch.io"])
        b = t.encode()
        self.assertEqual(b[f[0]["index"]["byteStart"]:f[0]["index"]["byteEnd"]].decode(), "https://github.com/a/b/tree/main/x")

    def test_real_changelog_has_an_entry_for_the_current_version(self):
        from mcpwatch import announce
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        v = re.search(r'^version = "([^"]+)"', open(os.path.join(root, "pyproject.toml")).read(), re.M).group(1)  # no tomllib on 3.10
        self.assertIsNotNone(announce.changelog_entry(os.path.join(root, "CHANGELOG.md"), v), "add a CHANGELOG.md entry before tagging")
