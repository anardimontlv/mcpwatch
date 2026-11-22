"""Runs tests/api_test.js (api/ handlers against an in-memory fake SQL layer and mailer) under unittest."""
import os, shutil, subprocess, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ApiHandlers(unittest.TestCase):
    def test_api_handlers(self):
        p = subprocess.run(["node", "--test", os.path.join(ROOT, "tests", "api_test.js")], capture_output=True, text=True,
                           env={k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "RESEND_API_KEY")})
        self.assertEqual(p.returncode, 0, p.stdout[-4000:] + p.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
