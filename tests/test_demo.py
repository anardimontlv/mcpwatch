"""The rug-pull demo in examples/ must keep working: it is the public proof of what check and guard do."""
import os, subprocess, sys, unittest

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "rug-pull-demo", "run_demo.py")


class Demo(unittest.TestCase):
    def test_demo_passes(self):
        p = subprocess.run([sys.executable, DEMO], capture_output=True, text=True, timeout=180)
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("PASS: the change was caught in CI and blocked at runtime.", p.stdout)
