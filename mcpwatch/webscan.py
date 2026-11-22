"""Static assets for the in-browser config scanner (/scan) and the watchlist page (/watch)."""
import os, shutil

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


def write_scan_assets(out):
    for f in ("scan.js", "watch.js"):
        shutil.copyfile(os.path.join(WEB, f), os.path.join(out, f))
