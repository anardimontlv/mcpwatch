"""Static assets for the in-browser config scanner (/scan)."""
import os, shutil

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


def write_scan_assets(out):
    shutil.copyfile(os.path.join(WEB, "scan.js"), os.path.join(out, "scan.js"))
