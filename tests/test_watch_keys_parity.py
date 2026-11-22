"""web/scan.js configKeys/pkgKey/urlKey (used by /watch) must give exactly what mcpwatch/watch.py gives."""
import json, os, shutil, subprocess, unittest
from mcpwatch.scan import servers_of
from mcpwatch.watch import config_keys, pkg_key, url_key

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = r"""
const s = require(process.argv[1]); let d = "";
process.stdin.on("data", (c) => (d += c)).on("end", () => {
  const {configs, pkgs, urls} = JSON.parse(d);
  const keys = (cfg) => { try { return s.configKeys(cfg); } catch (e) { return "error"; } };
  process.stdout.write(JSON.stringify({
    configs: configs.map((t) => [...s.serversOf(s.parseJSON(t))].filter(([, c]) => s.isDict(c)).map(([n, c]) => [n, keys(c)])),
    pkgs: pkgs.map(([k, i]) => s.pkgKey(k, i)),
    urls: urls.map((u) => s.urlKey(u)),
  }));
});
"""


def py_keys(cfg):
    try:
        return config_keys(cfg)
    except ValueError:  # shlex.split on an unclosed quote
        return "error"


def cfg(**servers):
    return json.dumps({"mcpServers": servers}, ensure_ascii=False)


CONFIGS = [
    cfg(a={"command": "npx", "args": ["-y", "@Scope/Pkg@1.2.3"]}, b={"command": "npx", "args": ["pkg@latest"]},
        c={"command": "/usr/local/bin/npx.cmd", "args": ["@scope/pkg"]}, d={"command": "C:\\tools\\bunx.exe", "args": ["Pkg"]},
        e={"command": "pnpx", "args": ["-y"]}, f={"command": "npx", "args": "-y 'my pkg' x"}, g={"command": "npx", "args": "-y 'unclosed"},
        h={"command": "npx", "args": [1, 2.5, True, None]}, i={"command": 5, "args": ["x"]}),
    cfg(a={"command": "uvx", "args": ["mcp_server_git==0.6.2"]}, b={"command": "uvx", "args": ["--from", "x", "Mcp-Server[extra]"]},
        c={"command": "pipx", "args": ["run", "mcp-server-git"]}, d={"command": "pipx", "args": ["run", "--spec", "x", "y"]},
        e={"command": "pipx", "args": ["run"]}, f={"command": "uvx", "args": ["pkg@1.0"]}, g={"command": "uvx", "args": ["a~=1", "b"]}),
    cfg(a={"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/Org/Img:1.2"]}, b={"command": "docker", "args": ["run", "img"]},
        c={"command": "podman", "args": ["run", "-v", "/a:/b", "reg:5000/x/y@sha256:abc"]}, d={"command": "docker", "args": ["run", "a/b", "c/d:2"]},
        e={"command": "docker", "args": []}, f={"command": "docker.exe", "args": ["run", "localhost:5000/img"]}),
    cfg(a={"command": "cmd", "args": ["/c", "npx", "-y", "@scope/pkg"]}, b={"command": "C:\\Windows\\System32\\cmd.exe", "args": ["/C", "uvx", "p"]},
        c={"command": "cmd", "args": ["/c"]}, d={"command": "node", "args": ["server.js"]}, e={}),
    cfg(a={"url": "https://Example.COM/mcp/"}, b={"serverUrl": "HTTP://h:8080/p//"}, c={"url": "", "serverUrl": "https://x.example/y"},
        d={"url": 0, "serverUrl": "https://z.example"}, e={"url": "not a url"}, f={"url": "http://[::1/x"}, g={"url": " \thttps://h.example/a?q=1#f "},
        h={"url": "https://user:pw@H.example:443/p"}, i={"url": 12}, j={"url": "http://[fe80::1%25eth0]/"}, k={"url": "https://exa\u2100mple.com/"},
        l={"url": "https://h.example", "command": "npx", "args": ["x"]}),
    json.dumps({"servers": {"vs": {"type": "stdio", "command": "npx", "args": ["pkg"]}}}),
    json.dumps({"mcp": {"servers": {"m": {"url": "https://m.example/x"}}, "x": 1}}),
    json.dumps({"mcpServers": {"s": "str", "n": None, "l": [1]}}),
]
PKGS = [["npm", "@Scope/Pkg@1"], ["npm", " pkg "], ["npm", "a@b@c"], ["npm", "@"], ["pypi", "Foo_Bar>=1"], ["pypi", "x[y]"], ["pypi", "a@https://x"],
        ["oci", "Docker.io/Lib/Img:Tag"], ["oci", "reg:5000/img"], ["oci", "img@sha256:00"], ["oci", "img"], ["nuget", "x"]]
URLS = ["https://A.example/b/", "", "x", "https://", "ftp://h/p", "https://h.example?x", "//h.example/p", "https://[::1]:99/"]


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class WatchKeysParity(unittest.TestCase):
    def test_js_matches_python(self):
        proc = subprocess.run(["node", "-e", NODE, os.path.join(ROOT, "web", "scan.js")],
                              input=json.dumps({"configs": CONFIGS, "pkgs": PKGS, "urls": URLS}),
                              capture_output=True, text=True, encoding="utf-8", check=True)
        js = json.loads(proc.stdout)
        for text, got in zip(CONFIGS, js["configs"]):
            with self.subTest(config=text[:100]):
                want = [[n, py_keys(c)] for n, c in servers_of(json.loads(text)).items() if isinstance(c, dict)]
                self.assertEqual(got, want)
        self.assertEqual(js["pkgs"], [pkg_key(k, i) for k, i in PKGS])
        self.assertEqual(js["urls"], [url_key(u) for u in URLS])

    def test_corpus_covers_every_kind(self):
        keys = {k.split(":")[0] for t in CONFIGS for c in servers_of(json.loads(t)).values() if isinstance(c, dict)
                for k in (py_keys(c) if py_keys(c) != "error" else [])}
        self.assertEqual(keys, {"npm", "pypi", "oci", "url"})


if __name__ == "__main__":
    unittest.main()
