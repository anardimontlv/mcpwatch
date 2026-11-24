/* mcpwatch in-browser config scanner. A line-for-line port of mcpwatch/scan.py
 * (scan_server, scan_tools, servers_of, score) that runs entirely in the page:
 * nothing you paste is sent anywhere. tests/test_webscan_parity.py keeps it in
 * lockstep with the Python CLI, so change both together.
 *
 * Parsed JSON keeps Python's types: objects are Maps (insertion order, like dict),
 * ints are BigInt, floats are Number, so str()/json.dumps()/truthiness match. */
(function (root) {
  "use strict";

  const SEV_WEIGHT = { critical: 40, high: 20, medium: 8, low: 3 };
  const SEV_ORDER = ["low", "medium", "high", "critical"];

  // Python's re/str semantics expressed as JS regex pieces (all regexes use the u flag).
  const WS = "\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"; // str.isspace / re \s
  const S = "[" + WS + "]";
  const W = "\\p{L}\\p{N}_"; // re \w (str.isalnum() or "_")
  const NOT_W = "(?![" + W + "])"; // \b after a word character
  const END = "(?=\\n?$)"; // re $ without MULTILINE: end, or before a final newline
  const rx = (src, flags) => new RegExp(src, "u" + (flags || ""));
  // re.I folds these to "i"; JS case folding does not. Same length, so match indices still line up.
  const fold = (s) => s.replace(/[\u0130\u0131]/g, "i");

  const SECRET_PATTERNS = [
    "sk-[A-Za-z0-9_\\-]{20,}", "sk-ant-[A-Za-z0-9_\\-]{20,}", "gh[pousr]_[A-Za-z0-9]{30,}",
    "github_pat_[A-Za-z0-9_]{30,}", "AKIA[0-9A-Z]{16}", "xox[abpr]-[A-Za-z0-9\\-]{10,}",
    "AIza[0-9A-Za-z_\\-]{35}", "glpat-[A-Za-z0-9_\\-]{20}", "-----BEGIN [A-Z ]*PRIVATE KEY-----",
  ].map((p) => rx(p));
  const hasSecretPattern = (s) => SECRET_PATTERNS.some((p) => p.test(s));
  const SECRET_KEY_NAME = rx("(KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH)", "i");
  const NOT_SECRET_NAME = rx("(_FILE|_PATH|_DIR|_MODE|_TYPE|_METHOD|_URL|_ENDPOINT|_HEADER|_NAME|_ID|_REGION|^MAX_|_LIMIT|_TOKENS)" + END, "i");
  const SECRET_PARAM = rx("^(?:api[_-]?key|key|token|access[_-]?token|auth[_-]?token|secret|client[_-]?secret|password|passwd|pwd|auth|sig|signature)$", "i");
  const ENV_REF_SRC = "\\$\\{?[A-Za-z_][A-Za-z0-9_:\\-]*\\}?|\\$\\{input:[^}]*\\}|\\{\\{[^}]*\\}\\}|\\{[A-Za-z_][" + W + ".\\-]*\\}|<[A-Za-z_][" + W + ".\\-]*>";
  const ENV_REF = rx(ENV_REF_SRC);
  const ENV_REF_FULL = rx("^(?:" + ENV_REF_SRC + ")$");
  const RUNNERS = new Set(["npx", "bunx", "pnpx", "uvx", "pipx", "dlx"]);
  const BROAD_PATH = rx("^(/|~|~/|\\$HOME|\\$\\{HOME\\}|%USERPROFILE%|[A-Za-z]:[\\\\/]?|/Users/[^/]+|/home/[^/]+|/root|[A-Za-z]:[\\\\/]Users[\\\\/][^\\\\/]+)[\\\\/]?" + END);
  const UNSAFE_FLAGS = rx("^--?(allow-all|allow-all-tools|dangerously-skip-permissions|no-sandbox|disable-sandbox|unsafe|yolo|trust-all)(=[^\\n]*)?" + END, "i");
  const INJECTION = rx(
    `(?<![("'\u201c\u2018])(ignore|disregard|forget)${S}+(all${S}+|any${S}+)?(the${S}+)?(previous|prior|above|earlier)${S}+(instructions|prompts|rules)` +
    `|do${S}+not${S}+(tell|inform|mention|reveal)[^.]{0,40}users?(?!${S}+(that${S}+)?(a|an|the|our)${S})` +
    `|<${S}*important${S}*>|before${S}+using${S}+any${S}+other${S}+tool` +
    `|instead${S}+of${S}+the${S}+user|send${S}+(it|them|the${S}+[a-z ]+)${S}+to${S}+https?://(?![^${WS})]*(sign-?up|register|sign-?in|login))` +
    `|(read|cat|open|include|attach|upload)${S}+[^.]{0,30}(\\.ssh/|id_(rsa|ed25519|ecdsa)${NOT_W})`, "i");
  const DANGEROUS_TOKENS = new Set(["exec", "execute", "shell", "bash", "sh", "zsh", "powershell", "sudo", "eval", "delete", "remove", "rm", "drop", "kill"]);
  const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);
  const CONN_STRING = rx(`^[a-z][a-z0-9+.\\-]*://[^/@${WS}:]+:[^/@${WS}]+@`, "i");
  const AUTH_SCHEME = rx(`^(bearer|basic|token)${S}+([^\\n]+)${END}`, "id");
  const FLAG_VALUE = rx(`^--?[${W}\\-]*(key|token|secret|password|auth)[${W}\\-]*=([^\\n]+)${END}`, "id");
  const CURL_PIPE = rx(`(curl|wget)[^|]*\\|${S}*(ba|z)?sh`);
  const CAP_ADD = rx(`--cap-add[ =](SYS_ADMIN|ALL)${NOT_W}`, "i");
  const ROOT_MOUNT = rx(`(-v|--volume)[ =]/:|(src|source)=/(,|${S}|${END})`);
  const HOST_NS = rx(`--(network|net|pid|ipc)[ =]host${NOT_W}`);
  const MOUNTS = rx(`(?:-v|--volume)[ =]([^:${WS}]+):|(?:src|source)=([^,${WS}]+)`, "g");
  // str.isdigit(): Nd plus the digit-valued No characters Python also accepts
  const PY_DIGITS = rx("^[\\p{Nd}\\u{b2}-\\u{b3}\\u{b9}\\u{1369}-\\u{1371}\\u{19da}\\u{2070}\\u{2074}-\\u{2079}\\u{2080}-\\u{2089}\\u{2460}-\\u{2468}\\u{2474}-\\u{247c}\\u{2488}-\\u{2490}\\u{24ea}\\u{24f5}-\\u{24fd}\\u{24ff}\\u{2776}-\\u{277e}\\u{2780}-\\u{2788}\\u{278a}-\\u{2792}\\u{10a40}-\\u{10a43}\\u{10e60}-\\u{10e68}\\u{11052}-\\u{1105a}\\u{1f100}-\\u{1f10a}]+$");
  const STRIP = rx(`^${S}+|${S}+$`, "g");
  const HIDDEN = rx("[\\p{Cf}\\p{Co}\\u{E0000}-\\u{E007F}]");
  const NOT_PRINTABLE = rx("^[\\p{Cc}\\p{Cf}\\p{Cs}\\p{Co}\\p{Cn}\\p{Zl}\\p{Zp}\\p{Zs}]$");

  // ---- Python builtins -------------------------------------------------------
  const cps = (s) => Array.from(s); // Python indexes strings by code point
  const isDict = (v) => v instanceof Map;
  const asDict = (v) => (isDict(v) ? v : new Map());
  const get = (m, k, dflt) => (m.has(k) ? m.get(k) : dflt);
  function truthy(v) {
    if (v === null || v === undefined || v === false) return false;
    if (typeof v === "string") return v.length > 0;
    if (typeof v === "bigint") return v !== 0n;
    if (typeof v === "number") return v !== 0; // NaN is truthy in Python
    if (Array.isArray(v)) return v.length > 0;
    if (isDict(v)) return v.size > 0;
    return true;
  }
  function floatRepr(x) {
    if (Number.isNaN(x)) return "nan";
    if (x === Infinity) return "inf";
    if (x === -Infinity) return "-inf";
    if (x === 0) return Object.is(x, -0) ? "-0.0" : "0.0";
    const sign = x < 0 ? "-" : "";
    const [mant, e] = Math.abs(x).toExponential().split("e"); // shortest round-trip digits, like repr()
    const digits = mant.replace(".", "");
    const exp = Number(e);
    if (exp < -4 || exp >= 16) {
      return sign + digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "") + "e" + (exp < 0 ? "-" : "+") + String(Math.abs(exp)).padStart(2, "0");
    }
    const dp = exp + 1;
    if (dp <= 0) return sign + "0." + "0".repeat(-dp) + digits;
    if (dp >= digits.length) return sign + digits + "0".repeat(dp - digits.length) + ".0";
    return sign + digits.slice(0, dp) + "." + digits.slice(dp);
  }
  const hex = (n, w) => n.toString(16).padStart(w, "0");
  function strRepr(s) {
    const q = s.includes("'") && !s.includes('"') ? '"' : "'";
    let out = q;
    for (const c of s) {
      const n = c.codePointAt(0);
      if (c === q || c === "\\") out += "\\" + c;
      else if (c === "\t") out += "\\t";
      else if (c === "\n") out += "\\n";
      else if (c === "\r") out += "\\r";
      else if (n < 0x20 || n === 0x7f) out += "\\x" + hex(n, 2);
      else if (n < 0x7f || !NOT_PRINTABLE.test(c)) out += c;
      else out += n <= 0xff ? "\\x" + hex(n, 2) : n <= 0xffff ? "\\u" + hex(n, 4) : "\\U" + hex(n, 8);
    }
    return out + q;
  }
  function pyRepr(v) {
    if (v === null || v === undefined) return "None";
    if (v === true) return "True";
    if (v === false) return "False";
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") return floatRepr(v);
    if (typeof v === "string") return strRepr(v);
    if (Array.isArray(v)) return "[" + v.map(pyRepr).join(", ") + "]";
    return "{" + Array.from(v, ([k, x]) => pyRepr(k) + ": " + pyRepr(x)).join(", ") + "}";
  }
  const pyStr = (v) => (typeof v === "string" ? v : pyRepr(v));
  const JSON_ESC = { "\\": "\\\\", '"': '\\"', "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };
  const dumpStr = (s) => '"' + s.replace(/[\x00-\x1f\\"]/g, (c) => JSON_ESC[c] || "\\u" + hex(c.charCodeAt(0), 4)) + '"';
  function pyDumps(v) { // json.dumps(v, ensure_ascii=False)
    if (v === null || v === undefined) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number") return Number.isNaN(v) ? "NaN" : v === Infinity ? "Infinity" : v === -Infinity ? "-Infinity" : floatRepr(v);
    if (typeof v === "string") return dumpStr(v);
    if (Array.isArray(v)) return "[" + v.map(pyDumps).join(", ") + "]";
    return "{" + Array.from(v, ([k, x]) => dumpStr(k) + ": " + pyDumps(x)).join(", ") + "}";
  }

  // json.loads: same accepted syntax (incl. NaN/Infinity), duplicate keys keep first position and last value.
  function parseJSON(s) {
    let i = 0;
    const fail = (msg, pos) => {
      if (pos === undefined) pos = i;
      const before = s.slice(0, pos);
      const err = new SyntaxError(msg);
      err.line = before.split("\n").length;
      err.col = pos - before.lastIndexOf("\n");
      throw err;
    };
    const ws = () => { while (i < s.length && " \t\n\r".includes(s[i])) i++; };
    const NUM = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?/y;
    function str() {
      const start = i++;
      let out = "";
      for (;;) {
        if (i >= s.length) fail("Unterminated string starting at", start);
        const c = s[i];
        if (c === '"') { i++; return out; }
        if (c < " ") fail("Invalid control character at");
        if (c !== "\\") { out += c; i++; continue; }
        const e = s[i + 1];
        if (e === undefined) fail("Unterminated string starting at", start);
        if (e !== "u") {
          const m = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
          if (m === undefined) fail("Invalid \\escape");
          out += m; i += 2; continue;
        }
        const u4 = (at) => (/^[0-9a-fA-F]{4}$/.test(s.slice(at, at + 4)) ? parseInt(s.slice(at, at + 4), 16) : -1);
        const u = u4(i + 2);
        if (u < 0) fail("Invalid \\uXXXX escape", i + 1);
        i += 6;
        if (u >= 0xd800 && u <= 0xdbff && s[i] === "\\" && s[i + 1] === "u") {
          const lo = u4(i + 2);
          if (lo >= 0xdc00 && lo <= 0xdfff) { out += String.fromCharCode(u, lo); i += 6; continue; }
        }
        out += String.fromCharCode(u);
      }
    }
    function value() {
      const c = s[i];
      if (c === '"') return str();
      if (c === "{") {
        const obj = new Map();
        i++; ws();
        if (s[i] === "}") { i++; return obj; }
        for (;;) {
          if (s[i] !== '"') fail("Expecting property name enclosed in double quotes");
          const k = str();
          ws();
          if (s[i] !== ":") fail("Expecting ':' delimiter");
          i++; ws();
          obj.set(k, value());
          ws();
          if (s[i] === "}") { i++; return obj; }
          if (s[i] !== ",") fail("Expecting ',' delimiter");
          i++; ws();
          if (s[i] === "}") fail("Illegal trailing comma before end of object");
        }
      }
      if (c === "[") {
        const arr = [];
        i++; ws();
        if (s[i] === "]") { i++; return arr; }
        for (;;) {
          arr.push(value());
          ws();
          if (s[i] === "]") { i++; return arr; }
          if (s[i] !== ",") fail("Expecting ',' delimiter");
          i++; ws();
          if (s[i] === "]") fail("Illegal trailing comma before end of array");
        }
      }
      for (const [lit, v] of [["null", null], ["true", true], ["false", false], ["NaN", NaN], ["Infinity", Infinity], ["-Infinity", -Infinity]]) {
        if (s.startsWith(lit, i)) { i += lit.length; return v; }
      }
      NUM.lastIndex = i;
      const m = NUM.exec(s);
      if (m) { i += m[0].length; return m[1] || m[2] ? Number(m[0]) : BigInt(m[0]); }
      return fail("Expecting value");
    }
    if (s.charCodeAt(0) === 0xfeff) fail("Unexpected UTF-8 BOM", 0);
    ws();
    const v = value();
    ws();
    if (i !== s.length) fail("Extra data");
    return v;
  }

  // shlex.split (POSIX mode, no comments). Throws on an unclosed quote or trailing escape.
  function shlexSplit(s) {
    const out = [];
    let tok = "", inTok = false, quote = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (quote === "'") { if (c === "'") quote = null; else tok += c; continue; }
      if (c === "\\") {
        if (i + 1 >= s.length) throw new Error("No escaped character");
        const n = s[++i];
        tok += quote === '"' && n !== '"' && n !== "\\" ? "\\" + n : n;
        inTok = true;
        continue;
      }
      if (quote === '"') { if (c === '"') quote = null; else tok += c; continue; }
      if (" \t\r\n".includes(c)) { if (inTok) out.push(tok); tok = ""; inTok = false; }
      else if (c === "'" || c === '"') { quote = c; inTok = true; }
      else { tok += c; inTok = true; }
    }
    if (quote) throw new Error("No closing quotation");
    if (inTok) out.push(tok);
    return out;
  }
  const pySplit = (s) => s.split(rx(S + "+")).filter(Boolean); // str.split()

  // ---- urllib.parse ----------------------------------------------------------
  const ValueErr = (m) => new Error(m);
  const partition = (s, sep) => { const i = s.indexOf(sep); return i < 0 ? [s, "", ""] : [s.slice(0, i), sep, s.slice(i + sep.length)]; };
  const rpartition = (s, sep) => { const i = s.lastIndexOf(sep); return i < 0 ? ["", "", s] : [s.slice(0, i), sep, s.slice(i + sep.length)]; };
  const isAscii = (s) => /^[\x00-\x7f]*$/.test(s);

  function isIPv4(s) {
    const o = s.split(".");
    return o.length === 4 && o.every((x) => /^[0-9]{1,3}$/.test(x) && !(x !== "0" && x[0] === "0") && Number(x) <= 255);
  }
  function isIPv6(s) { // ipaddress.IPv6Address, with optional %scope
    if (s.includes("/")) return false;
    const [addr, pct, scope] = partition(s, "%");
    if (pct && (!scope || scope.includes("%"))) return false;
    if (!addr || cps(addr).length > 45) return false;
    const parts = addr.split(":");
    if (parts.length < 3) return false;
    if (parts[parts.length - 1].includes(".")) {
      if (!isIPv4(parts.pop())) return false;
      parts.push("0", "0");
    }
    if (parts.length > 9) return false;
    let skip = -1;
    for (let i = 1; i < parts.length - 1; i++) {
      if (!parts[i]) { if (skip >= 0) return false; skip = i; }
    }
    let hi, lo;
    if (skip >= 0) {
      hi = skip; lo = parts.length - skip - 1;
      if (!parts[0] && --hi) return false;
      if (!parts[parts.length - 1] && --lo) return false;
      if (8 - (hi + lo) < 1) return false;
    } else {
      if (parts.length !== 8 || !parts[0] || !parts[7]) return false;
      hi = 8; lo = 0;
    }
    const hextet = (p) => /^[0-9a-fA-F]{1,4}$/.test(p);
    return parts.slice(0, hi).every(hextet) && parts.slice(parts.length - lo).every(hextet);
  }
  function checkBracketedNetloc(netloc) {
    const hostPort = rpartition(netloc, "@")[2];
    const [before, br, bracketed] = partition(hostPort, "[");
    let host;
    if (br) {
      if (before) throw ValueErr("Invalid IPv6 URL");
      const [h, , port] = partition(bracketed, "]");
      if (port && !port.startsWith(":")) throw ValueErr("Invalid IPv6 URL");
      host = h;
    } else {
      host = partition(hostPort, ":")[0];
    }
    if (/^[vV]/.test(host)) {
      if (!/^[vV][a-fA-F0-9]+\.[^\n]+$/.test(host)) throw ValueErr("IPvFuture address is invalid");
    } else if (!isIPv6(host)) {
      throw ValueErr("invalid bracketed host");
    }
  }
  function urlsplit(url) {
    url = url.replace(/^[\x00-\x20]+/, "").replace(/[\t\r\n]/g, "");
    let scheme = "", netloc = "", query = "";
    const i = url.indexOf(":");
    if (i > 0 && /^[A-Za-z][A-Za-z0-9+\-.]*$/.test(url.slice(0, i))) {
      scheme = url.slice(0, i).toLowerCase();
      url = url.slice(i + 1);
    }
    if (url.slice(0, 2) === "//") {
      let delim = url.length;
      for (const c of "/?#") { const w = url.indexOf(c, 2); if (w >= 0) delim = Math.min(delim, w); }
      netloc = url.slice(2, delim);
      url = url.slice(delim);
      const open = netloc.includes("["), close = netloc.includes("]");
      if (open !== close) throw ValueErr("Invalid IPv6 URL");
      if (open) checkBracketedNetloc(netloc);
    }
    url = partition(url, "#")[0];
    if (url.includes("?")) [url, , query] = partition(url, "?");
    if (netloc && !isAscii(netloc)) { // _checknetloc
      const n = netloc.replace(/[@:#?]/g, "");
      const n2 = n.normalize("NFKC");
      if (n !== n2 && /[/?#@:]/.test(n2)) throw ValueErr("netloc contains invalid characters under NFKC normalization");
    }
    return { scheme, netloc, path: url, query };
  }
  function hostinfo(netloc) {
    const hi = rpartition(netloc, "@")[2];
    const [, br, bracketed] = partition(hi, "[");
    let host, port;
    if (br) { let rest; [host, , rest] = partition(bracketed, "]"); port = partition(rest, ":")[2]; }
    else [host, , port] = partition(hi, ":");
    return [host, port || null];
  }
  function hostname(p) {
    const h = hostinfo(p.netloc)[0];
    if (!h) return null;
    const [a, pct, zone] = partition(h, "%");
    return a.toLowerCase() + pct + zone;
  }
  function portOf(p) {
    const port = hostinfo(p.netloc)[1];
    if (port === null) return null;
    if (!/^[0-9]+$/.test(port)) throw ValueErr("Port could not be cast to integer value");
    const n = Number(port);
    if (n > 65535) throw ValueErr("Port out of range 0-65535");
    return n;
  }
  function password(p) {
    const [userinfo, at] = rpartition(p.netloc, "@");
    if (!at) return null;
    const [, colon, pw] = partition(userinfo, ":");
    return colon ? pw : null;
  }
  const UTF8 = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8", { ignoreBOM: true }) : null;
  function unquote(s) { // percent-decode ASCII runs as UTF-8 with errors="replace"
    if (!s.includes("%")) return s;
    return s.replace(/[\x00-\x7f]+/g, (run) => {
      const bytes = [];
      for (let i = 0; i < run.length; i++) {
        if (run[i] === "%" && /^[0-9a-fA-F]{2}$/.test(run.slice(i + 1, i + 3))) { bytes.push(parseInt(run.slice(i + 1, i + 3), 16)); i += 2; }
        else bytes.push(run.charCodeAt(i));
      }
      return UTF8.decode(new Uint8Array(bytes));
    });
  }
  const unquotePlus = (s) => unquote(s.replace(/\+/g, " "));
  function parseQsl(qs, keepBlank) {
    const r = [];
    if (!qs) return r;
    for (const nv of qs.split("&")) {
      if (!nv) continue;
      const [name, , value] = partition(nv, "=");
      if (value || keepBlank) r.push([unquotePlus(name), unquotePlus(value)]);
    }
    return r;
  }

  // ---- scan.py ---------------------------------------------------------------
  function redact(s) {
    const c = cps(s);
    return c.length > 8 ? c.slice(0, 4).join("") + "\u2026" + `[${c.length} chars]` : "\u2026";
  }

  function safeUrl(url) {
    let p, host, port;
    try {
      p = urlsplit(url);
      host = hostname(p) || "";
      const n = portOf(p);
      port = n ? ":" + n : "";
    } catch (e) {
      return "(unparseable url)";
    }
    const q = p.query ? "?" + parseQsl(p.query, true).map(([k]) => k + "=\u2026").join("&") : "";
    return `${p.scheme}://${host}${port}${p.path}${q}`;
  }

  function looksLikeValue(v) {
    v = v.replace(STRIP, "");
    if (hasSecretPattern(v)) return true;
    if (!v || ENV_REF_FULL.test(v) || PY_DIGITS.test(v) || ["true", "false", "none", "null"].includes(v.toLowerCase())) return false;
    if ("/~.".includes(v[0]) || /^[A-Za-z]:[\\/]/.test(v) || /^[a-z]+([_\-][a-z]+)*$/.test(v)) return false;
    return cps(v).length >= 12 && !v.includes(" ");
  }

  const group = (s, m, n) => s.slice(m.indices[n][0], m.indices[n][1]); // group n of a match made on fold(s)

  function isSecretLiteral(key, val) {
    if (typeof val !== "string" || !val || ENV_REF_FULL.test(val.replace(STRIP, ""))) return false;
    if (hasSecretPattern(val)) return true;
    if (CONN_STRING.test(fold(val)) && !ENV_REF.test(val.split("@")[0])) return true; // credentials in a connection string
    const m = AUTH_SCHEME.exec(fold(val));
    if (m) return looksLikeValue(group(val, m, 2));
    return !!(key && SECRET_KEY_NAME.test(fold(key)) && !NOT_SECRET_NAME.test(fold(key))) && looksLikeValue(val);
  }

  function urlSecrets(url) {
    try {
      const p = urlsplit(url);
      const pw = password(p);
      if (pw && !ENV_REF.test(pw)) return true;
      return parseQsl(p.query, false).some(([k, v]) => SECRET_PARAM.test(fold(k)) && looksLikeValue(v));
    } catch (e) {
      return false;
    }
  }

  function pkgPinned(pkg) {
    if (pkg.startsWith("-") || pkg.includes("==")) return true;
    const name = pkg.startsWith("@") ? pkg.slice(1) : pkg;
    if (!name.includes("@")) return false;
    const version = rpartition(name, "@")[2];
    return !!version && !["latest", "next", "*"].includes(version);
  }

  function asArgs(v) {
    if (typeof v === "string") {
      try { return shlexSplit(v); } catch (e) { return pySplit(v); }
    }
    return Array.isArray(v) ? v.map(pyStr) : [];
  }

  function isLocal(url) {
    try { return LOCAL_HOSTS.has(hostname(urlsplit(url)) || ""); } catch (e) { return false; }
  }

  const removeSuffix = (s, x) => (s.endsWith(x) && x ? s.slice(0, -x.length) : s);

  function scanServer(name, cfg) {
    const f = [];
    const add = (rule, severity, message) => f.push({ server: String(name), rule, severity, message });
    const cmd = typeof cfg.get("command") === "string" ? cfg.get("command") : "";
    const args = asArgs(cfg.get("args"));
    const exe = removeSuffix(removeSuffix(rpartition(cmd.replace(/\\/g, "/"), "/")[2], ".cmd"), ".exe");

    for (const [where, items] of [["env", asDict(cfg.get("env"))], ["header", asDict(cfg.get("headers"))]]) {
      for (const [k, v] of items) {
        if (isSecretLiteral(k, v)) add("MW001", "high", `Plaintext secret in ${where} ${k} (${redact(v)}). Use an env reference or a secret store.`);
      }
    }
    for (const a of args) {
      const fv = FLAG_VALUE.exec(fold(a));
      if (hasSecretPattern(a) || (fv && looksLikeValue(group(a, fv, 2)))) {
        add("MW001", "high", `Plaintext secret in command args (${redact(a)}). Visible in process lists.`);
      }
      if (UNSAFE_FLAGS.test(fold(a))) add("MW009", "high", `Launched with '${a.split("=")[0]}', which turns off a safety control.`);
    }

    const origArgs = args;
    let rexe = exe, rargs = args;
    // Windows launches npx & co. as `cmd /c npx ...`: scan the program it runs, unless real shell syntax is involved
    if (exe === "cmd" && args.length >= 2 && args[0].toLowerCase() === "/c" && !args.slice(1).some((x) => /[&|<>^]/.test(x))) {
      rexe = removeSuffix(removeSuffix(rpartition(args[1].replace(/\\/g, "/"), "/")[2], ".cmd"), ".exe");
      rargs = args.slice(2);
    }
    if (RUNNERS.has(rexe)) {
      const plain = rargs.filter((a) => !a.startsWith("-"));
      const scanArgs = rexe === "pipx" && plain.length > 1 && plain[0] === "run" ? rargs.slice(rargs.indexOf(plain[1])) : rargs;
      const pkg = scanArgs.find((a) => !a.startsWith("-"));
      if (pkg && !pkgPinned(pkg)) add("MW002", "medium", `Unpinned package '${pkg}' via ${rexe}: every launch runs whatever the registry serves. Pin a version.`);
    }
    if (["bash", "sh", "zsh", "cmd", "powershell", "pwsh"].includes(rexe) && rargs.some((a) => ["-c", "/c", "-Command"].includes(a))) {
      add("MW008", "high", "Server launched through an inline shell command. Hard to audit; prefer a direct executable.");
    }
    if (CURL_PIPE.test([cmd, ...origArgs].join(" "))) add("MW008", "critical", "Pipes a download straight into a shell.");

    const container = exe === "docker" || exe === "podman";
    if (container) {
      const joined = args.join(" ");
      if (args.includes("--privileged") || CAP_ADD.test(fold(joined))) {
        add("MW007", "critical", "Container runs privileged or with SYS_ADMIN/ALL capabilities: effectively host access.");
      }
      if (joined.includes("/var/run/docker.sock") || ROOT_MOUNT.test(joined)) add("MW007", "critical", "Container mounts the host root or the Docker socket.");
      if (HOST_NS.test(joined)) add("MW007", "medium", "Container shares the host network, PID or IPC namespace.");
      for (const m of joined.matchAll(MOUNTS)) {
        const hostPath = m[1] || m[2];
        if (hostPath !== "/" && BROAD_PATH.test(hostPath)) add("MW006", "high", `Container mounts a whole home directory (${hostPath}).`);
      }
    }
    if (!container && args.some((a) => BROAD_PATH.test(a))) {
      add("MW006", "high", "Server is granted the filesystem root or a whole home directory. Scope it to a project folder.");
    }

    const url = truthy(cfg.get("url")) ? cfg.get("url") : cfg.get("serverUrl");
    if (typeof url === "string" && url) {
      const shown = safeUrl(url);
      if (urlSecrets(url)) add("MW001", "high", `Credentials embedded in the server URL (${shown}). They end up in logs and history.`);
      if (url.toLowerCase().startsWith("http://") && !isLocal(url)) add("MW004", "high", `Remote server over plain HTTP (${shown}). Traffic and tokens can be intercepted.`);
      const headers = new Set(Array.from(asDict(cfg.get("headers")).keys(), (k) => k.toLowerCase()));
      if (!["authorization", "x-api-key", "api-key"].some((h) => headers.has(h)) && !truthy(cfg.get("oauth")) && !isLocal(url) && !urlSecrets(url)) {
        add("MW005", "low", "Remote server configured without auth headers. Fine if it uses OAuth; otherwise anyone with the URL can call it.");
      }
    }
    return f;
  }

  function nameTokens(name) {
    return new Set(Array.from(name.matchAll(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\p{Nd}+/gu), (m) => m[0].toLowerCase()));
  }

  function scanTools(tools, server) {
    server = server || "(tools manifest)";
    const f = [], risky = [];
    for (const t of Array.isArray(tools) ? tools : []) {
      if (!isDict(t)) continue;
      const name = pyStr(get(t, "name", "?"));
      const text = pyStr(get(t, "description", "")) + " " + pyDumps(get(t, "inputSchema", new Map()));
      const add = (rule, severity, msg) => f.push({ server, rule, severity, message: `tool '${name}': ${msg}` });
      if (HIDDEN.test(text + name)) add("MW103", "critical", "contains invisible/tag Unicode characters, a common way to hide instructions from humans.");
      const m = INJECTION.exec(fold(text));
      if (m) {
        const hit = cps(text.substr(m.index, m[0].length)).slice(0, 60).join("");
        add("MW101", "critical", `description contains instruction-like text aimed at the model ('${hit}'). Possible tool poisoning.`);
      }
      const toks = nameTokens(name);
      if ([...toks].some((x) => DANGEROUS_TOKENS.has(x)) || (toks.has("run") && toks.has("command"))) risky.push(name);
    }
    if (risky.length) { // one finding per server: an admin API with 13 delete tools is not 13x worse
      const shown = risky.slice(0, 5).join(", ") + (risky.length > 5 ? ` and ${risky.length - 5} more` : "");
      f.push({ server, rule: "MW102", severity: "medium",
        message: `${risky.length} tool(s) can execute commands or delete data (${shown}). Require confirmation before the agent calls them.` });
    }
    return f;
  }

  function serversOf(config) {
    if (!isDict(config)) return new Map();
    let s = config.get("mcpServers");
    if (!truthy(s)) s = config.get("servers");
    if (!truthy(s)) s = asDict(config.get("mcp")).get("servers");
    return isDict(s) ? s : new Map();
  }

  function score(findings) {
    const pts = Math.max(0, 100 - findings.reduce((n, x) => n + SEV_WEIGHT[x.severity], 0));
    const grade = pts >= 90 ? "A" : pts >= 75 ? "B" : pts >= 60 ? "C" : pts >= 40 ? "D" : "F";
    return [pts, grade];
  }

  /* Scan pasted text: an MCP client config and/or a tools manifest ({"tools": [...]} or a bare list).
   * Returns {score, grade, servers, findings} or {error: "json", message, line, col} / {error: "noservers"}. */
  function scanText(text) {
    let data;
    try {
      data = parseJSON(text);
    } catch (e) {
      if (e instanceof SyntaxError) return { error: "json", message: e.message, line: e.line, col: e.col };
      return { error: "json", message: "Input is nested too deeply." };
    }
    const servers = serversOf(data);
    const isTools = Array.isArray(data) || (isDict(data) && data.has("tools"));
    if (!servers.size && !isTools) return { error: "noservers" };
    const findings = [];
    for (const [name, cfg] of servers) if (isDict(cfg)) findings.push(...scanServer(name, cfg));
    if (isTools) findings.push(...scanTools(Array.isArray(data) ? data : data.get("tools")));
    const [pts, grade] = score(findings);
    return { score: pts, grade, servers: servers.size, findings };
  }

  // ---- lookup keys: port of mcpwatch/watch.py url_key / pkg_key / config_keys (tests/test_watch_keys_parity.py) ----
  const pyStrip = (s) => s.replace(STRIP, "");
  function urlKey(url) {
    let p, h;
    try { p = urlsplit(pyStrip(url)); h = hostname(p); } catch (e) { return null; }
    return h ? `url:${p.scheme.toLowerCase()}://${h.toLowerCase()}${p.path.replace(/\/+$/, "")}` : null;
  }
  function pkgKey(kind, ident) {
    ident = pyStrip(ident);
    if (kind === "npm") {
      const name = partition(ident.startsWith("@") ? ident.slice(1) : ident, "@")[0];
      return "npm:" + (ident.startsWith("@") ? "@" : "") + name.toLowerCase();
    }
    if (kind === "pypi") return "pypi:" + ident.split(/[=<>~!\[@]/)[0].toLowerCase().replace(/_/g, "-");
    if (kind === "oci") {
      let img = partition(ident, "@")[0];
      if (img.slice(img.lastIndexOf("/") + 1).includes(":")) img = img.slice(0, img.lastIndexOf(":"));
      return "oci:" + img.toLowerCase();
    }
    return null;
  }
  // Throws (like shlex.split) on an unclosed quote in a string "args".
  function configKeys(cfg) {
    let url = get(cfg, "url", null);
    if (!truthy(url)) url = get(cfg, "serverUrl", null);
    if (typeof url === "string") { const k = urlKey(url); return k ? [k] : []; }
    const cmd = typeof get(cfg, "command", null) === "string" ? cfg.get("command") : "";
    let args = get(cfg, "args", null);
    args = typeof args === "string" ? shlexSplit(args) : Array.isArray(args) ? args.map(pyStr) : [];
    const base = (c) => removeSuffix(removeSuffix(c.replace(/\\/g, "/").split("/").pop(), ".cmd"), ".exe");
    let exe = base(cmd);
    if (exe === "cmd" && args.length >= 2 && args[0].toLowerCase() === "/c") { exe = base(args[1]); args = args.slice(2); }
    const plain = args.filter((a) => !a.startsWith("-"));
    if (["npx", "bunx", "pnpx"].includes(exe) && plain.length) return [pkgKey("npm", plain[0])];
    if (["uvx", "pipx"].includes(exe) && plain.length) {
      return [pkgKey("pypi", exe === "pipx" && plain[0] === "run" && plain.length > 1 ? plain[plain.length - 1] : plain[0])];
    }
    if (["docker", "podman"].includes(exe)) return plain.slice(1).filter((a) => a.includes("/") || a.includes(":")).map((a) => pkgKey("oci", a)).slice(-1);
    return [];
  }

  const api = { scanText, parseJSON, scanServer, scanTools, serversOf, score, shlexSplit, urlKey, pkgKey, configKeys, isDict };
  root.mcpwatchScan = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;

  // ---- page wiring -----------------------------------------------------------
  if (typeof document === "undefined") return;
  const $ = (id) => document.getElementById(id);
  const input = $("cfg"), out = $("results");
  if (!input || !out) return;

  const el = (tag, text, cls) => {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    if (cls) e.className = cls;
    return e;
  };
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

  function show(nodes) {
    out.replaceChildren(...nodes);
    const h = out.querySelector("h2");
    if (h) h.focus();
  }

  function message(title, text) {
    const h = el("h2", title);
    h.tabIndex = -1;
    return [h, el("p", text)];
  }

  function run() {
    const text = input.value;
    if (!text.trim()) return show(message("Nothing to scan", "Paste an MCP config or a tools manifest into the box above, or try the example."));
    const r = scanText(text);
    if (r.error === "json") {
      const where = r.line ? ` (line ${r.line}, column ${r.col})` : "";
      return show(message("That is not valid JSON", `${r.message}${where}. Check for a missing comma, quote or bracket.`));
    }
    if (r.error === "noservers") {
      return show(message("No MCP servers found", 'Looked for "mcpServers", "servers" or "mcp.servers", and for a "tools" list. Paste the whole config file.'));
    }
    const h = el("h2", "Grade ");
    h.tabIndex = -1;
    h.append(el("span", r.grade, "g g" + r.grade));
    const summary = el("p", `Score ${r.score}/100 across ${r.servers} server(s), ${r.findings.length} finding(s).`, "mut");
    const nodes = [h, summary];
    if (!r.findings.length) nodes.push(el("p", "No issues found. Pin it with mcpwatch lock so you hear about changes."));
    for (const sev of [...SEV_ORDER].reverse()) {
      const items = r.findings.filter((x) => x.severity === sev);
      if (!items.length) continue;
      const card = el("div", undefined, "card");
      card.append(el("h3", `${SEV_LABEL[sev]} (${items.length})`));
      const ul = el("ul");
      for (const x of items) {
        const li = el("li", undefined, "wrap");
        li.append(el("strong", x.rule), " ", el("code", x.server), ": " + x.message);
        ul.append(li);
      }
      card.append(ul);
      nodes.push(card);
    }
    show(nodes);
  }

  const FAKE_KEY = "sk-ant-" + "EXAMPLE".repeat(4); // built at runtime: not a real key
  const EXAMPLE = {
    mcpServers: {
      filesystem: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "~"] },
      assistant: { command: "npx", args: ["-y", "example-mcp-server@1.4.0"], env: { ANTHROPIC_API_KEY: FAKE_KEY } },
      sandbox: { command: "docker", args: ["run", "-i", "--rm", "--privileged", "-v", "/var/run/docker.sock:/var/run/docker.sock", "example/sandbox"] },
      remote: { url: "http://mcp.example.com/sse" },
    },
  };

  $("scan-btn").addEventListener("click", run);
  $("example-btn").addEventListener("click", () => {
    input.value = JSON.stringify(EXAMPLE, null, 2);
    run();
  });
})(typeof globalThis !== "undefined" ? globalThis : this);
