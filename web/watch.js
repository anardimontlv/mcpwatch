/* /watch page and the /api/confirm + /api/unsubscribe link landings. Builds the DOM with textContent only.
 * A pasted config never leaves the browser: lookup keys are computed by mcpwatchScan.configKeys (a parity-tested port
 * of mcpwatch/watch.py) and resolved against the public /m/ shards; only public server ids (slugs) are POSTed. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (t, txt, cls) => { const e = document.createElement(t); if (txt != null) e.textContent = txt; if (cls) e.className = cls; return e; };
  const post = async (url, body) => {
    try {
      const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      return { ok: r.ok, d };
    } catch (e) { return { ok: false, d: { error: "network error, try again" } }; }
  };

  // ---- link landings: the button POSTs the URL's token, so a mail scanner's GET prefetch changes nothing ----
  const linkBtn = $("link-btn");
  if (linkBtn) {
    linkBtn.addEventListener("click", async () => {
      linkBtn.disabled = true;
      const t = new URLSearchParams(location.search).get("t") || "";
      const { ok, d } = await post(location.pathname, { t });
      if (ok && d.manage) { location.replace("/watch?confirmed=1#m=" + d.manage); return; }
      $("link-msg").textContent = ok ? d.message : "Could not do that: " + (d.error || "unknown error") + ".";
      if (!ok) linkBtn.disabled = false;
    });
    return;
  }
  if (!$("w-go")) return;

  const S = window.mcpwatchScan;
  const SLUG = /^[a-z0-9-]{10,100}$/;
  const fm = /^#m=([A-Za-z0-9_-]{43})$/.exec(location.hash);
  const token = fm ? fm[1] : null;
  const chosen = new Map(); // slug -> title
  const msg = (t) => { $("w-msg").textContent = t; };
  const cache = {};
  const getJSON = (p) => cache[p] || (cache[p] = fetch(p).then((r) => (r.ok ? r.json() : r.status === 404 ? {} : Promise.reject(new Error("HTTP " + r.status))))
    .catch((e) => { delete cache[p]; throw e; }));
  const title = async (sl) => ((await getJSON("/d/" + sl.slice(-8, -6) + ".json"))[sl] || {}).t;
  async function shard2(text) {
    const b = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    return b[0].toString(16).padStart(2, "0");
  }

  function renderChosen() {
    const ul = $("w-chosen");
    ul.replaceChildren();
    if (!chosen.size) { ul.append(el("li", "None yet: search above or paste a config.", "mut")); return; }
    for (const [sl, t] of chosen) {
      const li = el("li"), a = el("a", t || sl, "wrap"), b = el("button", "Remove", "btn");
      a.href = "/s/" + sl;
      b.type = "button";
      b.addEventListener("click", () => { chosen.delete(sl); renderChosen(); });
      li.append(a, " ", b);
      ul.append(li);
    }
  }

  let list = null;
  function renderList(slugs) {
    list = slugs;
    const ul = $("w-list");
    ul.replaceChildren();
    if (!slugs.length) ul.append(el("li", "No servers yet: add some below.", "mut"));
    for (const sl of slugs) {
      const li = el("li"), a = el("a", sl, "wrap"), b = el("button", "Remove", "btn");
      a.href = "/s/" + sl;
      title(sl).then((t) => { if (t) a.textContent = t; }).catch(() => {});
      b.type = "button";
      b.addEventListener("click", () => manage("remove", [sl]));
      li.append(a, " ", b);
      ul.append(li);
    }
  }

  async function manage(action, slugs) {
    const { ok, d } = await post("/api/manage", { token, action, slugs });
    if (!ok) { msg("Could not update your list: " + (d.error || "unknown error") + "."); return false; }
    if (d.deleted) {
      $("w-manage").hidden = true;
      msg("Your account and watchlist were deleted.");
      history.replaceState(null, "", "/watch");
      return true;
    }
    $("w-who").textContent = "Daily digest goes to " + d.email + ". " + d.slugs.length + " server" + (d.slugs.length === 1 ? "" : "s") +
      " watched (you can watch up to " + d.max + " of the index's servers during the beta).";
    renderList(d.slugs);
    renderBilling(d);
    return true;
  }

  // Paid plans: shown only when the server says billing is on. The target URL comes from our API (a Paddle page).
  function renderBilling(d) {
    const box = $("w-bill");
    box.replaceChildren();
    box.hidden = !d.billing_enabled;
    if (!d.billing_enabled) return;
    const free = d.plan === "free";
    const b = el("button", free ? "Upgrade to Pro ($19/month)" : "Manage billing", free ? "btn pri" : "btn");
    b.type = "button";
    b.addEventListener("click", async () => {
      b.disabled = true;
      const { ok, d: r } = await post(free ? "/api/billing/checkout" : "/api/billing/portal", free ? { token, plan: "pro" } : { token });
      if (ok && typeof r.url === "string" && /^https:\/\//.test(r.url)) { location.assign(r.url); return; }
      msg("Could not open billing: " + ((r && r.error) || "unknown error") + ".");
      b.disabled = false;
    });
    box.append(b, " ", el("span", free ? "Free plan: up to " + d.limit + " servers, weekly digest." : "Plan: " + d.plan + ", daily digest.", "mut sm"));
  }

  async function add(sl, t) {
    if (token) { if (await manage("add", [sl])) msg("Added " + (t || sl) + "."); return; }
    if (chosen.size >= 200) { msg("200 servers is the beta limit."); return; }
    chosen.set(sl, t);
    renderChosen();
    msg("Selected " + (t || sl) + ".");
  }

  // search, like the home page: /list.json rows are [slug, title, grade, findings]
  let L = null;
  $("w-q").addEventListener("input", async () => {
    const v = $("w-q").value.trim().toLowerCase(), ul = $("w-hits");
    if (v.length < 2) { ul.replaceChildren(); return; }
    try { L = L || await getJSON("/list.json"); } catch (e) { ul.replaceChildren(el("li", "Could not load the index.")); return; }
    const hits = L.filter((x) => x[0].includes(v) || x[1].toLowerCase().includes(v)).slice(0, 20);
    ul.replaceChildren(...(hits.length ? hits.map((x) => {
      const li = el("li"), b = el("button", "Add", "btn"), c = el("span", null, "g g" + x[2]);
      c.append(el("span", "Grade ", "vh"), x[2]);
      b.type = "button";
      b.addEventListener("click", () => add(x[0], x[1]));
      li.append(c, " ", el("span", x[1], "wrap"), " ", b);
      return li;
    }) : [el("li", "No servers match.", "mut")]));
  });

  $("w-find").addEventListener("click", async () => {
    const ul = $("w-found");
    let data;
    try { data = S.parseJSON($("w-cfg").value); } catch (e) { ul.replaceChildren(el("li", "That is not valid JSON.")); return; }
    const rows = [];
    let added = 0;
    for (const [name, cfg] of S.serversOf(data)) {
      if (!S.isDict(cfg)) continue;
      let keys = [], res = "not in the public index (private or local server)";
      try { keys = S.configKeys(cfg); } catch (e) { /* unparsable args: not indexed */ }
      try {
        for (const k of keys) {
          const sl = (await getJSON("/m/" + await shard2(k) + ".json"))[k];
          if (Array.isArray(sl)) { res = "claimed by several index entries: add it by search"; break; }
          if (typeof sl === "string" && SLUG.test(sl)) {
            const t = await title(sl);
            if (t) { await add(sl, t); added++; res = "matched: " + t; }
            break;
          }
        }
      } catch (e) { res = "could not reach the index, try again"; }
      rows.push(el("li", name + ": " + res, "wrap"));
    }
    ul.replaceChildren(...(rows.length ? rows : [el("li", "No MCP servers found in that config.")]));
    msg(added + " server(s) matched.");
  });

  $("w-go").addEventListener("click", async () => {
    const b = $("w-go");
    b.disabled = true;
    const { ok, d } = await post("/api/subscribe", { email: $("w-email").value, slugs: [...chosen.keys()] });
    msg(ok ? d.message : "Could not sign up: " + (d.error || "unknown error") + ".");
    b.disabled = false;
  });

  $("w-link").addEventListener("click", async () => {
    const { ok, d } = await post("/api/manage", { action: "email_link", email: $("w-email2").value });
    msg(ok ? d.message : "Could not send: " + (d.error || "unknown error") + ".");
  });

  $("w-delete").addEventListener("click", () => {
    if (confirm("Delete your email address and watchlist now? This cannot be undone.")) manage("delete_account");
  });

  const qs = new URLSearchParams(location.search);
  const note = (t) => { $("w-note").textContent = t; $("w-note").hidden = false; };
  if (qs.get("confirmed") === "1" && token) note("Confirmed. Bookmark this page: for 30 days its address is your private link to manage your list. After that, request a new link below.");
  if (token) {
    $("w-manage").hidden = false;
    $("w-sub").hidden = true;
    $("w-pick-h").textContent = "Add servers";
    manage("list");
  } else {
    renderChosen();
    const sl = qs.get("add");
    if (sl && SLUG.test(sl)) title(sl).then((t) => { if (t) add(sl, t); }).catch(() => {});
  }
})();
