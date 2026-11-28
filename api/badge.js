// GET /badge/<slug>.svg -> grade badge. Looks the slug up in this deployment's own static shard.
const COLORS = { A: "#1a7f37", B: "#4d7c0f", C: "#8a5a00", D: "#bc4c00", F: "#c4222e", "?": "#6e7781" };

// must stay byte-identical to mcpwatch/scan.py badge()
function svg(grade) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="20" role="img" aria-label="mcpwatch: ${grade}">` +
    `<title>mcpwatch: ${grade}</title><clipPath id="r"><rect width="128" height="20" rx="3"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="96" height="20" fill="#1f2a30"/><rect x="96" width="32" height="20" fill="${COLORS[grade]}"/></g>` +
    `<g fill="none" stroke="#2dd4bf" stroke-width="1.5" stroke-linecap="round"><path d="M12 5a5 5 0 1 0 5 5"/><path d="M12 10l3.5-3.5"/></g>` +
    `<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">` +
    `<text x="57" y="14">mcpwatch</text><text x="112" y="14" font-weight="bold">${grade}</text></g></svg>`;
}

module.exports = async (req, res) => {
  const slug = String(req.query.slug || "");
  let grade = "?";
  if (/^[a-z0-9-]{10,100}$/.test(slug)) {
    try {
      // host comes from the platform (production domain: per-deployment URLs sit behind deployment protection),
      // never from the request's Host header
      const host = process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL;
      const r = await fetch(`https://${host}/d/${slug.slice(-8, -6)}.json`);
      const g = r.ok ? (await r.json())[slug]?.g : undefined;
      if (g && COLORS[g]) grade = g;
    } catch (_) { /* unknown stays grey */ }
  }
  res.setHeader("Content-Type", "image/svg+xml");
  res.setHeader("Cache-Control", "public, max-age=3600, s-maxage=3600");
  res.status(200).send(svg(grade));
};
