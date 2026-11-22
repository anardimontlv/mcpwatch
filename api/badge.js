// GET /badge/<slug>.svg -> grade badge. Looks the slug up in this deployment's own static shard.
const COLORS = { A: "#2e7d32", B: "#558b2f", C: "#f9a825", D: "#ef6c00", F: "#c62828", "?": "#9e9e9e" };

function svg(grade) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="20" role="img" aria-label="agentguard: ${grade}">` +
    `<rect width="96" height="20" fill="#555"/><rect x="96" width="32" height="20" fill="${COLORS[grade]}"/>` +
    `<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">` +
    `<text x="48" y="14">agentguard</text><text x="112" y="14">${grade}</text></g></svg>`;
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
