const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

function getAllowedOrigins() {
  const configured = process.env.FRONTEND_ORIGIN;
  return configured
    ? configured.split(",").map((origin) => origin.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_ORIGINS;
}

function configureCors(req, res) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const origin = req.headers?.origin;
  if (!origin) return true;
  if (!getAllowedOrigins().includes(origin)) return false;
  res.setHeader("Access-Control-Allow-Origin", origin);
  return true;
}

export default function handler(req, res) {
  if (!configureCors(req, res)) {
    return res.status(403).json({ error: "Origin not allowed." });
  }

  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({ error: "Method not allowed. Use GET." });
  }

  const aiConfigured = Boolean(process.env.NVIDIA_API_KEY);
  return res.status(200).json({
    ok: true,
    aiConfigured,
    provider: aiConfigured ? "NVIDIA NIM" : "NVIDIA NIM (not configured)",
    message: aiConfigured
      ? "The backend is online and an AI provider key is configured."
      : "The backend is online, but AI chat is not configured.",
  });
}
