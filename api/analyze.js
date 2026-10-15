import { analyzeInput } from "../lib/detectionEngine.js";

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const MAX_REQUEST_BYTES = 12 * 1024;

function getAllowedOrigins() {
  const configured = process.env.FRONTEND_ORIGIN;

  if (!configured) {
    return DEFAULT_ALLOWED_ORIGINS;
  }

  return configured
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

function configureCors(req, res) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  const origin = req.headers?.origin;

  // Allow non-browser requests, such as local PowerShell tests.
  if (!origin) return true;

  if (!getAllowedOrigins().includes(origin)) {
    return false;
  }

  res.setHeader("Access-Control-Allow-Origin", origin);
  return true;
}

export default function handler(req, res) {
  if (!configureCors(req, res)) {
    return res.status(403).json({
      error: "Origin not allowed.",
    });
  }

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST, OPTIONS");

    return res.status(405).json({
      error: "Method not allowed. Use POST.",
    });
  }

  const contentType = String(
    req.headers?.["content-type"] ?? ""
  )
    .split(";")[0]
    .trim()
    .toLowerCase();

  if (contentType !== "application/json") {
    return res.status(415).json({
      error: "Content-Type must be application/json.",
    });
  }

  let body = req.body;

  // Vercel normally parses JSON bodies. This also handles a
  // string body in local tests or compatible runtimes.
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      return res.status(400).json({
        error: "Request body contains invalid JSON.",
      });
    }
  }

  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return res.status(400).json({
      error: "Request body must be a JSON object.",
    });
  }

  const serializedBody = JSON.stringify(body);

  if (Buffer.byteLength(serializedBody, "utf8") > MAX_REQUEST_BYTES) {
    return res.status(413).json({
      error: "Request body is too large.",
    });
  }

  try {
    const result = analyzeInput(body);

    return res.status(200).json(result);
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) {
      return res.status(400).json({
        error: error.message,
      });
    }

    console.error("ScamShield analysis endpoint failed.");

    return res.status(500).json({
      error: "Analysis failed due to an internal server error.",
    });
  }
}
