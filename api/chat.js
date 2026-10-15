// NVIDIA NIM uses Node.js built-in fetch.

const MAX_MESSAGE_LENGTH = 2000;
const MAX_REQUEST_BYTES = 12 * 1024;

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
];

const SYSTEM_INSTRUCTION = `
You are ScamShield, a cybersecurity awareness assistant.

Explain phishing, suspicious messages, unsafe links, online scams,
and practical ways to protect users.

Be concise, calm, and helpful. Recommend verifying requests through
independently opened official websites, apps, or trusted contact channels.

Do not claim that a website or message is safe without sufficient evidence.
Do not claim to have scanned a URL or checked threat intelligence unless
that operation was actually performed.
Never ask users to share passwords, OTPs, or recovery codes.

General chat is separate from ScamShield's deterministic detection engine.
Do not invent or override the engine's findings.
`;

function getAllowedOrigins() {
  const configured = process.env.FRONTEND_ORIGIN;

  return configured
    ? configured.split(",").map((value) => value.trim()).filter(Boolean)
    : DEFAULT_ALLOWED_ORIGINS;
}

function configureCors(req, res) {
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  const origin = req.headers?.origin;

  // Allow requests without an Origin header, such as local PowerShell tests.
  if (!origin) return true;

  if (!getAllowedOrigins().includes(origin)) {
    return false;
  }

  res.setHeader("Access-Control-Allow-Origin", origin);
  return true;
}

async function generateNimReply(message) {
  const apiKey = process.env.NVIDIA_API_KEY;

  if (!apiKey) {
    const error = new Error("NVIDIA API key is not configured.");
    error.code = "MISSING_NVIDIA_API_KEY";
    throw error;
  }

  const response = await fetch(
    "https://integrate.api.nvidia.com/v1/chat/completions",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        model: process.env.NVIDIA_MODEL || "openai/gpt-oss-20b",
        messages: [
          {
            role: "system",
            content: SYSTEM_INSTRUCTION,
          },
          {
            role: "user",
            content: message,
          },
        ],
        temperature: 0.4,
        max_tokens: 500,
        stream: false,
      }),
      signal: AbortSignal.timeout(45_000),
    }
  );

  if (!response.ok) {
    const error = new Error(
      `NVIDIA NIM returned HTTP ${response.status}.`
    );
    error.status = response.status;
    error.code = `NIM_HTTP_${response.status}`;
    throw error;
  }

  const data = await response.json();
  const reply = data.choices?.[0]?.message?.content?.trim();

  if (!reply) {
    const error = new Error("NVIDIA NIM returned no text.");
    error.code = "EMPTY_NIM_RESPONSE";
    throw error;
  }

  return reply;
}
// Inject a mock generator in tests so testing does not call NVIDIA NIM.
export function createChatHandler({
  generateReply = generateNimReply,
} = {}) {
  return async function handler(req, res) {
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

    if (
      typeof body === "string" &&
      Buffer.byteLength(body, "utf8") > MAX_REQUEST_BYTES
    ) {
      return res.status(413).json({
        error: "Request body is too large.",
      });
    }

    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch {
        return res.status(400).json({
          error: "Request body contains invalid JSON.",
        });
      }
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({
        error: "Request body must be a JSON object.",
      });
    }

    if (Buffer.byteLength(JSON.stringify(body), "utf8") > MAX_REQUEST_BYTES) {
      return res.status(413).json({
        error: "Request body is too large.",
      });
    }

    if (typeof body.message !== "string") {
      return res.status(400).json({
        error: "message must be a string.",
      });
    }

    const message = body.message.trim();

    if (!message) {
      return res.status(400).json({
        error: "message must not be empty.",
      });
    }

    if (message.length > MAX_MESSAGE_LENGTH) {
      return res.status(413).json({
        error: `message must not exceed ${MAX_MESSAGE_LENGTH} characters.`,
      });
    }

    try {
      const reply = await generateReply(message);

      return res.status(200).json({ reply });
    } catch (error) {
      if (error?.code === "MISSING_NVIDIA_API_KEY") {
        return res.status(503).json({
          error: "Chat service is not configured.",
        });
      }

      const diagnostic = {
        name: error?.name || "UnknownError",
        status: error?.status ?? error?.statusCode ?? "unknown",
        code: error?.code ?? "unknown",
        message: String(error?.message ?? "No error message").slice(0, 300),
      };

      if (process.env.NVIDIA_API_KEY) {
        diagnostic.message = diagnostic.message.replaceAll(
          process.env.NVIDIA_API_KEY,
          "[REDACTED]"
        );
      }

      console.error("ScamShield chat request failed:", diagnostic);

      return res.status(502).json({
        error: "The chat service is temporarily unavailable.",
      });
    }
  };
}

export default createChatHandler();
