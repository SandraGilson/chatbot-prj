import { createServer } from "node:http";

import analyzeHandler from "./api/analyze.js";
import analyseHandler from "./api/analyse.js";
import chatHandler from "./api/chat.js";
import healthHandler from "./api/health.js";

const PORT = Number(process.env.PORT) || 3000;

const routes = {
  "/api/analyze": analyzeHandler,
  "/api/analyse": analyseHandler,
  "/api/chat": chatHandler,
  "/api/health": healthHandler,
};

function makeResponse(res) {
  return {
    status(code) {
      res.statusCode = code;
      return this;
    },
    setHeader(name, value) {
      res.setHeader(name, value);
      return this;
    },
    json(data) {
      res.setHeader(
        "Content-Type",
        "application/json; charset=utf-8"
      );
      res.end(JSON.stringify(data));
      return this;
    },
    end() {
      res.end();
      return this;
    },
  };
}

function sendError(res, status, message) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ error: message }));
}

const server = createServer(async (req, res) => {
  let pathname;

  try {
    pathname = new URL(
      req.url || "/",
      "http://localhost"
    ).pathname;
  } catch {
    sendError(res, 400, "Invalid request URL.");
    return;
  }

  const handler = routes[pathname];

  if (!handler) {
    sendError(res, 404, "Endpoint not found.");
    return;
  }

  const chunks = [];
  let size = 0;

  try {
    for await (const chunk of req) {
      size += chunk.length;

      if (size > 65536) {
        sendError(res, 413, "Request body is too large.");
        return;
      }

      chunks.push(chunk);
    }

    req.body = ["GET", "HEAD", "OPTIONS"].includes(req.method)
      ? undefined
      : Buffer.concat(chunks).toString("utf8");

    await handler(req, makeResponse(res));
  } catch (error) {
    console.error("ScamShield request failed:", error.message);

    if (!res.writableEnded) {
      sendError(res, 500, "Internal server error.");
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`ScamShield API listening on port ${PORT}`);
});