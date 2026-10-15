import assert from "node:assert/strict";
import test from "node:test";
import handler, { createChatHandler } from "../api/chat.js";

async function invoke(targetHandler, {
  method = "POST",
  headers = {},
  body,
} = {}) {
  const req = {
    method,
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body,
  };

  const res = {
    statusCode: 200,
    headers: {},
    payload: undefined,
    ended: false,

    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },

    status(code) {
      this.statusCode = code;
      return this;
    },

    json(payload) {
      this.payload = payload;
      return this;
    },

    end() {
      this.ended = true;
      return this;
    },
  };

  await targetHandler(req, res);
  return res;
}

test("valid question returns a reply", async () => {
  const testHandler = createChatHandler({
    generateReply: async (message) => `Test reply: ${message}`,
  });

  const res = await invoke(testHandler, {
    body: { message: "How can I recognize phishing?" },
  });

  assert.equal(res.statusCode, 200);
  assert.equal(
    res.payload.reply,
    "Test reply: How can I recognize phishing?"
  );
});

test("missing NVIDIA key returns 503", async () => {
  const original = process.env.NVIDIA_API_KEY;
  delete process.env.NVIDIA_API_KEY;

  try {
    const res = await invoke(handler, {
      body: { message: "Explain phishing." },
    });

    assert.equal(res.statusCode, 503);
  } finally {
    if (original !== undefined) {
      process.env.NVIDIA_API_KEY = original;
    }
  }
});

test("GET returns 405", async () => {
  const res = await invoke(handler, { method: "GET", body: {} });
  assert.equal(res.statusCode, 405);
});

test("invalid JSON returns 400", async () => {
  const res = await invoke(handler, { body: "{invalid" });
  assert.equal(res.statusCode, 400);
});

test("wrong content type returns 415", async () => {
  const res = await invoke(handler, {
    headers: { "content-type": "text/plain" },
    body: "hello",
  });
  assert.equal(res.statusCode, 415);
});

test("empty question returns 400", async () => {
  const res = await invoke(handler, { body: { message: "   " } });
  assert.equal(res.statusCode, 400);
});

test("oversized question returns 413", async () => {
  const res = await invoke(handler, {
    body: { message: "x".repeat(2001) },
  });
  assert.equal(res.statusCode, 413);
});

test("oversized raw body returns 413", async () => {
  const res = await invoke(handler, {
    body: JSON.stringify({
      message: "hello",
      extra: "x".repeat(13000),
    }),
  });
  assert.equal(res.statusCode, 413);
});

test("OPTIONS returns 204", async () => {
  const res = await invoke(handler, { method: "OPTIONS" });
  assert.equal(res.statusCode, 204);
  assert.equal(res.ended, true);
});

test("unapproved origin returns 403", async () => {
  const res = await invoke(handler, {
    headers: { origin: "https://untrusted.invalid" },
    body: { message: "Explain phishing." },
  });
  assert.equal(res.statusCode, 403);
});

test("provider failure returns generic 502", async () => {
  const testHandler = createChatHandler({
    generateReply: async () => {
      throw new Error("Simulated provider failure");
    },
  });

  const res = await invoke(testHandler, {
    body: { message: "Explain phishing." },
  });

  assert.equal(res.statusCode, 502);
});
