import assert from "node:assert/strict";
import test from "node:test";
import handler from "../api/analyze.js";

function invoke({
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

  handler(req, res);
  return res;
}

test("valid message returns a structured analysis", () => {
  const res = invoke({
    body: {
      type: "message",
      content: "Your account will be blocked. Send your OTP now.",
    },
  });

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.type, "message");
  assert.ok(Array.isArray(res.payload.indicators));
  assert.ok("riskLevel" in res.payload);
  assert.ok("score" in res.payload);
  assert.ok("recommendation" in res.payload);
  assert.ok("disclaimer" in res.payload);
});

test("valid URL input returns a URL analysis", () => {
  const res = invoke({
    body: {
      type: "url",
      content: "https://example.com/",
    },
  });

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.type, "url");
  assert.ok(Array.isArray(res.payload.indicators));
});

test("invalid input type returns 400", () => {
  const res = invoke({
    body: {
      type: "other",
      content: "hello",
    },
  });

  assert.equal(res.statusCode, 400);
  assert.ok(res.payload.error);
});

test("invalid JSON returns 400", () => {
  const res = invoke({
    body: "{invalid-json",
  });

  assert.equal(res.statusCode, 400);
});

test("wrong content type returns 415", () => {
  const res = invoke({
    headers: {
      "content-type": "text/plain",
    },
    body: "hello",
  });

  assert.equal(res.statusCode, 415);
});

test("GET requests return 405", () => {
  const res = invoke({
    method: "GET",
    body: {},
  });

  assert.equal(res.statusCode, 405);
});

test("oversized request returns 413", () => {
  const res = invoke({
    body: {
      type: "message",
      content: "x".repeat(13_000),
    },
  });

  assert.equal(res.statusCode, 413);
});

test("OPTIONS request returns 204", () => {
  const res = invoke({
    method: "OPTIONS",
    headers: {},
  });

  assert.equal(res.statusCode, 204);
  assert.equal(res.ended, true);
});

test("unapproved browser origin returns 403", () => {
  const res = invoke({
    headers: {
      origin: "https://untrusted.invalid",
    },
    body: {
      type: "message",
      content: "Hello",
    },
  });

  assert.equal(res.statusCode, 403);
});
