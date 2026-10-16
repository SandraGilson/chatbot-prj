import assert from "node:assert/strict";
import test from "node:test";
import handler from "../api/health.js";

function invoke({ method = "GET", headers = {} } = {}) {
  const req = { method, headers };
  const res = {
    statusCode: 200, headers: {}, payload: undefined, ended: false,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; return this; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return this; },
    end() { this.ended = true; return this; },
  };
  handler(req, res);
  return res;
}

test("health endpoint reports backend availability and provider configuration", () => {
  const res = invoke();
  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.ok, true);
  assert.equal(typeof res.payload.aiConfigured, "boolean");
  assert.equal(typeof res.payload.provider, "string");
});

test("health endpoint rejects unsupported methods", () => {
  const res = invoke({ method: "POST" });
  assert.equal(res.statusCode, 405);
});

test("health endpoint restricts browser origins", () => {
  const original = process.env.FRONTEND_ORIGIN;
  process.env.FRONTEND_ORIGIN = "https://frontend.example";
  try {
    const res = invoke({ headers: { origin: "https://untrusted.example" } });
    assert.equal(res.statusCode, 403);
  } finally {
    if (original === undefined) delete process.env.FRONTEND_ORIGIN;
    else process.env.FRONTEND_ORIGIN = original;
  }
});
