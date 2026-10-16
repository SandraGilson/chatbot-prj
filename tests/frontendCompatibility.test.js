import assert from "node:assert/strict";
import test from "node:test";
import handler from "../api/analyse.js";

function invoke({ method = "POST", headers = {}, body } = {}) {
  const req = {
    method,
    headers: { "content-type": "application/json", ...headers },
    body,
  };
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

test("frontend-compatible analyse route accepts text and returns UI fields", () => {
  const res = invoke({ body: {
    type: "message",
    text: "URGENT: Your account will be blocked today. Send your OTP now.",
  } });

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.type, "message");
  assert.equal(res.payload.risk, "high");
  assert.ok(Array.isArray(res.payload.indicators));
  assert.ok(res.payload.indicators.some((item) => typeof item.label === "string"));
  assert.ok(Array.isArray(res.payload.nextSteps));
  assert.ok(Number.isFinite(res.payload.scorePercent));
});
