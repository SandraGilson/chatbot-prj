import test from "node:test";
import assert from "node:assert/strict";
import { analyzeMessage } from "../lib/messageRules.js";
import { analyzeUrl, extractUrls } from "../lib/urlRules.js";
import { analyzeInput } from "../lib/detectionEngine.js";
import { calculateRisk } from "../lib/riskScoring.js";

test("message flags a direct OTP request", () => {
  const findings = analyzeMessage("Your account is blocked. Send your OTP now.");
  assert.ok(findings.some((item) => item.code === "credential_request" || item.code === "credential_request_indirect"));
  assert.ok(findings.some((item) => item.code === "threat_or_urgency"));
});

test("message flags an upfront registration fee", () => {
  const findings = analyzeMessage("Congratulations on your job offer. Pay a registration fee to proceed.");
  assert.ok(findings.some((item) => item.code === "upfront_payment"));
});

test("ordinary message does not create indicators", () => {
  assert.deepEqual(analyzeMessage("The lab starts at 10 am tomorrow."), []);
});

test("safety advice warning users not to share OTP does not trigger credential rule", () => {
  const findings = analyzeMessage("Never share your OTP with anyone.");
  assert.equal(findings.some((item) => item.code.startsWith("credential_request")), false);
});

test("invalid non-string message is rejected", () => {
  assert.throws(() => analyzeMessage(null), TypeError);
});

test("HTTP URL is flagged as unencrypted without claiming it is malicious", () => {
  const findings = analyzeUrl("http://example.com/login");
  assert.ok(findings.some((item) => item.code === "http_scheme"));
  assert.equal(findings.some((item) => item.code === "brand_lookalike"), false);
});

test("IP address URL is flagged", () => {
  const findings = analyzeUrl("http://192.0.2.10/login");
  assert.ok(findings.some((item) => item.code === "ip_host"));
});

test("credential-like userinfo before @ is flagged", () => {
  const findings = analyzeUrl("https://paypal.com@evil.example/login");
  assert.ok(findings.some((item) => item.code === "url_userinfo"));
});

test("possible brand lookalike is flagged", () => {
  const findings = analyzeUrl("https://paypal-login.example/path");
  assert.ok(findings.some((item) => item.code === "brand_lookalike"));
});

test("an official subdomain is not flagged as a brand lookalike", () => {
  const findings = analyzeUrl("https://accounts.google.com/");
  assert.equal(findings.some((item) => item.code === "brand_lookalike"), false);
});

test("unsupported active-content scheme is rejected as a warning", () => {
  const findings = analyzeUrl("javascript:alert(1)");
  assert.ok(findings.some((item) => item.code === "unsafe_scheme"));
});

test("ordinary HTTPS domain with no known heuristic is inconclusive", () => {
  const result = analyzeInput({ type: "url", content: "https://example.org" });
  assert.equal(result.riskLevel, "inconclusive");
  assert.match(result.disclaimer, /not proof that .* safe/i);
});

test("URL extraction finds web links and avoids email domain", () => {
  const found = extractUrls("Email me at analyst@example.com or visit https://pay.example/login and www.test.example/path.");
  assert.deepEqual(found, ["https://pay.example/login", "www.test.example/path"]);
});

test("message analysis also inspects embedded URL without fetching it", () => {
  const result = analyzeInput({
    type: "message",
    content: "Urgent! Verify your account at http://192.0.2.5 now.",
  });
  assert.ok(result.indicators.some((item) => item.code === "ip_host"));
  assert.ok(result.indicators.some((item) => item.code === "threat_or_urgency"));
});

test("repeated indicator codes do not inflate scoring", () => {
  const { score } = calculateRisk([
    { code: "urgent", points: 2 },
    { code: "urgent", points: 2 },
    { code: "payment", points: 3 },
  ]);
  assert.equal(score, 5);
});

test("input type, empty content and length are validated", () => {
  assert.throws(() => analyzeInput({ type: "other", content: "hi" }), TypeError);
  assert.throws(() => analyzeInput({ type: "message", content: "  " }), TypeError);
  assert.throws(() => analyzeInput({ type: "message", content: "x".repeat(2001) }), RangeError);
});
