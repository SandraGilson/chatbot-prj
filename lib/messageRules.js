/**
 * Deterministic, explainable message indicators for ScamShield.
 * These rules flag warning signs; they do not prove that a message is fraudulent.
 */

const MAX_MESSAGE_LENGTH = 2_000;

const RULES = [
  {
    code: "credential_request",
    name: "Sensitive credential request",
    severity: "high",
    points: 4,
    pattern: /\b(?:send|share|provide|enter|submit|reply\s+with|give\s+(?:me|us)|tell\s+(?:me|us))\s+(?:(?:us|me)\s+)?(?:your\s+)?(?:otp|one[-\s]?time password|password|pin|cvv|security code|verification code|recovery code)\b/i,
    evidence: "The message appears to ask the recipient to disclose a password, OTP, PIN, CVV, or another authentication code.",
  },
  {
    code: "credential_request_indirect",
    name: "Possible authentication-code request",
    severity: "high",
    points: 4,
    pattern: /\b(?:otp|one[-\s]?time password|password|pin|cvv|verification code|recovery code)\b.{0,45}\b(?:send|share|provide|enter|reply|confirm|verify)\b/i,
    evidence: "The message mentions a sensitive credential near an instruction to submit or verify it.",
  },
  {
    code: "upfront_payment",
    name: "Upfront payment pressure",
    severity: "high",
    points: 3,
    pattern: /\b(?:pay|transfer|send|deposit|submit)\b.{0,55}\b(?:(?:registration|processing|release|delivery|activation|verification|security|interview|training|application|customs|handling)\s+)?(?:fee|deposit|payment|charge)\b|\b(?:up[- ]front|advance)\s+(?:fee|payment|deposit)\b/i,
    evidence: "The message appears to request a fee, deposit, or payment, which can be a warning sign in unsolicited offers.",
  },
  {
    code: "threat_or_urgency",
    name: "Urgency or threat",
    severity: "medium",
    points: 2,
    pattern: /\b(?:act now|immediately|urgent(?:ly)?|final warning|within\s+\d+\s+(?:minutes?|hours?|days?)|account\s+(?:will be|has been|is being|is)\s+(?:blocked|suspended|locked|closed|deactivated)|failure to act|last chance|action required|avoid suspension)\b/i,
    evidence: "The message uses urgency, a deadline, or a threat to push the recipient to act quickly.",
  },
  {
    code: "unrealistic_reward_or_offer",
    name: "Unusually attractive reward or offer",
    severity: "medium",
    points: 2,
    pattern: /\b(?:you have won|winner selected|claim your (?:prize|reward|gift)|guaranteed (?:job|employment|returns?|profit)|risk[- ]free (?:investment|returns?)|earn\s+[$₹€£]?\s*\d[\d,]*(?:\.\d+)?\s+(?:daily|per day))\b/i,
    evidence: "The message advertises a prize, guaranteed outcome, or unusually attractive offer that deserves independent verification.",
  },
];

function isNegated(text, matchIndex, matchedText) {
  // Include the matched words, not just the prefix, so "Never share your OTP"
  // is recognized as safety advice rather than a suspicious request.
  const prefix = text.slice(Math.max(0, matchIndex - 55), matchIndex);
  const localClause = `${prefix.split(/[.!?;\n]/).pop() ?? prefix}${matchedText}`;
  return /\b(?:never|don't|dont|do not|should not|shouldn't|cannot|can't|avoid)\s+(?:ever\s+)?(?:send|share|provide|enter|submit|reply with|pay|transfer|deposit|give|tell)\b/i.test(localClause.trim());
}

function makeFinding(rule) {
  return {
    code: rule.code,
    name: rule.name,
    severity: rule.severity,
    points: rule.points,
    evidence: rule.evidence,
    category: "message",
  };
}

/** Return unique deterministic indicators found in message text. */
export function analyzeMessage(message) {
  if (typeof message !== "string") {
    throw new TypeError("Message must be a string.");
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    throw new RangeError(`Message must not exceed ${MAX_MESSAGE_LENGTH} characters.`);
  }

  const text = message.trim();
  if (!text) return [];

  const findings = new Map();
  for (const rule of RULES) {
    const match = rule.pattern.exec(text);
    if (!match || isNegated(text, match.index, match[0])) continue;

    // The two credential rules describe the same core risk. Report it once.
    if (rule.code === "credential_request_indirect" && findings.has("credential_request")) {
      continue;
    }
    if (rule.code === "credential_request" && findings.has("credential_request_indirect")) {
      findings.delete("credential_request_indirect");
    }

    findings.set(rule.code, makeFinding(rule));
  }

  return [...findings.values()];
}

export const MESSAGE_MAX_LENGTH = MAX_MESSAGE_LENGTH;
