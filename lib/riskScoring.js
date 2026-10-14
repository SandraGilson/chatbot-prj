/**
 * Preliminary heuristic scoring. Thresholds are not validated security metrics.
 * Risk level is an indicator summary, not a probability of fraud.
 */
const LEVELS = {
  inconclusive: { max: 0 },
  low: { max: 1 },
  medium: { max: 3 },
  high: { max: Number.POSITIVE_INFINITY },
};

export function calculateRisk(indicators = []) {
  if (!Array.isArray(indicators)) {
    throw new TypeError("Indicators must be an array.");
  }

  // Count each indicator code once to avoid inflating a score when a phrase repeats.
  const seen = new Set();
  let score = 0;
  for (const indicator of indicators) {
    if (!indicator || typeof indicator.code !== "string" || seen.has(indicator.code)) continue;
    seen.add(indicator.code);
    const points = Number(indicator.points);
    if (Number.isFinite(points) && points > 0) score += points;
  }

  let riskLevel = "high";
  for (const [level, config] of Object.entries(LEVELS)) {
    if (score <= config.max) {
      riskLevel = level;
      break;
    }
  }

  return {
    score,
    riskLevel,
    explanation: score === 0
      ? "No configured warning indicators were found. This is inconclusive, not proof that the content is safe."
      : "This preliminary score summarizes configured warning indicators; it is not a probability of fraud.",
  };
}

export function recommendationFor(indicators, riskLevel) {
  const codes = new Set(indicators.map((item) => item.code));

  if (codes.has("credential_request") || codes.has("credential_request_indirect")) {
    return "Do not share passwords, OTPs, PINs, CVVs, or recovery codes. Verify the request using the service's official app or a contact method you already trust.";
  }
  if (codes.has("upfront_payment")) {
    return "Do not pay solely because of this message. Independently verify the organization and any fee through its official channels.";
  }
  if (riskLevel === "high") {
    return "Do not click links or provide information yet. Verify the sender and destination through an independently known official channel.";
  }
  if (riskLevel === "medium") {
    return "Pause before acting. Check the sender, claims, and destination independently; do not share credentials or payment details based on this message alone.";
  }
  if (riskLevel === "low") {
    return "A limited warning indicator was found. Inspect the context and verify the sender before taking action.";
  }
  return "No configured warning indicators were found, but this checker cannot prove a message or URL is safe. Verify unexpected requests independently.";
}
