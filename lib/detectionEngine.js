import { analyzeMessage } from "./messageRules.js";
import { analyzeUrl, extractUrls } from "./urlRules.js";
import { calculateRisk, recommendationFor } from "./riskScoring.js";

const MAX_MESSAGE_LENGTH = 2_000;
const MAX_URL_LENGTH = 2_048;

function mergeIndicators(indicators) {
  const merged = new Map();
  for (const item of indicators) {
    const existing = merged.get(item.code);
    if (!existing) {
      merged.set(item.code, { ...item, occurrences: 1 });
    } else {
      existing.occurrences += 1;
    }
  }
  return [...merged.values()];
}

/**
 * Shared interface for the backend.
 * Input:  { type: "message" | "url", content: string }
 * Output: { type, riskLevel, score, indicators, recommendation, disclaimer }
 */
export function analyzeInput({ type, content } = {}) {
  if (type !== "message" && type !== "url") {
    throw new TypeError('type must be either "message" or "url".');
  }
  if (typeof content !== "string") {
    throw new TypeError("content must be a string.");
  }
  const limit = type === "message" ? MAX_MESSAGE_LENGTH : MAX_URL_LENGTH;
  if (content.length > limit) {
    throw new RangeError(`content must not exceed ${limit} characters.`);
  }
  if (!content.trim()) {
    throw new TypeError("content must not be empty.");
  }

  let indicators;
  if (type === "url") {
    indicators = analyzeUrl(content);
  } else {
    indicators = [...analyzeMessage(content)];
    // A suspicious message may include a link, so inspect URL text locally as well.
    // No destination is fetched or opened.
    const urls = extractUrls(content).slice(0, 5);
    for (const url of urls) {
      indicators.push(...analyzeUrl(url));
    }
  }

  const uniqueIndicators = mergeIndicators(indicators);
  const { score, riskLevel, explanation } = calculateRisk(uniqueIndicators);

  return {
    type,
    riskLevel,
    score,
    indicators: uniqueIndicators,
    recommendation: recommendationFor(uniqueIndicators, riskLevel),
    disclaimer: explanation,
  };
}

export { analyzeMessage } from "./messageRules.js";
export { analyzeUrl, extractUrls } from "./urlRules.js";
export { calculateRisk, recommendationFor } from "./riskScoring.js";
