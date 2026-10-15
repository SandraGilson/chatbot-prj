import { isIP } from "node:net";

const MAX_URL_LENGTH = 2_048;
const SHORTENER_HOSTS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
  "tiny.cc", "rebrand.ly", "shorturl.at", "ow.ly", "buff.ly", "rb.gy",
]);

// This is a small heuristic list, not a complete or authoritative brand registry.
// A match is a warning for manual verification, not a claim that a site is fake.
const BRAND_ROOTS = [
  { brand: "PayPal", token: "paypal", roots: ["paypal.com", "paypal.me"] },
  { brand: "Google", token: "google", roots: ["google.com", "google.co.in", "google.co.uk", "googleapis.com", "youtube.com"] },
  { brand: "Microsoft", token: "microsoft", roots: ["microsoft.com", "live.com", "outlook.com"] },
  { brand: "Amazon", token: "amazon", roots: ["amazon.com", "amazon.in", "amazon.co.uk"] },
  { brand: "Apple", token: "apple", roots: ["apple.com", "icloud.com"] },
  { brand: "Facebook", token: "facebook", roots: ["facebook.com", "fb.com"] },
  { brand: "Instagram", token: "instagram", roots: ["instagram.com"] },
  { brand: "Netflix", token: "netflix", roots: ["netflix.com"] },
  { brand: "State Bank of India", token: "sbi", roots: ["sbi.co.in", "onlinesbi.sbi"] },
  { brand: "HDFC Bank", token: "hdfc", roots: ["hdfcbank.com"] },
  { brand: "ICICI Bank", token: "icici", roots: ["icicibank.com"] },
  { brand: "Axis Bank", token: "axisbank", roots: ["axisbank.com"] },
];

function finding(code, name, severity, points, evidence) {
  return { code, name, severity, points, evidence, category: "url" };
}

function parseCandidate(input) {
  const candidate = input.trim();
  // Do not treat arbitrary schemes as web links. Add HTTPS only for a plain host/URL.
  const hasScheme = /^[a-z][a-z\d+.-]*:/i.test(candidate);
  const parseValue = hasScheme ? candidate : `https://${candidate}`;
  try {
    return { url: new URL(parseValue), hadScheme: hasScheme };
  } catch {
    return null;
  }
}

function isTrustedBrandHost(hostname, roots) {
  return roots.some((root) => hostname === root || hostname.endsWith(`.${root}`));
}

function containsBrandLookalike(hostname) {
  for (const brand of BRAND_ROOTS) {
    if (hostname.split(".").some((label) => label.includes(brand.token)) && !isTrustedBrandHost(hostname, brand.roots)) {
      return brand.brand;
    }
  }
  return null;
}

/**
 * Inspect URL text only. This function never makes a network request or visits the URL.
 * It returns [] for a structurally valid URL with no matched indicators, so the caller
 * can report an inconclusive result instead of claiming that it is safe.
 */
export function analyzeUrl(input) {
  if (typeof input !== "string") {
    throw new TypeError("URL must be a string.");
  }
  if (input.length > MAX_URL_LENGTH) {
    throw new RangeError(`URL must not exceed ${MAX_URL_LENGTH} characters.`);
  }
  const raw = input.trim();
  if (!raw) return [finding("invalid_url", "Missing URL", "info", 0, "No URL was provided for analysis.")];

  const parsed = parseCandidate(raw);
  if (!parsed) {
    return [finding("invalid_url", "Invalid URL format", "info", 0, "The input could not be parsed as a URL. Check the spelling and try again.")];
  }

  const { url, hadScheme } = parsed;
  const protocol = url.protocol.toLowerCase();
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const findings = [];

  if (protocol === "javascript:" || protocol === "data:") {
    findings.push(finding(
      "unsafe_scheme", "Unsupported active-content scheme", "high", 5,
      "This is not a normal HTTP/HTTPS website URL. Do not open it as a link."
    ));
    return findings;
  }

  if (protocol !== "http:" && protocol !== "https:") {
    findings.push(finding(
      "unsupported_scheme", "Unsupported URL scheme", "medium", 2,
      "Only HTTP and HTTPS website URLs are supported by this checker."
    ));
    return findings;
  }

  if (url.username || url.password) {
    findings.push(finding(
      "url_userinfo", "Credentials embedded in URL", "high", 3,
      "The URL contains text before the @ symbol that may be interpreted as user information. Verify the actual hostname carefully."
    ));
  }

  const ipVersion = isIP(hostname);
  if (ipVersion !== 0) {
    findings.push(finding(
      "ip_host", "IP address used as hostname", "medium", 3,
      `The URL host is an IP address (IPv${ipVersion}) rather than a conventional domain name.`
    ));
  }

  if (protocol === "http:") {
    findings.push(finding(
      "http_scheme", "Unencrypted HTTP connection", "low", 1,
      "The URL uses HTTP rather than HTTPS. This alone does not prove the site is malicious."
    ));
  }

  if (hostname.split(".").filter(Boolean).length >= 5) {
    findings.push(finding(
      "many_subdomains", "Unusually deep hostname", "low", 1,
      "The hostname has many dot-separated labels. Check which domain actually owns the site."
    ));
  }

  if (hostname.split(".").some((label) => label.startsWith("xn--"))) {
    findings.push(finding(
      "punycode_hostname", "Internationalized hostname", "low", 1,
      "The hostname contains a Punycode label. Internationalized domains can be legitimate, but inspect it carefully for lookalike characters."
    ));
  }

  const lookalikeBrand = containsBrandLookalike(hostname);
  if (lookalikeBrand) {
    findings.push(finding(
      "brand_lookalike", `Possible ${lookalikeBrand} lookalike domain`, "high", 4,
      `The hostname contains the name ${lookalikeBrand}, but it does not end in a configured official domain for that brand. Verify through the brand's known official website.`
    ));
  }

  if (SHORTENER_HOSTS.has(hostname)) {
    findings.push(finding(
      "url_shortener", "URL shortener hides the final destination", "low", 1,
      "The hostname belongs to a known URL-shortening service. Verify the final destination before visiting."
    ));
  }

  // Document that protocol was inferred when the user supplied only a domain.
  if (!hadScheme) {
    // This is metadata for debugging/UI, not an additional risk finding.
    Object.defineProperty(findings, "normalizedUrl", {
      value: url.href,
      enumerable: false,
      configurable: true,
    });
  }

  return findings;
}

export const URL_MAX_LENGTH = MAX_URL_LENGTH;

/** Extract common URL-like strings from a message without resolving or visiting them. */
export function extractUrls(message) {
  if (typeof message !== "string") {
    throw new TypeError("Message must be a string.");
  }
  const pattern = /(?:https?:\/\/[^\s<>"']+|www\.[^\s<>"']+|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?:\/[^\s<>"']*)?)/gi;
  const seen = new Set();
  const urls = [];
  for (const match of message.matchAll(pattern)) {
    const candidate = match[0].replace(/[),.!?;:\]}]+$/g, "");
    if (!candidate || seen.has(candidate.toLowerCase())) continue;
    // Avoid extracting ordinary email domains even if punctuation defeats the lookbehind.
    if (match.index > 0 && message[match.index - 1] === "@") continue;
    seen.add(candidate.toLowerCase());
    urls.push(candidate);
  }
  return urls;
}
