const HTML_TAG_PATTERN = /<[^>]*>/g;
const SCRIPT_URI_PATTERN = /javascript:/gi;
const EVENT_HANDLER_PATTERN = /on\w+\s*=/gi;
const DANGEROUS_CHAR_PATTERN = /[<>"'`\\]/g;

/**
 * Strip XSS vectors from telemetry strings before they enter React state.
 */
export function sanitizeTelemetryString(value: unknown, maxLength = 256): string {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .slice(0, maxLength)
    .replace(HTML_TAG_PATTERN, "")
    .replace(SCRIPT_URI_PATTERN, "")
    .replace(EVENT_HANDLER_PATTERN, "")
    .replace(DANGEROUS_CHAR_PATTERN, "");
}

export function sanitizeSpiffeId(value: unknown): string | null {
  const sanitized = sanitizeTelemetryString(value, 512);
  if (!sanitized.startsWith("spiffe://")) {
    return null;
  }

  return sanitized;
}

export function sanitizeIdentifier(value: unknown, maxLength = 128): string | null {
  const sanitized = sanitizeTelemetryString(value, maxLength);
  if (!/^[a-zA-Z0-9._:/-]+$/.test(sanitized)) {
    return null;
  }

  return sanitized;
}
