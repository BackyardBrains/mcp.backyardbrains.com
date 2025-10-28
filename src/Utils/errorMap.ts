export function mapErrorToMessage(err: any): string {
  const status = err?.response?.status || err?.statusCode || err?.status;
  if (status === 401) return "Unauthorized with Xero";
  if (status === 403) return "Forbidden by Xero";
  if (status === 404) return "Resource not found";
  if (status === 429) return "Rate limit exceeded. Please retry later.";
  if (status && status >= 500) return "Xero service error. Please try again later.";

  const message = err?.response?.data?.message || err?.message || String(err);
  // Ensure we do not leak secrets
  return `${message}`.replace(/(client_secret|refresh_token|access_token)=[^&\s]+/gi, "$1=[REDACTED]");
}


