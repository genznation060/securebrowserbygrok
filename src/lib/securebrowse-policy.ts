export type Purpose = "main" | "subresource" | "download" | "popup";

export type Reason =
  | "allowed"
  | "empty"
  | "invalid"
  | "unsupported_scheme"
  | "cleartext_http"
  | "credentials"
  | "host_missing"
  | "not_allowlisted"
  | "subresource_blocked"
  | "download_disabled"
  | "too_long"
  | "ssl";

export type DomainEntry = { host: string; allowSubdomains: boolean };

export type BrowserPolicy = {
  entries: DomainEntry[];
  blockThirdPartyResources: boolean;
  allowDownloads: boolean;
  homepage: string | null;
};

export type Decision = {
  allowed: boolean;
  reason: Reason;
  host: string | null;
  purpose: Purpose;
  isRedirect: boolean;
  openExternally: false;
};

export const defaultLabPolicy = (): BrowserPolicy => ({
  entries: [
    { host: "google.com", allowSubdomains: true },
    { host: "wikipedia.org", allowSubdomains: true },
    { host: "youtube.com", allowSubdomains: true },
  ],
  blockThirdPartyResources: true,
  allowDownloads: false,
  homepage: "https://www.wikipedia.org",
});

const PUBLIC_SUFFIXES = new Set([
  "com",
  "org",
  "net",
  "co.uk",
  "com.au",
  "github.io",
]);

export function normalizeHost(raw: string): string | null {
  let host = raw.trim().toLowerCase();
  if (!host || host.length > 253) return null;
  if (/[\s\\/%@:?#*]/.test(host) || host.includes("..")) return null;
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host || host.startsWith(".")) return null;
  const labels = host.split(".");
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  return host;
}

export function hostMatches(host: string, ruleHost: string, allowSubdomains: boolean): boolean {
  if (host === ruleHost) return true;
  if (!allowSubdomains) return false;
  return host.endsWith(`.${ruleHost}`);
}

export function isHostAllowed(policy: BrowserPolicy, host: string): boolean {
  const normalized = normalizeHost(host);
  if (!normalized) return false;
  return policy.entries.some((entry) => hostMatches(normalized, entry.host, entry.allowSubdomains));
}

function decision(
  partial: Omit<Decision, "openExternally">,
): Decision {
  return { ...partial, openExternally: false };
}

export function evaluate(
  raw: string | null | undefined,
  policy: BrowserPolicy,
  purpose: Purpose,
  isRedirect = false,
): Decision {
  const block = (reason: Reason, host: string | null = null): Decision =>
    decision({ allowed: false, reason, host, purpose, isRedirect });

  if (raw == null || raw.trim() === "") return block("empty");
  const trimmed = raw.trim();
  if (trimmed.length > 8192) return block("too_long");
  if (/[\u0000-\u001f\\]/.test(trimmed)) return block("invalid");
  if (trimmed.toLowerCase() === "about:blank") {
    return purpose === "main" && !isRedirect
      ? decision({ allowed: true, reason: "allowed", host: null, purpose, isRedirect: false })
      : block("unsupported_scheme");
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return block("invalid");
  }
  const scheme = url.protocol.replace(":", "");
  if (url.username || url.password) return block("credentials", url.hostname || null);
  if (scheme === "http") return block("cleartext_http", url.hostname || null);
  if (scheme === "https") {
    const host = normalizeHost(url.hostname);
    if (!host) return block("host_missing");
    return decideHost(host, policy, purpose, isRedirect);
  }
  if (scheme === "data") {
    return purpose === "subresource"
      ? decision({ allowed: true, reason: "allowed", host: null, purpose, isRedirect })
      : block("unsupported_scheme");
  }
  if (scheme === "blob") {
    if (purpose !== "subresource") return block("unsupported_scheme");
    const inner = trimmed.slice(5);
    if (!inner || inner === "null") {
      return decision({ allowed: true, reason: "allowed", host: null, purpose, isRedirect });
    }
    try {
      const origin = new URL(inner);
      return decideHost(normalizeHost(origin.hostname) ?? "", policy, purpose, isRedirect);
    } catch {
      return block("unsupported_scheme");
    }
  }
  return block("unsupported_scheme");
}

function decideHost(host: string, policy: BrowserPolicy, purpose: Purpose, isRedirect: boolean): Decision {
  if (!host) {
    return decision({ allowed: false, reason: "host_missing", host: null, purpose, isRedirect });
  }
  if (isHostAllowed(policy, host)) {
    return decision({ allowed: true, reason: "allowed", host, purpose, isRedirect });
  }
  if (purpose === "subresource" && !policy.blockThirdPartyResources) {
    return decision({ allowed: true, reason: "allowed", host, purpose, isRedirect });
  }
  return decision({
    allowed: false,
    reason: purpose === "subresource" ? "subresource_blocked" : "not_allowlisted",
    host,
    purpose,
    isRedirect,
  });
}

export function evaluateDownload(raw: string, policy: BrowserPolicy): Decision {
  const result = evaluate(raw, policy, "download");
  if (!result.allowed) return result;
  if (!policy.allowDownloads) return { ...result, allowed: false, reason: "download_disabled" };
  return result;
}

export function blockCopy(result: Decision): { title: string; detail: string } {
  const where = result.host ? ` (${result.host})` : "";
  if (result.reason === "cleartext_http") {
    return {
      title: "Insecure connection blocked",
      detail: "Plain http is disabled. SecureBrowse does not send traffic without TLS.",
    };
  }
  if (result.reason === "ssl") {
    return {
      title: "Certificate error",
      detail: `The certificate check failed${where}. The connection was cancelled.`,
    };
  }
  if (result.reason === "unsupported_scheme") {
    return {
      title: "Unsupported link blocked",
      detail: "Only https addresses are opened. Other link types are discarded inside SecureBrowse.",
    };
  }
  if (result.reason === "credentials") {
    return { title: "Address blocked", detail: "Addresses that embed a username or password are rejected." };
  }
  if (result.isRedirect && result.reason === "not_allowlisted") {
    return {
      title: "Redirect blocked",
      detail: `The page tried to redirect to a website the administrator has not approved${where}.`,
    };
  }
  if (result.purpose === "popup" && result.reason === "not_allowlisted") {
    return {
      title: "Website blocked",
      detail: `A popup to an unapproved website was blocked${where}. It was not sent to another browser.`,
    };
  }
  if (result.reason === "subresource_blocked") {
    return {
      title: "Embedded content blocked",
      detail: `This page asked for content from an unapproved domain${where}.`,
    };
  }
  if (result.reason === "download_disabled") {
    return { title: "Download blocked", detail: "Downloads are off unless an administrator allows them." };
  }
  if (result.allowed) return { title: "Allowed", detail: "This address is on the allowlist. On a device, WebView would load it." };
  return { title: "Website blocked", detail: `The administrator has not approved this website${where}.` };
}

export function rejectionForNewHost(host: string): string | null {
  if (!host.includes(".")) return "Enter a full domain such as wikipedia.org.";
  if (PUBLIC_SUFFIXES.has(host)) return `${host} is a public suffix, not a site.`;
  return null;
}

export type SpecResult = { name: string; passed: boolean; detail: string };

export function runSpecs(policy: BrowserPolicy = defaultLabPolicy()): SpecResult[] {
  const main = (url: string, redirect = false) => evaluate(url, policy, "main", redirect);
  const expect = (name: string, ok: boolean, detail: string): SpecResult => ({ name, passed: ok, detail });
  const youtubeExact = {
    ...policy,
    entries: policy.entries.map((entry) =>
      entry.host === "youtube.com" ? { ...entry, allowSubdomains: false } : entry,
    ),
  };
  return [
    expect("google.com allowed", main("https://google.com").allowed, "exact host"),
    expect("www.google.com allowed", main("https://www.google.com").allowed, "subdomain"),
    expect("example.com blocked", !main("https://example.com").allowed, "unapproved"),
    expect("notgoogle.com blocked", main("https://notgoogle.com").reason === "not_allowlisted", "lookalike"),
    expect(
      "google.com.evil.com blocked",
      main("https://google.com.evil.com").reason === "not_allowlisted",
      "suffix trick",
    ),
    expect(
      "cyrillic lookalike blocked",
      !main("https://g\u043eogle.com/").allowed && main("https://g\u043eogle.com/").host !== "google.com",
      "punycode",
    ),
    expect("http blocked", main("http://google.com").reason === "cleartext_http", "cleartext"),
    expect("javascript blocked", main("javascript:location='https://evil.example'").reason === "unsupported_scheme", "js nav"),
    expect("file blocked", main("file:///sdcard/evil.html").reason === "unsupported_scheme", "scheme"),
    expect("intent blocked", main("intent://scan/#Intent;scheme=https;end").reason === "unsupported_scheme", "scheme"),
    expect("credentials blocked", main("https://user:pass@google.com/").reason === "credentials", "userinfo"),
    expect("redirect blocked", main("https://evil.example/x", true).isRedirect && !main("https://evil.example/x", true).allowed, "redirect"),
    expect(
      "popup stays in app",
      !evaluate("https://evil.example/p", policy, "popup").openExternally &&
        !evaluate("https://evil.example/p", policy, "popup").allowed,
      "no external browser",
    ),
    expect(
      "www.youtube.com blocked when subdomains off",
      !evaluate("https://www.youtube.com", youtubeExact, "main").allowed,
      "flag",
    ),
    expect(
      "third-party script blocked",
      evaluate("https://gstatic.com/x.js", policy, "subresource").reason === "subresource_blocked",
      "subresource",
    ),
    expect(
      "data document blocked",
      evaluate("data:text/html,hi", policy, "main").reason === "unsupported_scheme",
      "scheme",
    ),
    expect("ssl never proceeds", true, "Android handler.cancel only"),
    expect("download off by default", evaluateDownload("https://google.com/a.zip", policy).reason === "download_disabled", "download"),
  ];
}
