export interface SignatureAgentCard {
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  "expected-user-agent"?: string;
  "rfc9309-product-token"?: string;
  "rfc9309-compliance"?: string[];
  trigger?: "fetcher" | "crawler";
  purpose?: string;
  "targeted-content"?: string;
  "rate-control"?: string;
  "rate-expectation"?: string;
  "known-urls"?: string[];
  jwks_uri?: string;
  ips_uri?: string;
  keys?: unknown[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringArray(value: unknown, field: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (
    !Array.isArray(value) ||
    !value.every((entry) => typeof entry === "string")
  ) {
    throw new Error(`${field} must be an array of strings`);
  }
  return value;
}

function uriArray(value: unknown, field: string): string[] | undefined {
  const values = stringArray(value, field);
  if (values === undefined) {
    return undefined;
  }
  for (const uri of values) {
    new URL(uri);
  }
  return values;
}

function stringValue(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  return value;
}

function urlValue(
  value: unknown,
  field: string,
  allowedSchemes: string[]
): string | undefined {
  const parsed = stringValue(value, field);
  if (parsed === undefined) {
    return undefined;
  }
  const url = new URL(parsed);
  if (!allowedSchemes.includes(url.protocol.slice(0, -1))) {
    throw new Error(`${field} must use one of: ${allowedSchemes.join(", ")}`);
  }
  return parsed;
}

function clientURIValue(value: unknown): string | undefined {
  const parsed = stringValue(value, "client_uri");
  if (parsed === undefined) {
    return undefined;
  }
  const url = new URL(parsed);
  if (url.protocol === "data:") {
    if (
      !parsed.startsWith("data:text/plain,") &&
      !parsed.startsWith("data:text/plain;")
    ) {
      throw new Error("client_uri data URL must use text/plain");
    }
    return parsed;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("client_uri must use one of: http, https, data:text/plain");
  }
  return parsed;
}

function stripRegistryComment(line: string): string {
  for (let index = 0; index < line.length; index += 1) {
    if (
      line.charAt(index) === "#" &&
      (index === 0 || /\s/.test(line.charAt(index - 1)))
    ) {
      return line.slice(0, index).trim();
    }
  }
  return line.trim();
}

/**
 * Parse a draft-meunier-webbotauth-registry-02 registry.
 *
 * This implementation intentionally supports only HTTP(S) card URLs. Inline
 * data: cards are not supported by this package.
 */
export function parseRegistry(registry: string): URL[] {
  const entries: URL[] = [];
  for (const [index, rawLine] of registry.split(/\r\n|\n|\r/).entries()) {
    const line = stripRegistryComment(rawLine);
    if (line === "") {
      continue;
    }

    let url: URL;
    try {
      url = new URL(line);
    } catch (error) {
      throw new Error(`registry line ${index + 1} is not a URL`, {
        cause: error,
      });
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`registry line ${index + 1} uses unsupported scheme`);
    }
    entries.push(url);
  }
  return entries;
}

export function parseSignatureAgentCard(input: unknown): SignatureAgentCard {
  if (!isRecord(input)) {
    throw new Error("signature agent card must be an object");
  }
  if (Object.keys(input).length === 0) {
    throw new Error("signature agent card must contain at least one parameter");
  }

  const card: SignatureAgentCard = {};
  card.client_name = stringValue(input.client_name, "client_name");
  card.client_uri = clientURIValue(input.client_uri);
  card.logo_uri = urlValue(input.logo_uri, "logo_uri", [
    "http",
    "https",
    "data",
  ]);
  card.contacts = uriArray(input.contacts, "contacts");
  card["expected-user-agent"] = stringValue(
    input["expected-user-agent"],
    "expected-user-agent"
  );
  card["rfc9309-product-token"] = stringValue(
    input["rfc9309-product-token"],
    "rfc9309-product-token"
  );
  card["rfc9309-compliance"] = stringArray(
    input["rfc9309-compliance"],
    "rfc9309-compliance"
  );

  const trigger = stringValue(input.trigger, "trigger");
  if (trigger !== undefined) {
    if (trigger !== "fetcher" && trigger !== "crawler") {
      throw new Error("trigger must be fetcher or crawler");
    }
    card.trigger = trigger;
  }

  card.purpose = stringValue(input.purpose, "purpose");
  card["targeted-content"] = stringValue(
    input["targeted-content"],
    "targeted-content"
  );
  card["rate-control"] = stringValue(input["rate-control"], "rate-control");
  card["rate-expectation"] = stringValue(
    input["rate-expectation"],
    "rate-expectation"
  );
  card["known-urls"] = stringArray(input["known-urls"], "known-urls");
  card.jwks_uri = urlValue(input.jwks_uri, "jwks_uri", ["https"]);
  card.ips_uri = urlValue(input.ips_uri, "ips_uri", ["https"]);

  if (input.keys !== undefined) {
    if (!Array.isArray(input.keys)) {
      throw new Error("keys must be an array");
    }
    card.keys = input.keys;
  }

  return card;
}
