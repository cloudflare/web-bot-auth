import { parseDictionary, parseItem } from "structured-headers";

export type SignatureAgentDiscoveryType = "directory" | "jwks_uri" | "cimd";

export interface SignatureAgentEntry {
  label: string;
  uri: string;
  type: SignatureAgentDiscoveryType;
}

export type SignatureAgentHeader =
  | {
      kind: "current";
      entries: SignatureAgentEntry[];
    }
  | {
      kind: "legacy";
      entries: SignatureAgentEntry[];
    };

export interface JSONWebKeySet {
  keys: JsonWebKey[];
}

export interface WebBotAuthMetadata {
  "expected-user-agent"?: string;
  "rfc9309-product-token"?: string;
  "rfc9309-compliance"?: string[];
  trigger?: "fetcher" | "crawler";
  purpose?: string;
  "targeted-content"?: string;
  "rate-control"?: string;
  "rate-expectation"?: string;
  "known-urls"?: string[];
  ips_uri?: string;
}

export interface SignatureAgentCard {
  client_id?: string;
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  jwks_uri?: string;
  jwks?: JSONWebKeySet;
  ips_uri?: string;
  web_bot_auth?: WebBotAuthMetadata;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function stringArray(value: unknown, field: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array of strings`);
  }
  const output: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      throw new Error(`${field} must be an array of strings`);
    }
    output.push(entry);
  }
  return output;
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

function urlValue(
  value: unknown,
  field: string,
  allowedProtocols: string[]
): string | undefined {
  const parsed = stringValue(value, field);
  if (parsed === undefined) {
    return undefined;
  }
  const url = new URL(parsed);
  if (!allowedProtocols.includes(url.protocol)) {
    throw new Error(`${field} must use one of: ${allowedProtocols.join(", ")}`);
  }
  return parsed;
}

function jwksValue(value: unknown): JSONWebKeySet | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value) || !Array.isArray(value.keys)) {
    throw new Error("jwks must be a JWK Set");
  }
  const keys: JsonWebKey[] = [];
  for (const key of value.keys) {
    if (!isRecord(key)) {
      throw new Error("jwks keys must be objects");
    }
    keys.push(key);
  }
  return { keys };
}

function triggerValue(value: unknown): "fetcher" | "crawler" | undefined {
  const parsed = stringValue(value, "trigger");
  if (parsed === undefined) {
    return undefined;
  }
  if (parsed === "fetcher" || parsed === "crawler") {
    return parsed;
  }
  throw new Error("trigger must be fetcher or crawler");
}

function discoveryType(value: unknown): SignatureAgentDiscoveryType {
  const typeName = value === undefined ? "directory" : String(value);
  if (typeName === "directory") {
    return "directory";
  }
  if (typeName === "jwks_uri" || typeName === "cimd") {
    return typeName;
  }
  throw new Error(`unsupported Signature-Agent type ${typeName}`);
}

function validateDiscoveryURI(uri: string, type: SignatureAgentDiscoveryType) {
  const url = new URL(uri);
  if (type === "directory") {
    if (url.protocol === "http:" || url.protocol === "https:") {
      return;
    }
    throw new Error("directory Signature-Agent must use http or https");
  }
  if (url.protocol !== "https:") {
    throw new Error(`${type} Signature-Agent must use https`);
  }
}

export function parseSignatureAgentHeader(
  header: string
): SignatureAgentHeader {
  try {
    const dictionary = parseDictionary(header);
    if (dictionary.size === 0) {
      throw new Error("Signature-Agent header must not be empty");
    }
    const entries: SignatureAgentEntry[] = [];
    for (const [label, value] of dictionary) {
      const [uri, params] = value;
      if (typeof uri !== "string") {
        throw new Error("Signature-Agent values must be strings");
      }
      const type = discoveryType(params.get("type"));
      validateDiscoveryURI(uri, type);
      entries.push({ label, uri, type });
    }
    return { kind: "current", entries };
  } catch (dictionaryError) {
    try {
      const [uri] = parseItem(header);
      if (typeof uri !== "string") {
        throw new Error("legacy Signature-Agent must be a string");
      }
      validateDiscoveryURI(uri, "directory");
      return {
        kind: "legacy",
        entries: [{ label: "", uri, type: "directory" }],
      };
    } catch (itemError) {
      throw new Error(
        `failed to parse Signature-Agent header: ${errorMessage(dictionaryError)}; ${errorMessage(itemError)}`
      );
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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

export function parseRegistry(registry: string): URL[] {
  const entries: URL[] = [];
  for (const [index, rawLine] of registry.split(/\r\n|\n|\r/).entries()) {
    const line = stripRegistryComment(rawLine);
    if (line === "") {
      continue;
    }
    const url = new URL(line);
    if (url.protocol === "data:") {
      throw new Error("inline signature agent cards are not supported");
    }
    if (url.protocol !== "https:") {
      throw new Error(
        `registry line ${index + 1}: registry entries must use https`
      );
    }
    entries.push(url);
  }
  return entries;
}

function webBotAuthValue(value: unknown): WebBotAuthMetadata | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isRecord(value)) {
    throw new Error("web_bot_auth must be an object");
  }
  const metadata: WebBotAuthMetadata = {
    "expected-user-agent": stringValue(
      value["expected-user-agent"],
      "expected-user-agent"
    ),
    "rfc9309-product-token": stringValue(
      value["rfc9309-product-token"],
      "rfc9309-product-token"
    ),
    "rfc9309-compliance": stringArray(
      value["rfc9309-compliance"],
      "rfc9309-compliance"
    ),
    trigger: triggerValue(value.trigger),
    purpose: stringValue(value.purpose, "purpose"),
    "targeted-content": stringValue(
      value["targeted-content"],
      "targeted-content"
    ),
    "rate-control": stringValue(value["rate-control"], "rate-control"),
    "rate-expectation": stringValue(
      value["rate-expectation"],
      "rate-expectation"
    ),
    "known-urls": stringArray(value["known-urls"], "known-urls"),
    ips_uri: urlValue(value.ips_uri, "ips_uri", ["https:"]),
  };
  return Object.fromEntries(
    Object.entries(metadata).filter((entry) => entry[1] !== undefined)
  );
}

export function parseSignatureAgentCard(
  input: unknown,
  cardURL?: string
): SignatureAgentCard {
  if (!isRecord(input)) {
    throw new Error("signature agent card must be an object");
  }

  const card: SignatureAgentCard = {
    client_id: urlValue(input.client_id, "client_id", ["https:"]),
    client_name: stringValue(input.client_name, "client_name"),
    client_uri: urlValue(input.client_uri, "client_uri", ["http:", "https:"]),
    logo_uri: urlValue(input.logo_uri, "logo_uri", [
      "http:",
      "https:",
      "data:",
    ]),
    contacts: uriArray(input.contacts, "contacts"),
    jwks_uri: urlValue(input.jwks_uri, "jwks_uri", ["https:"]),
    jwks: jwksValue(input.jwks),
    ips_uri: urlValue(input.ips_uri, "ips_uri", ["https:"]),
    web_bot_auth: webBotAuthValue(input.web_bot_auth),
  };

  if (card.jwks !== undefined && card.jwks_uri !== undefined) {
    throw new Error("card must not contain both jwks and jwks_uri");
  }
  if (card.jwks === undefined && card.jwks_uri === undefined) {
    throw new Error("card must contain either jwks or jwks_uri");
  }
  if (cardURL !== undefined && card.client_id === undefined) {
    throw new Error("client_id is required when card URL is known");
  }
  if (
    cardURL !== undefined &&
    card.client_id !== undefined &&
    card.client_id !== cardURL
  ) {
    throw new Error("client_id must match the card URL");
  }

  const output = Object.fromEntries(
    Object.entries(card).filter((entry) => entry[1] !== undefined)
  );
  if (Object.keys(output).length === 0) {
    throw new Error("signature agent card must contain at least one parameter");
  }
  return output;
}
