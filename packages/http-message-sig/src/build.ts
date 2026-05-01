import {
  Component,
  ComponentWithParameters,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
  StructuredFieldComponent,
} from "./types";
import { serializeItem } from "structured-headers";

/**
 * Extract a value from a dictionary-style header by key.
 *
 * WARNING: This is a best-effort parser that does NOT conform to RFC 8941.
 * It splits on commas and equals signs, which will misparse values containing
 * commas in quoted strings, inner lists, or base64 sequences. It also does
 * not unescape escaped quotes (\\") or validate key syntax.
 * Use only for headers with simple dictionary values where keys map to
 * quoted strings or bare tokens without commas.
 */
export function extractStructuredFieldDictionaryHeader(
  r: RequestLike | ResponseLike,
  component: StructuredFieldComponent
): string {
  const headerValue = extractHeader(r, component.header);
  if (!headerValue) return headerValue;

  const items = headerValue.split(",").map((item) => item.trim());
  for (const item of items) {
    const [key, ...rest] = item.split("=");
    if (key === component.key) {
      return rest.join("=").replace(/^"|"$/g, "");
    }
  }
  return "";
}

export function extractHeader(
  { headers }: RequestLike | ResponseLike,
  header: string
): string {
  if (typeof headers.get === "function") return headers.get(header) ?? "";

  const lcHeader = header.toLowerCase();
  const key = Object.keys(headers).find(
    (name) => name.toLowerCase() === lcHeader
  );
  // eslint-disable-next-line security/detect-object-injection
  let val = key ? (headers[key] ?? "") : "";
  if (Array.isArray(val)) {
    val = val.join(", ");
  }
  return val.toString().replace(/\s+/g, " ");
}

export function getUrl(
  message: RequestLike | ResponseLike,
  component: string
): URL {
  if ("url" in message && "protocol" in message) {
    const host = extractHeader(message, "host");
    const protocol = message.protocol || "http";
    const baseUrl = `${protocol}://${host}`;
    return new URL(message.url, baseUrl);
  }
  if (!(message as RequestLike).url)
    throw new Error(`${component} is only valid for requests`);
  return new URL((message as RequestLike).url);
}

// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-06#section-2.3
export function extractComponent(
  message: RequestLike | ResponseLike,
  component: string
): string {
  switch (component) {
    case "@method":
      if (!(message as RequestLike).method)
        throw new Error(`${component} is only valid for requests`);
      return (message as RequestLike).method.toUpperCase();
    case "@target-uri":
      if (!(message as RequestLike).url)
        throw new Error(`${component} is only valid for requests`);
      return (message as RequestLike).url;
    case "@authority": {
      const url = getUrl(message, component);
      const port = url.port ? parseInt(url.port, 10) : null;
      return `${url.hostname}${port && ![80, 443].includes(port) ? `:${port}` : ""}`;
    }
    case "@scheme":
      return getUrl(message, component).protocol.slice(0, -1);
    case "@request-target": {
      const { pathname, search } = getUrl(message, component);
      return `${pathname}${search}`;
    }
    case "@path":
      return getUrl(message, component).pathname;
    case "@query":
      return getUrl(message, component).search;
    case "@status":
      if (!(message as ResponseLike).status)
        throw new Error(`${component} is only valid for responses`);
      return (message as ResponseLike).status.toString();
    case "@query-params":
      throw new Error(`${component} is not implemented yet`);
    default:
      throw new Error(`Unknown specialty component ${component}`);
  }
}

export function isStructuredFieldComponent(
  component: Component
): component is StructuredFieldComponent {
  return (component as StructuredFieldComponent).header !== undefined;
}

export function serializeComponent(cwp: Component): string {
  if (typeof cwp === "string") {
    return `"${cwp.toLowerCase()}"`;
  }

  if (isStructuredFieldComponent(cwp)) {
    return `"${cwp.header.toLowerCase()}";key="${cwp.key}"`;
  }

  return serializeItem(`${cwp.name.toLowerCase()}`, cwp.parameters);
}

export function isRawMessage(
  message: RequestLike | ResponseLike | ResponseRequestPair
): message is RequestLike | ResponseLike {
  return (
    (message as ResponseRequestPair).response === undefined &&
    (message as ResponseRequestPair).request === undefined
  );
}

export function componentHasParameters(
  component: Component
): component is ComponentWithParameters {
  return (component as ComponentWithParameters).parameters !== undefined;
}

export function resolveMessageKind(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  cwp?: Component
): RequestLike | ResponseLike {
  let requiresReq = false;
  if (cwp !== undefined && componentHasParameters(cwp)) {
    requiresReq = cwp.parameters.has("req");
  }

  if (isRawMessage(message)) {
    if (requiresReq) {
      throw new Error(
        "`req` component parameter can only be used with ResponseRequestPair message types"
      );
    }

    return message;
  }

  if (requiresReq) {
    return message.request;
  }

  return message.response;
}

export function buildSignatureInputString(
  componentNames: Component[],
  parameters: Parameters
): string {
  const components = componentNames.map(serializeComponent).join(" ");
  const values = Object.entries(parameters)
    .map(([parameter, value]) => {
      if (typeof value === "number") return `;${parameter}=${value}`;
      if (value instanceof Date)
        return `;${parameter}=${Math.floor(value.getTime() / 1000)}`;
      return `;${parameter}="${value.toString()}"`;
    })
    .join("");

  return `(${components})${values}`;
}

export function buildSignedData(
  message: RequestLike | ResponseLike | ResponseRequestPair,
  components: Component[],
  signatureInputString: string
): string {
  const parts = components.map((component) => {
    const messageToUse = resolveMessageKind(message, component);
    let value: string;

    if (typeof component === "string") {
      value = component.startsWith("@")
        ? extractComponent(messageToUse, component)
        : extractHeader(messageToUse, component);
    } else if (isStructuredFieldComponent(component)) {
      value = extractStructuredFieldDictionaryHeader(messageToUse, component);
    } else {
      const componentName = component.name;
      value = componentName.startsWith("@")
        ? extractComponent(messageToUse, componentName)
        : extractHeader(messageToUse, componentName);
    }

    return `${serializeComponent(component)}: ${value}`;
  });
  parts.push(`"@signature-params": ${signatureInputString}`);
  return parts.join("\n");
}
