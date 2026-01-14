import {
  Component,
  ComponentWithParameters,
  Parameters,
  RequestLike,
  ResponseLike,
  ResponseRequestPair,
} from "./types";
import { serializeItem } from "structured-headers";

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
    const url = new URL(message.url, baseUrl);
    url.pathname = decodeURIComponent(url.pathname);
    return new URL(url.href);
  }
  if (!(message as RequestLike).url)
    throw new Error(`${component} is only valid for requests`);
  const url = new URL((message as RequestLike).url);
  url.pathname = decodeURIComponent(url.pathname);
  return new URL(url.href);
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

export function serializeComponent(cwp: Component): string {
  if (componentHasParameters(cwp)) {
    return serializeItem(`${cwp.name.toLowerCase()}`, cwp.parameters);
  }

  return `"${cwp.toLowerCase()}"`;
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
    const componentName = componentHasParameters(component)
      ? component.name
      : component;
    const value = componentName.startsWith("@")
      ? extractComponent(messageToUse, componentName)
      : extractHeader(messageToUse, componentName);
    return `${serializeComponent(component)}: ${value}`;
  });
  parts.push(`"@signature-params": ${signatureInputString}`);
  return parts.join("\n");
}
