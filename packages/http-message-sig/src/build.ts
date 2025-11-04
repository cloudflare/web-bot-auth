import {
  Component,
  Parameters,
  RequestLike,
  ResponseLike,
  StructuredFieldComponent,
} from "./types";

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
    case "@request-response":
      throw new Error(`${component} is not implemented yet`);
    default:
      throw new Error(`Unknown specialty component ${component}`);
  }
}

const componentToString = (component: Component): string => {
  if (typeof component === "string") {
    return `"${component}"`.toLowerCase();
  }
  return `"${component.header}";key="${component.key}"`.toLocaleLowerCase();
};

export function buildSignatureInputString(
  componentNames: Component[],
  parameters: Parameters
): string {
  const components = componentNames.map(componentToString).join(" ");
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
  request: RequestLike | ResponseLike,
  components: Component[],
  signatureInputString: string
): string {
  const parts = components.map((component) => {
    let value: string;
    if (typeof component !== "string") {
      value = extractStructuredFieldDictionaryHeader(request, component);
    } else if (component.startsWith("@")) {
      value = extractComponent(request, component);
    } else {
      value = extractHeader(request, component);
    }
    return `${componentToString(component)}: ${value}`;
  });
  parts.push(`"@signature-params": ${signatureInputString}`);
  return parts.join("\n");
}
