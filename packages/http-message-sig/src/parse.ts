import {
  Component,
  HeaderValue,
  Parameter,
  Parameters,
  StructuredFieldComponent,
} from "./types";
import { decode as base64Decode } from "./base64";

function parseEntry(
  headerName: string,
  entry: string
): [
  string,
  string | number | true | (string | number | StructuredFieldComponent)[],
] {
  // this is wrong. it should only split the first `=`
  const equalsIndex = entry.indexOf("=");
  if (equalsIndex === -1) {
    return [entry.trim(), true];
  }
  const key = entry.slice(0, equalsIndex);
  const value = entry.slice(equalsIndex + 1).trim();
  if (key.length === 0) {
    throw new Error(`Invalid ${headerName} header. Invalid value ${entry}`);
  }

  if (value.match(/^".*"$/)) return [key.trim(), value.slice(1, -1)];
  if (value.match(/^\d+$/)) return [key.trim(), parseInt(value)];

  // TODO: this is restricted to components array. Per RFC9421, there could be more
  if (value.match(/^\(.*\)$/)) {
    const arr = value.slice(1, -1).split(/\s+/);

    const res = [];
    for (const item of arr) {
      const match = item.match(/^"(.*)"$/);
      let toPush;
      if (!match) {
        toPush = parseInt(item);
      } else if (match[1].includes('";key="')) {
        toPush = {
          key: match[1].split('";key="')[1],
          header: match[1].split('";key="')[0],
        };
      } else {
        toPush = match[1];
      }
      res.push(toPush);
    }

    if (res.some((value) => typeof value === "number" && isNaN(value))) {
      throw new Error(
        `Invalid ${headerName} header. Invalid value ${key}=${value}`
      );
    }

    return [key.trim(), res];
  }

  throw new Error(
    `Invalid ${headerName} header. Invalid value ${key}=${value}`
  );
}

function parseParametersHeader(
  name: string,
  header: HeaderValue
): { key: string; components: Component[]; parameters: Parameters } {
  const rawHeader = header.toString();
  const [rawComponents, rawParameters] = rawHeader.split(/(?<=\))/, 2);
  const [key, components] = parseEntry(name, rawComponents.trim()) as [
    string,
    Component[],
  ];

  const entries = rawParameters
    // eslint-disable-next-line security/detect-unsafe-regex
    .match(/(?:[^;"]+|"[^"]+")+/g)
    ?.map((entry) => parseEntry(name, entry.trim()));

  if (!entries) throw new Error(`Invalid ${name} header. Invalid value`);

  const parameters = Object.fromEntries(entries) as Record<
    Parameter,
    string | number | Date
  >;
  if (typeof parameters.created === "number")
    parameters.created = new Date(parameters.created * 1000);
  if (typeof parameters.expires === "number")
    parameters.expires = new Date(parameters.expires * 1000);

  return { key, components, parameters };
}

export function parseSignatureInputHeader(header: HeaderValue): {
  key: string;
  components: Component[];
  parameters: Parameters;
} {
  return parseParametersHeader("Signature-Input", header);
}

export function parseAcceptSignatureHeader(header: HeaderValue): {
  key: string;
  components: Component[];
  parameters: Parameters;
} {
  return parseParametersHeader("Accept-Signature", header);
}

export function parseSignatureHeader(key, header: HeaderValue): Uint8Array {
  const signatureMatch = header
    .toString()
    .match(/^([\w-]+)=:([A-Za-z0-9+/=]+):$/);
  if (!signatureMatch) throw new Error("Invalid Signature header");

  const [, signatureKey, signature] = signatureMatch;
  if (signatureKey !== key)
    throw new Error(
      `Invalid Signature header. Key mismatch ${signatureKey} !== ${key}`
    );

  return base64Decode(signature);
}
