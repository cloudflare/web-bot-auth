import {
  Component,
  ComponentParameters,
  HeaderValue,
  Parameter,
  Parameters,
} from "./types";
import { decode as base64Decode } from "./base64";
import { parseDictionary, isInnerList } from "structured-headers";

function parseSfvDictionary(
  name: string,
  header: HeaderValue
): { key: string; components: Component[]; parameters: Parameters } {
  let dictionary;
  try {
    dictionary = parseDictionary(header.toString());
  } catch (error) {
    throw new Error(
      `Invalid ${name} header; failed to parse as RFC 8941 dictionary: ${(error as Error).message}`
    );
  }

  if (dictionary.size > 1) {
    throw new Error(`Multiple signatures is not supported`);
  }

  const entry = dictionary.entries().next();

  if (!entry.value) {
    throw new Error(`Invalid ${name} header. Invalid value`);
  }

  const [key, innerlist] = entry.value;
  if (!isInnerList(innerlist)) {
    throw new Error(`Invalid ${name} header. Missing components`);
  }

  const [cwp, params] = innerlist;

  const parameters: Parameters = Object.fromEntries(params) as Record<
    Parameter,
    string | number | Date
  >;
  if (typeof parameters.created === "number")
    parameters.created = new Date(parameters.created * 1000);
  if (typeof parameters.expires === "number")
    parameters.expires = new Date(parameters.expires * 1000);

  const components: Component[] = cwp.map(([component, componentParams]) => {
    if (typeof component !== "string") {
      throw new Error(
        `Failed to parse component ${component} in component list: type is not string`
      );
    }

    if (componentParams.size === 0) {
      return component;
    }

    for (const [paramName, paramValue] of componentParams.entries()) {
      if (typeof paramValue !== "string" && typeof paramValue !== "boolean") {
        throw new Error(
          `Failed to parse parameter ${paramName} on ${component}: type is neither string nor boolean`
        );
      }
    }

    return {
      name: component,
      parameters: componentParams as ComponentParameters,
    };
  });

  return { key, components, parameters };
}

export function parseSignatureInputHeader(header: HeaderValue): {
  key: string;
  components: Component[];
  parameters: Parameters;
} {
  return parseSfvDictionary("Signature-Input", header);
}

export function parseAcceptSignatureHeader(header: HeaderValue): {
  key: string;
  components: Component[];
  parameters: Parameters;
} {
  return parseSfvDictionary("Accept-Signature", header);
}

export function parseSignatureHeader(
  key: string,
  header: HeaderValue
): Uint8Array {
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
