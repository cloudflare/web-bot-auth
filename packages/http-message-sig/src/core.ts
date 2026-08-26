import {
  DisplayString,
  isInnerList,
  parseDictionary,
  serializeDictionary,
  serializeInnerList,
  serializeItem,
  type BareItem,
  type Dictionary,
  type InnerList,
  type Item,
  type Parameters,
} from "structured-headers";
import { SignatureError, SignatureErrorCode } from "./errors";
import type {
  ComponentDescriptor,
  ComponentParameters,
  CreateSignatureOptions,
  CreateSignatureSyncOptions,
  FieldOccurrence,
  RequestDescriptor,
  Rfc8941BareItem,
  SignatureComponent,
  SignatureFields,
  SignatureMessage,
  SignatureParameters,
  UntrustedSignatureCandidate,
  VerifiedSignature,
  Verifier,
  VerificationPolicy,
  VerifySignatureOptions,
} from "./types";

const encoder = new TextEncoder();
const fieldNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const sfKeyPattern = /^[a-z*][a-z0-9_.*-]*$/;
const derivedComponents = new Set([
  "@method",
  "@target-uri",
  "@authority",
  "@scheme",
  "@request-target",
  "@path",
  "@query",
  "@status",
]);
const unsupportedParameters = new Set(["sf", "bs", "tr"]);

interface RequestSnapshot {
  readonly kind: "request";
  readonly method: string;
  readonly targetUri: string;
  readonly requestTarget?: string;
  readonly fields: readonly FieldOccurrence[];
  readonly trailers: readonly FieldOccurrence[];
}

interface ResponseSnapshot {
  readonly kind: "response";
  readonly status: number;
  readonly fields: readonly FieldOccurrence[];
  readonly trailers: readonly FieldOccurrence[];
  readonly request?: RequestSnapshot;
}

type MessageSnapshot = RequestSnapshot | ResponseSnapshot;

interface ParsedSignatureInput {
  readonly value: InnerList;
  readonly components: readonly ComponentDescriptor[];
  readonly parameters: SignatureParameters;
}

function fail(
  code: (typeof SignatureErrorCode)[keyof typeof SignatureErrorCode],
  message: string,
  cause?: unknown
): never {
  throw new SignatureError(code, message, cause);
}

function cloneBareItem(value: Rfc8941BareItem): Rfc8941BareItem {
  if (value instanceof ArrayBuffer) return value.slice(0);
  return value;
}

function validateParameterName(name: string): void {
  if (!sfKeyPattern.test(name)) {
    fail(SignatureErrorCode.MalformedField, `Invalid parameter name ${name}`);
  }
}

function validateSerializableBareItem(
  value: Rfc8941BareItem,
  location: string
): void {
  try {
    serializeItem(value);
  } catch (error) {
    fail(SignatureErrorCode.MalformedField, `Invalid ${location}`, error);
  }
}

function isRfc8941BareItem(value: BareItem): value is Rfc8941BareItem {
  return !(value instanceof Date) && !(value instanceof DisplayString);
}

function validateBareItem(value: BareItem, location: string): Rfc8941BareItem {
  if (!isRfc8941BareItem(value)) {
    return fail(
      SignatureErrorCode.UnsupportedFeature,
      `${location} uses an RFC 9651-only value`
    );
  }
  return cloneBareItem(value);
}

function copyParameters(
  input: Readonly<{ readonly [name: string]: Rfc8941BareItem | undefined }>
): SignatureParameters {
  const output: Record<string, Rfc8941BareItem> = {};
  for (const [name, value] of Object.entries(input)) {
    validateParameterName(name);
    if (value !== undefined) {
      validateSerializableBareItem(value, `parameter ${name}`);
      output[name] = cloneBareItem(value);
    }
  }
  validateKnownParameters(output);
  return Object.freeze(output);
}

function validateKnownParameters(
  parameters: Readonly<Record<string, Rfc8941BareItem>>
): void {
  for (const name of ["created", "expires"]) {
    const value = parameters[name];
    if (
      value !== undefined &&
      (!Number.isInteger(value) || typeof value !== "number")
    ) {
      fail(SignatureErrorCode.MalformedField, `${name} must be an integer`);
    }
  }
  for (const name of ["nonce", "alg", "keyid", "tag"]) {
    const value = parameters[name];
    if (value !== undefined && typeof value !== "string") {
      fail(SignatureErrorCode.MalformedField, `${name} must be a string`);
    }
  }
}

function parametersToMap(parameters: SignatureParameters): Parameters {
  const output: Parameters = new Map();
  for (const [name, value] of Object.entries(parameters)) {
    if (value !== undefined) output.set(name, cloneBareItem(value));
  }
  return output;
}

function parametersFromMap(parameters: Parameters): SignatureParameters {
  const output: Record<string, Rfc8941BareItem> = {};
  for (const [name, value] of parameters) {
    output[name] = validateBareItem(value, `Parameter ${name}`);
  }
  validateKnownParameters(output);
  return Object.freeze(output);
}

export function component(
  name: string,
  parameters: ComponentParameters = {}
): ComponentDescriptor {
  const normalizedName = normalizeComponentName(name);
  const copied = copyComponentParameters(parameters);
  validateComponent({ name: normalizedName, parameters: copied });
  return Object.freeze({ name: normalizedName, parameters: copied });
}

function copyComponentParameters(
  parameters: ComponentParameters
): ComponentParameters {
  const output: Record<string, Rfc8941BareItem> = {};
  for (const [name, value] of Object.entries(parameters)) {
    validateParameterName(name);
    if (value !== undefined) {
      validateSerializableBareItem(value, `component parameter ${name}`);
      output[name] = cloneBareItem(value);
    }
  }
  return Object.freeze(output);
}

function normalizeComponentName(name: string): string {
  const normalized = name.toLowerCase();
  if (normalized.startsWith("@")) {
    if (normalized === "@query-param") {
      return fail(
        SignatureErrorCode.UnsupportedFeature,
        "@query-param is not supported"
      );
    }
    if (!derivedComponents.has(normalized)) {
      return fail(
        SignatureErrorCode.UnsupportedFeature,
        `Unknown derived component ${normalized}`
      );
    }
  } else if (!fieldNamePattern.test(normalized)) {
    return fail(
      SignatureErrorCode.InvalidComponent,
      `Invalid field component ${name}`
    );
  }
  return normalized;
}

function normalizeComponent(input: SignatureComponent): ComponentDescriptor {
  return typeof input === "string"
    ? component(input)
    : component(input.name, input.parameters);
}

function validateComponent(value: ComponentDescriptor): void {
  const entries = Object.entries(value.parameters);
  for (const [name, parameterValue] of entries) {
    if (unsupportedParameters.has(name)) {
      fail(SignatureErrorCode.UnsupportedFeature, `${name} is not supported`);
    }
    if (name !== "req" && name !== "key") {
      fail(
        SignatureErrorCode.UnsupportedFeature,
        `Component parameter ${name} is not supported`
      );
    }
    if (name === "req" && parameterValue !== true) {
      fail(SignatureErrorCode.InvalidComponent, "req must be true");
    }
    if (name === "key" && typeof parameterValue !== "string") {
      fail(SignatureErrorCode.InvalidComponent, "key must be a string");
    }
  }
  if (value.name.startsWith("@") && value.parameters.key !== undefined) {
    fail(
      SignatureErrorCode.InvalidComponent,
      `key is invalid on derived component ${value.name}`
    );
  }
}

function componentMap(value: ComponentDescriptor): Parameters {
  const output: Parameters = new Map();
  for (const [name, parameterValue] of Object.entries(value.parameters)) {
    if (parameterValue !== undefined) output.set(name, parameterValue);
  }
  return output;
}

export function componentIdentity(input: SignatureComponent): string {
  const value = normalizeComponent(input);
  return serializeItem(value.name, componentMap(value));
}

function equivalentIdentity(input: ComponentDescriptor): string {
  const ordered = Object.entries(input.parameters)
    .filter((entry) => entry[1] !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  const parameters: Parameters = new Map();
  for (const [name, value] of ordered) {
    if (value !== undefined) parameters.set(name, value);
  }
  return serializeItem(input.name, parameters);
}

function normalizeComponents(
  inputs: readonly SignatureComponent[]
): readonly ComponentDescriptor[] {
  const output: ComponentDescriptor[] = [];
  const identities = new Set<string>();
  for (const input of inputs) {
    const value = normalizeComponent(input);
    const identity = equivalentIdentity(value);
    if (identities.has(identity)) {
      fail(
        SignatureErrorCode.DuplicateComponent,
        `Duplicate component ${identity}`
      );
    }
    identities.add(identity);
    output.push(value);
  }
  return Object.freeze(output);
}

function fieldsFromHeaders(headers: Headers): readonly FieldOccurrence[] {
  const fields: FieldOccurrence[] = [];
  headers.forEach((value, name) => fields.push(Object.freeze({ name, value })));
  return Object.freeze(fields);
}

function copyFields(
  fields: readonly FieldOccurrence[]
): readonly FieldOccurrence[] {
  return Object.freeze(
    fields.map(({ name, value }) => {
      if (!fieldNamePattern.test(name)) {
        fail(SignatureErrorCode.MalformedField, `Invalid field name ${name}`);
      }
      const normalized = normalizeFieldValue(value);
      validateAscii(normalized, `Field ${name}`);
      return Object.freeze({ name: name.toLowerCase(), value: normalized });
    })
  );
}

function isNativeRequest(
  message: SignatureMessage | Request | RequestDescriptor
): message is Request {
  return typeof Request !== "undefined" && message instanceof Request;
}

function isNativeResponse(message: SignatureMessage): message is Response {
  return typeof Response !== "undefined" && message instanceof Response;
}

function snapshotRequest(
  message: Request | RequestDescriptor
): RequestSnapshot {
  if (isNativeRequest(message)) {
    return Object.freeze({
      kind: "request",
      method: message.method,
      targetUri: message.url,
      fields: fieldsFromHeaders(message.headers),
      trailers: Object.freeze([]),
    });
  }
  if (!fieldNamePattern.test(message.method)) {
    fail(SignatureErrorCode.InvalidComponent, "Invalid request method");
  }
  validateAscii(message.targetUri, "Target URI");
  if (message.requestTarget !== undefined) {
    validateAscii(message.requestTarget, "Request target");
  }
  return Object.freeze({
    kind: "request",
    method: message.method,
    targetUri: message.targetUri,
    requestTarget: message.requestTarget,
    fields: copyFields(message.fields),
    trailers: copyFields(message.trailers ?? []),
  });
}

function snapshotMessage(message: SignatureMessage): MessageSnapshot {
  if (isNativeRequest(message)) {
    return snapshotRequest(message);
  }
  if (isNativeResponse(message)) {
    return Object.freeze({
      kind: "response",
      status: message.status,
      fields: fieldsFromHeaders(message.headers),
      trailers: Object.freeze([]),
    });
  }
  if (message.kind === "request") return snapshotRequest(message);
  if (
    !Number.isInteger(message.status) ||
    message.status < 100 ||
    message.status > 999
  ) {
    fail(SignatureErrorCode.InvalidComponent, "Invalid response status");
  }
  return Object.freeze({
    kind: "response",
    status: message.status,
    fields: copyFields(message.fields),
    trailers: copyFields(message.trailers ?? []),
    request:
      message.request === undefined
        ? undefined
        : snapshotRequest(message.request),
  });
}

function normalizeFieldValue(value: string): string {
  return value.replace(/\r\n[\t ]+/g, " ").replace(/^[\t ]+|[\t ]+$/g, "");
}

function validateAscii(value: string, location: string): void {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code > 0x7e || code < 0x20 || code === 0x7f) {
      if (code === 0x09) continue;
      fail(
        SignatureErrorCode.MalformedField,
        `${location} is not ASCII field content`
      );
    }
  }
}

function extractField(
  snapshot: RequestSnapshot | ResponseSnapshot,
  name: string,
  trailers: boolean
): string {
  const source = trailers ? snapshot.trailers : snapshot.fields;
  const values = source
    .filter((field) => field.name.toLowerCase() === name)
    .map((field) => normalizeFieldValue(field.value));
  if (values.length === 0) {
    return fail(SignatureErrorCode.MissingField, `Missing field ${name}`);
  }
  return values.join(", ");
}

function requestForComponent(
  snapshot: MessageSnapshot,
  value: ComponentDescriptor
): RequestSnapshot | ResponseSnapshot {
  if (value.parameters.req === undefined) return snapshot;
  if (snapshot.kind !== "response" || snapshot.request === undefined) {
    return fail(
      SignatureErrorCode.InvalidComponent,
      "req requires a response with a related request"
    );
  }
  return snapshot.request;
}

function requestUrl(snapshot: RequestSnapshot, name: string): URL {
  try {
    return new URL(snapshot.targetUri);
  } catch (error) {
    return fail(
      SignatureErrorCode.InvalidComponent,
      `${name} requires an absolute target URI`,
      error
    );
  }
}

function requestTarget(
  snapshot: RequestSnapshot,
  name: string
): {
  readonly url: URL;
  readonly path: string;
  readonly query: string;
} {
  const url = requestUrl(snapshot, name);
  if (url.hash !== "") {
    return fail(
      SignatureErrorCode.InvalidComponent,
      `${name} target URI cannot contain a fragment`
    );
  }
  const schemeEnd = snapshot.targetUri.indexOf("://");
  if (schemeEnd === -1) {
    return fail(
      SignatureErrorCode.InvalidComponent,
      `${name} requires an HTTP target URI`
    );
  }
  const pathStart = snapshot.targetUri.indexOf("/", schemeEnd + 3);
  const queryStart = snapshot.targetUri.indexOf("?", schemeEnd + 3);
  const start =
    pathStart !== -1 && (queryStart === -1 || pathStart < queryStart)
      ? pathStart
      : queryStart;
  const pathEnd = queryStart === -1 ? snapshot.targetUri.length : queryStart;
  return Object.freeze({
    url,
    path:
      start === -1 || start === queryStart
        ? "/"
        : snapshot.targetUri.slice(start, pathEnd),
    query: queryStart === -1 ? "?" : snapshot.targetUri.slice(queryStart),
  });
}

function extractDerived(
  snapshot: RequestSnapshot | ResponseSnapshot,
  name: string
): string {
  if (name === "@status") {
    if (snapshot.kind !== "response") {
      return fail(
        SignatureErrorCode.InvalidComponent,
        "@status requires a response"
      );
    }
    return snapshot.status.toString();
  }
  if (snapshot.kind !== "request") {
    return fail(
      SignatureErrorCode.InvalidComponent,
      `${name} requires a request`
    );
  }
  if (name === "@method") return snapshot.method;
  const target = requestTarget(snapshot, name);
  switch (name) {
    case "@target-uri":
      return snapshot.targetUri;
    case "@authority":
      return target.url.host;
    case "@scheme":
      return target.url.protocol.slice(0, -1);
    case "@request-target":
      if (snapshot.requestTarget === undefined) {
        return fail(
          SignatureErrorCode.UnsupportedFeature,
          "@request-target requires a descriptor requestTarget"
        );
      }
      return snapshot.requestTarget;
    case "@path":
      return target.path;
    case "@query":
      return target.query;
    default:
      return fail(
        SignatureErrorCode.UnsupportedFeature,
        `Unknown derived component ${name}`
      );
  }
}

function extractComponentValue(
  snapshot: MessageSnapshot,
  value: ComponentDescriptor
): string {
  const selected = requestForComponent(snapshot, value);
  if (value.name.startsWith("@")) return extractDerived(selected, value.name);
  const fieldValue = extractField(selected, value.name, false);
  const key = value.parameters.key;
  if (key === undefined) return fieldValue;
  if (typeof key !== "string") {
    return fail(SignatureErrorCode.InvalidComponent, "key must be a string");
  }
  const dictionary = parseRfc8941Dictionary(fieldValue, `field ${value.name}`);
  const member = dictionary.get(key);
  if (member === undefined) {
    return fail(
      SignatureErrorCode.MissingField,
      `Field ${value.name} has no dictionary member ${key}`
    );
  }
  return isInnerList(member)
    ? serializeInnerList(member)
    : serializeItem(member);
}

function componentsToInnerList(
  components: readonly ComponentDescriptor[],
  parameters: SignatureParameters
): InnerList {
  const items: Item[] = components.map((value) => [
    value.name,
    componentMap(value),
  ]);
  return [items, parametersToMap(parameters)];
}

function buildSignatureBase(
  snapshot: MessageSnapshot,
  components: readonly ComponentDescriptor[],
  signatureInput: InnerList
): Uint8Array {
  const lines = components.map(
    (value) =>
      `${serializeItem(value.name, componentMap(value))}: ${extractComponentValue(snapshot, value)}`
  );
  lines.push(`"@signature-params": ${serializeInnerList(signatureInput)}`);
  return encoder.encode(lines.join("\n"));
}

function assertAlgorithm(
  claimed: Rfc8941BareItem | undefined,
  actual: string
): void {
  if (claimed !== undefined && claimed !== actual) {
    fail(
      SignatureErrorCode.AlgorithmMismatch,
      `Claimed algorithm ${String(claimed)} does not match ${actual}`
    );
  }
}

function createInput(
  message: SignatureMessage,
  label: string,
  componentsInput: readonly SignatureComponent[],
  parametersInput: SignatureParameters,
  algorithm: string
): {
  readonly base: Uint8Array;
  readonly signatureInput: string;
} {
  if (!sfKeyPattern.test(label)) {
    fail(SignatureErrorCode.MalformedField, `Invalid signature label ${label}`);
  }
  const snapshot = snapshotMessage(message);
  const components = normalizeComponents(componentsInput);
  const parameters = copyParameters(parametersInput);
  assertAlgorithm(parameters.alg, algorithm);
  const innerList = componentsToInnerList(components, parameters);
  const dictionary: Dictionary = new Map([[label, innerList]]);
  return Object.freeze({
    base: buildSignatureBase(snapshot, components, innerList),
    signatureInput: serializeDictionary(dictionary),
  });
}

function signatureDictionary(label: string, signature: Uint8Array): string {
  const bytes = Uint8Array.from(signature).buffer;
  const item: Item = [bytes, new Map()];
  const dictionary: Dictionary = new Map([[label, item]]);
  return serializeDictionary(dictionary);
}

export async function createSignature(
  message: SignatureMessage,
  options: CreateSignatureOptions
): Promise<SignatureFields> {
  const label = options.label ?? "sig1";
  const input = createInput(
    message,
    label,
    options.components,
    options.parameters,
    options.signer.algorithm
  );
  const signature = await options.signer.sign(input.base.slice());
  return Object.freeze({
    signature: signatureDictionary(label, signature),
    signatureInput: input.signatureInput,
  });
}

export function createSignatureSync(
  message: SignatureMessage,
  options: CreateSignatureSyncOptions
): SignatureFields {
  const label = options.label ?? "sig1";
  const input = createInput(
    message,
    label,
    options.components,
    options.parameters,
    options.signer.algorithm
  );
  return Object.freeze({
    signature: signatureDictionary(
      label,
      options.signer.sign(input.base.slice())
    ),
    signatureInput: input.signatureInput,
  });
}

function topLevelMemberCount(input: string): number {
  let count = input.trim() === "" ? 0 : 1;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const character of input) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') quoted = !quoted;
    if (quoted) continue;
    if (character === "(") depth += 1;
    if (character === ")") depth -= 1;
    if (character === "," && depth === 0) count += 1;
  }
  return count;
}

function rawParameterCount(input: string): number {
  let count = 0;
  let quoted = false;
  let escaped = false;
  for (const character of input) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') quoted = !quoted;
    if (!quoted && character === ";") count += 1;
  }
  return count;
}

function parsedParameterCount(dictionary: Dictionary): number {
  let count = 0;
  for (const member of dictionary.values()) {
    count += member[1].size;
    if (isInnerList(member)) {
      for (const item of member[0]) count += item[1].size;
    }
  }
  return count;
}

function assertNoRfc9651Syntax(input: string, name: string): void {
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') {
      quoted = !quoted;
      continue;
    }
    if (
      !quoted &&
      (character === "@" || (character === "%" && input[index + 1] === '"'))
    ) {
      fail(
        SignatureErrorCode.UnsupportedFeature,
        `${name} uses an RFC 9651-only value`
      );
    }
  }
}

function parseRfc8941Dictionary(input: string, name: string): Dictionary {
  assertNoRfc9651Syntax(input, name);
  let dictionary: Dictionary;
  try {
    dictionary = parseDictionary(input);
  } catch (error) {
    return fail(SignatureErrorCode.MalformedField, `Malformed ${name}`, error);
  }
  assertRfc8941Dictionary(dictionary, name);
  return dictionary;
}

function parseStrictDictionary(input: string, name: string): Dictionary {
  const dictionary = parseRfc8941Dictionary(input, name);
  if (topLevelMemberCount(input) !== dictionary.size) {
    return fail(
      SignatureErrorCode.DuplicateLabel,
      `${name} has duplicate labels`
    );
  }
  if (rawParameterCount(input) !== parsedParameterCount(dictionary)) {
    return fail(
      SignatureErrorCode.MalformedField,
      `${name} has duplicate parameters`
    );
  }
  return dictionary;
}

function assertRfc8941Dictionary(dictionary: Dictionary, name: string): void {
  for (const member of dictionary.values()) {
    if (isInnerList(member)) {
      for (const [value, parameters] of member[0]) {
        validateBareItem(value, name);
        for (const parameter of parameters.values())
          validateBareItem(parameter, name);
      }
    } else {
      validateBareItem(member[0], name);
    }
    for (const parameter of member[1].values())
      validateBareItem(parameter, name);
  }
}

function parseSignatureDictionary(input: string): Dictionary {
  const dictionary = parseStrictDictionary(input, "Signature");
  for (const member of dictionary.values()) {
    if (
      isInnerList(member) ||
      !(member[0] instanceof ArrayBuffer) ||
      member[1].size !== 0
    ) {
      fail(
        SignatureErrorCode.MalformedField,
        "Signature members must be unparameterized byte sequences"
      );
    }
  }
  return dictionary;
}

function parseSignatureInputDictionary(input: string): Dictionary {
  const dictionary = parseStrictDictionary(input, "Signature-Input");
  for (const member of dictionary.values()) {
    if (!isInnerList(member)) {
      fail(
        SignatureErrorCode.MalformedField,
        "Signature-Input members must be inner lists"
      );
    }
  }
  return dictionary;
}

function matchingLabels(left: Dictionary, right: Dictionary): boolean {
  if (left.size !== right.size) return false;
  for (const label of left.keys()) if (!right.has(label)) return false;
  return true;
}

function selectedLabel(
  signatures: Dictionary,
  inputs: Dictionary,
  requested: string | undefined
): string {
  if (!matchingLabels(signatures, inputs)) {
    return fail(
      SignatureErrorCode.LabelMismatch,
      "Signature and Signature-Input label sets differ"
    );
  }
  if (requested !== undefined) {
    if (!signatures.has(requested) || !inputs.has(requested)) {
      return fail(
        SignatureErrorCode.LabelMismatch,
        `Label ${requested} is not present in both signature fields`
      );
    }
    return requested;
  }
  if (signatures.size !== 1) {
    return fail(
      SignatureErrorCode.LabelRequired,
      "An explicit label is required for multiple or mismatched signatures"
    );
  }
  const iterator = signatures.keys().next();
  if (iterator.done) {
    return fail(SignatureErrorCode.MissingField, "Signature fields are empty");
  }
  return iterator.value;
}

function parsedSignatureInput(member: InnerList): ParsedSignatureInput {
  const components: ComponentDescriptor[] = [];
  for (const [name, parameters] of member[0]) {
    if (typeof name !== "string") {
      return fail(
        SignatureErrorCode.MalformedField,
        "Component identifiers must be strings"
      );
    }
    if (name !== name.toLowerCase()) {
      return fail(
        SignatureErrorCode.MalformedField,
        `Component identifier ${name} must be lowercase`
      );
    }
    const values: Record<string, Rfc8941BareItem> = {};
    for (const [parameterName, value] of parameters) {
      values[parameterName] = validateBareItem(
        value,
        `Component parameter ${parameterName}`
      );
    }
    components.push(component(name, values));
  }
  const normalized = normalizeComponents(components);
  return Object.freeze({
    value: member,
    components: normalized,
    parameters: parametersFromMap(member[1]),
  });
}

function signatureBytes(member: Item | InnerList): Uint8Array {
  if (isInnerList(member) || !(member[0] instanceof ArrayBuffer)) {
    return fail(SignatureErrorCode.MalformedField, "Invalid Signature member");
  }
  return new Uint8Array(member[0].slice(0));
}

export function appendSignature(
  headers: Headers,
  fields: SignatureFields
): Headers {
  const newSignatures = parseSignatureDictionary(fields.signature);
  const newInputs = parseSignatureInputDictionary(fields.signatureInput);
  if (newSignatures.size === 0 || newInputs.size === 0) {
    fail(SignatureErrorCode.MalformedField, "New signature fields are empty");
  }
  if (!matchingLabels(newSignatures, newInputs)) {
    fail(SignatureErrorCode.LabelMismatch, "New signature label sets differ");
  }

  const signatureHeader = headers.get("signature");
  const inputHeader = headers.get("signature-input");
  if ((signatureHeader === null) !== (inputHeader === null)) {
    fail(
      SignatureErrorCode.LabelMismatch,
      "Existing signature label sets differ"
    );
  }
  const signatures =
    signatureHeader === null
      ? new Map<string, Item | InnerList>()
      : parseSignatureDictionary(signatureHeader);
  const inputs =
    inputHeader === null
      ? new Map<string, Item | InnerList>()
      : parseSignatureInputDictionary(inputHeader);
  if (!matchingLabels(signatures, inputs)) {
    fail(
      SignatureErrorCode.LabelMismatch,
      "Existing signature label sets differ"
    );
  }
  for (const label of newSignatures.keys()) {
    if (signatures.has(label) || inputs.has(label)) {
      fail(
        SignatureErrorCode.DuplicateLabel,
        `Duplicate signature label ${label}`
      );
    }
  }
  for (const [label, value] of newSignatures) signatures.set(label, value);
  for (const [label, value] of newInputs) inputs.set(label, value);

  const output = new Headers(headers);
  output.set("signature", serializeDictionary(signatures));
  output.set("signature-input", serializeDictionary(inputs));
  return output;
}

function getRequiredField(snapshot: MessageSnapshot, name: string): string {
  return extractField(snapshot, name, false);
}

function assertPolicyCoverage<V extends Verifier>(
  components: readonly ComponentDescriptor[],
  parameters: SignatureParameters,
  policy: VerificationPolicy<V>,
  now: number
): void {
  const present = new Set(components.map(equivalentIdentity));
  for (const required of policy.requiredComponents) {
    const identity = equivalentIdentity(normalizeComponent(required));
    if (!present.has(identity)) {
      fail(
        SignatureErrorCode.PolicyViolation,
        `Required component ${identity} is absent`
      );
    }
  }
  for (const required of policy.requiredParameters) {
    if (parameters[required] === undefined) {
      fail(
        SignatureErrorCode.PolicyViolation,
        `Required parameter ${required} is absent`
      );
    }
  }
  const skew = policy.clockSkew ?? 0;
  if (!Number.isFinite(skew) || skew < 0) {
    fail(SignatureErrorCode.PolicyViolation, "clockSkew must be non-negative");
  }
  const created = parameters.created;
  const expires = parameters.expires;
  if (created !== undefined && created > now + skew) {
    fail(
      SignatureErrorCode.PolicyViolation,
      "Signature was created in the future"
    );
  }
  if (expires !== undefined && expires < now - skew) {
    fail(SignatureErrorCode.PolicyViolation, "Signature has expired");
  }
  if (policy.maxAge !== undefined) {
    if (!Number.isFinite(policy.maxAge) || policy.maxAge < 0) {
      fail(SignatureErrorCode.PolicyViolation, "maxAge must be non-negative");
    }
    if (created === undefined) {
      fail(SignatureErrorCode.PolicyViolation, "maxAge requires created");
    }
    if (now - created > policy.maxAge + skew) {
      fail(SignatureErrorCode.PolicyViolation, "Signature is too old");
    }
  }
}

export async function verifySignature<V extends Verifier>(
  message: SignatureMessage,
  options: VerifySignatureOptions<V>
): Promise<VerifiedSignature<V>> {
  const snapshot = snapshotMessage(message);
  const signatureHeader = getRequiredField(snapshot, "signature");
  const inputHeader = getRequiredField(snapshot, "signature-input");
  const signatures = parseSignatureDictionary(signatureHeader);
  const inputs = parseSignatureInputDictionary(inputHeader);
  const label = selectedLabel(signatures, inputs, options.label);
  const inputMember = inputs.get(label);
  const signatureMember = signatures.get(label);
  if (
    inputMember === undefined ||
    !isInnerList(inputMember) ||
    signatureMember === undefined
  ) {
    return fail(
      SignatureErrorCode.LabelMismatch,
      `Incomplete signature ${label}`
    );
  }
  const parsed = parsedSignatureInput(inputMember);
  const signature = signatureBytes(signatureMember);
  const base = buildSignatureBase(snapshot, parsed.components, parsed.value);
  const now = options.policy.now ?? Math.floor(Date.now() / 1000);
  if (!Number.isFinite(now)) {
    return fail(SignatureErrorCode.PolicyViolation, "now must be finite");
  }
  assertPolicyCoverage(
    parsed.components,
    parsed.parameters,
    options.policy,
    now
  );
  const claimedAlgorithm = parsed.parameters.alg;
  if (
    claimedAlgorithm !== undefined &&
    !options.policy.algorithms.includes(claimedAlgorithm)
  ) {
    return fail(
      SignatureErrorCode.PolicyViolation,
      `Algorithm ${claimedAlgorithm} is not allowed`
    );
  }

  const untrustedCandidate: UntrustedSignatureCandidate = Object.freeze({
    label,
    algorithm: claimedAlgorithm,
    components: parsed.components,
    parameters: copyParameters(parsed.parameters),
    signature: signature.slice(),
  });
  let verifier: V;
  try {
    verifier = await options.resolveVerifier(
      untrustedCandidate,
      Object.freeze({ now })
    );
  } catch (error) {
    return fail(
      SignatureErrorCode.ResolverFailed,
      "Verifier resolution failed",
      error
    );
  }
  if (!options.policy.algorithms.includes(verifier.algorithm)) {
    return fail(
      SignatureErrorCode.PolicyViolation,
      `Algorithm ${verifier.algorithm} is not allowed`
    );
  }
  assertAlgorithm(claimedAlgorithm, verifier.algorithm);
  const valid = await verifier.verify(base.slice(), signature.slice());
  if (!valid) {
    return fail(
      SignatureErrorCode.VerificationFailed,
      "Signature verification failed"
    );
  }

  const verified: VerifiedSignature<V> = Object.freeze({
    verifier,
    label,
    algorithm: verifier.algorithm,
    components: parsed.components,
    parameters: parsed.parameters,
    signature: signature.slice(),
  });
  if (options.policy.validate !== undefined) {
    const accepted = await options.policy.validate(verified);
    if (accepted === false) {
      return fail(
        SignatureErrorCode.PolicyViolation,
        "Signature rejected by policy"
      );
    }
  }
  return verified;
}
