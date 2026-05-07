// Copyright 2025 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
	Directory,
	HTTP_MESSAGE_SIGNATURES_DIRECTORY,
	MediaType,
	Signer,
	VerificationParams,
	directoryResponseHeaders,
	helpers,
	jwkToKeyID,
	signatureHeaders,
	verify,
} from "web-bot-auth";
import { generateHTML } from "./html";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };
import { Ed25519Signer } from "web-bot-auth/crypto";

const DIRECTORY_FETCH_TIMEOUT_MS = 5_000;
const DIRECTORY_RESPONSE_MAX_BYTES = 64_000;
const TURNSTILE_VERIFY_URL =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";

interface ValidationResult {
	ok: boolean;
	errors: string[];
	warnings: string[];
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function getProperty(value: unknown, name: string): unknown {
	if (value === null || typeof value !== "object") {
		return undefined;
	}
	for (const [key, property] of Object.entries(value)) {
		if (key === name) {
			return property;
		}
	}
	return undefined;
}

function getStringProperty(value: unknown, name: string): string | undefined {
	const property = getProperty(value, name);
	return typeof property === "string" ? property : undefined;
}

function getBooleanProperty(value: unknown, name: string): boolean | undefined {
	const property = getProperty(value, name);
	return typeof property === "boolean" ? property : undefined;
}

function validationResponse(result: ValidationResult, status = 200): Response {
	return Response.json(result, { status });
}

function errorResponse(errors: string[], status = 400): Response {
	return validationResponse({ ok: false, errors, warnings: [] }, status);
}

function getTurnstileSiteKey(env: Env): string {
	return getStringProperty(env, "TURNSTILE_SITE_KEY") ?? "";
}

function base64urlDecodedLength(value: string): number | undefined {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) {
		return undefined;
	}
	try {
		const padding = "=".repeat((4 - (value.length % 4)) % 4);
		return atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding)
			.length;
	} catch {
		return undefined;
	}
}

async function getExampleDirectory(): Promise<Directory> {
	const key = {
		kid: await jwkToKeyID(
			jwk,
			helpers.WEBCRYPTO_SHA256,
			helpers.BASE64URL_DECODE
		),
		kty: jwk.kty,
		crv: jwk.crv,
		x: jwk.x,
		nbf: new Date("2025-04-01").getTime(),
	};
	return {
		keys: [key],
		purpose: "rag",
	};
}

async function fetchDirectory(signatureAgent: string): Promise<Directory> {
	// make "some" validatation of the Signature-Agent header before making a request
	let parsed: string;
	try {
		parsed = JSON.parse(signatureAgent);
	} catch {
		const e = new Error(
			`Failed to validate Signature-Agent header: ${signatureAgent}`
		);
		console.error(e.message);
		throw e;
	}

	try {
		const url = new URL(parsed);
		if (url.protocol !== "https:") {
			throw new Error(
				'The demo only supports "https:" scheme for Signature-Agent header'
			);
		}
		if (url.pathname !== "/") {
			throw new Error(
				`Only support signature-agent at the root, got "${url.pathname}"`
			);
		}
	} catch (e) {
		console.error(
			`Failed to validate Signature-Agent header: ${signatureAgent}`
		);
		throw e;
	}
	if (parsed.endsWith("/")) {
		parsed = parsed.slice(0, -1);
	}
	console.log(
		`Fetching \`Signature-Agent\` directory from: "${parsed}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}"`
	);
	const response = await fetch(`${parsed}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`);
	return response.json();
}

async function validateTurnstile(
	env: Env,
	token: string,
	remoteIP: string | null
): Promise<boolean> {
	const formData = new FormData();
	formData.append("secret", env.TURNSTILE_SECRET_KEY);
	formData.append("response", token);
	if (remoteIP !== null) {
		formData.append("remoteip", remoteIP);
	}

	let response: Response;
	try {
		response = await fetch(TURNSTILE_VERIFY_URL, {
			body: formData,
			method: "POST",
		});
	} catch {
		return false;
	}

	if (!response.ok) {
		return false;
	}

	try {
		const body: unknown = await response.json();
		return getBooleanProperty(body, "success") === true;
	} catch {
		return false;
	}
}

function hasExpectedRequestContext(request: Request): boolean {
	const requestOrigin = new URL(request.url).origin;
	if (request.headers.get("Origin") !== requestOrigin) {
		return false;
	}

	const referer = request.headers.get("Referer");
	if (referer === null) {
		return false;
	}
	try {
		if (new URL(referer).origin !== requestOrigin) {
			return false;
		}
	} catch {
		return false;
	}

	return (
		request.headers.get("Sec-Fetch-Site") === "same-origin" &&
		request.headers.get("Sec-Fetch-Mode") === "cors" &&
		request.headers.get("Sec-Fetch-Dest") === "empty"
	);
}

function validateDirectoryURL(url: string): URL | Response {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return errorResponse(["URL must be valid"]);
	}

	if (parsed.protocol !== "https:") {
		return errorResponse(['Directory URL must use "https:"']);
	}
	if (parsed.username !== "" || parsed.password !== "") {
		return errorResponse(["Directory URL must not include credentials"]);
	}
	if (parsed.port !== "") {
		return errorResponse(["Directory URL must not use a custom port"]);
	}
	if (parsed.pathname !== HTTP_MESSAGE_SIGNATURES_DIRECTORY) {
		return errorResponse([
			`Directory URL path must be ${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`,
		]);
	}

	return parsed;
}

function validateDirectory(directory: unknown): ValidationResult {
	const errors: string[] = [];
	const warnings: string[] = [];

	if (directory === null || typeof directory !== "object") {
		return { ok: false, errors: ["Directory must be a JSON object"], warnings };
	}

	const keys = getProperty(directory, "keys");
	if (!Array.isArray(keys)) {
		errors.push("Directory must include a keys array");
	} else if (keys.length === 0) {
		errors.push("Directory keys array must not be empty");
	} else {
		for (const [index, key] of keys.entries()) {
			if (key === null || typeof key !== "object") {
				errors.push(`keys[${index}] must be a JSON object`);
				continue;
			}

			const kty = getStringProperty(key, "kty");
			if (kty === undefined) {
				errors.push(`keys[${index}].kty must be a string`);
				continue;
			}

			if (kty !== "OKP") {
				warnings.push(`keys[${index}].kty is not OKP`);
				continue;
			}

			if (getStringProperty(key, "crv") !== "Ed25519") {
				errors.push(`keys[${index}].crv must be Ed25519`);
			}
			const x = getStringProperty(key, "x");
			if (x === undefined) {
				errors.push(`keys[${index}].x must be a string`);
			} else if (base64urlDecodedLength(x) !== 32) {
				errors.push(`keys[${index}].x must be a 32-byte base64url value`);
			}
		}
	}

	const purpose = getProperty(directory, "purpose");
	if (purpose !== undefined && typeof purpose !== "string") {
		errors.push("Directory purpose must be a string when present");
	}

	return { ok: errors.length === 0, errors, warnings };
}

async function readTextWithLimit(
	response: Response,
	byteLimit: number
): Promise<string> {
	if (response.body === null) {
		return "";
	}

	const reader = response.body.getReader();
	const decoder = new TextDecoder();
	let bytesRead = 0;
	let text = "";

	while (true) {
		const result = await reader.read();
		if (result.done) {
			return text + decoder.decode();
		}

		bytesRead += result.value.byteLength;
		if (bytesRead > byteLimit) {
			await reader.cancel();
			throw new Error("Directory response is too large");
		}
		text += decoder.decode(result.value, { stream: true });
	}
}

async function validateDirectoryRequest(
	request: Request,
	env: Env
): Promise<Response> {
	if (request.method !== "POST") {
		return errorResponse(["Method not allowed"], 405);
	}
	if (!hasExpectedRequestContext(request)) {
		return errorResponse(["Bad request"]);
	}

	let body: unknown;
	try {
		body = await request.json();
	} catch {
		return errorResponse(["Request body must be valid JSON"]);
	}

	const url = getStringProperty(body, "url");
	const turnstileToken = getStringProperty(body, "turnstileToken");
	if (url === undefined || url.length === 0) {
		return errorResponse(["Missing url"]);
	}
	if (turnstileToken === undefined || turnstileToken.length === 0) {
		return errorResponse(["Missing Turnstile token"]);
	}

	const parsed = validateDirectoryURL(url);
	if (parsed instanceof Response) {
		return parsed;
	}

	const turnstileOK = await validateTurnstile(
		env,
		turnstileToken,
		request.headers.get("CF-Connecting-IP")
	);
	if (!turnstileOK) {
		return errorResponse(["Turnstile verification failed"], 403);
	}

	let response: Response;
	try {
		response = await fetch(parsed.toString(), {
			redirect: "manual",
			signal: AbortSignal.timeout(DIRECTORY_FETCH_TIMEOUT_MS),
		});
	} catch {
		return errorResponse(["Directory fetch failed"], 502);
	}

	if (!response.ok) {
		return errorResponse([`Directory returned HTTP ${response.status}`], 502);
	}

	const warnings: string[] = [];
	const contentType = response.headers.get("Content-Type");
	const mediaType = contentType?.split(";", 1)[0]?.trim().toLowerCase();
	if (
		mediaType !== MediaType.HTTP_MESSAGE_SIGNATURES_DIRECTORY &&
		mediaType !== "application/json"
	) {
		warnings.push(
			`Directory returned unexpected Content-Type ${contentType ?? "none"}`
		);
	}

	let text: string;
	try {
		text = await readTextWithLimit(response, DIRECTORY_RESPONSE_MAX_BYTES);
	} catch {
		return errorResponse(["Directory response is too large"], 502);
	}

	let directory: unknown;
	try {
		directory = JSON.parse(text);
	} catch {
		return errorResponse(["Directory response must be valid JSON"], 502);
	}

	const result = validateDirectory(directory);
	return validationResponse({
		...result,
		warnings: [...warnings, ...result.warnings],
	});
}

async function getSigner(): Promise<Signer> {
	return Ed25519Signer.fromJWK(jwk);
}

function verifyEd25519(
	directory: Directory
): (
	data: string,
	signature: Uint8Array,
	params: VerificationParams
) => Promise<void> {
	return async (data, signature, _params) => {
		void _params;
		const key = await crypto.subtle.importKey(
			"jwk",
			directory.keys[0],
			{ name: "Ed25519" },
			true,
			["verify"]
		);

		const encodedData = new TextEncoder().encode(data);

		const isValid = await crypto.subtle.verify(
			{ name: "Ed25519" },
			key,
			signature,
			encodedData
		);

		if (!isValid) {
			throw new Error("invalid signature");
		}
	};
}

const SignatureValidationStatus = {
	NEUTRAL: "neutral",
	INVALID: (message?: string) => `invalid${message ? `: ${message}` : ""}`,
	VALID: "valid",
} as const;
type SignatureValidationStatus = string;

async function verifySignature(
	env: Env,
	request: Request
): Promise<SignatureValidationStatus> {
	if (request.headers.get("Signature") === null) {
		return SignatureValidationStatus.NEUTRAL;
	}

	const signatureAgent = request.headers.get("Signature-Agent");
	let directory: Directory;
	try {
		if (signatureAgent && !signatureAgent.includes(env.SIGNATURE_AGENT)) {
			directory = await fetchDirectory(signatureAgent);
		} else {
			directory = await getExampleDirectory();
		}
	} catch (e) {
		return SignatureValidationStatus.INVALID(errorMessage(e));
	}

	try {
		await verify(request, verifyEd25519(directory));
	} catch (e) {
		return SignatureValidationStatus.INVALID(errorMessage(e));
	}

	console.log("Signature verified successfully");
	if (signatureAgent) {
		console.log(`Signature-Agent: "${signatureAgent}"`);
	}

	return SignatureValidationStatus.VALID;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		void ctx;
		const url = new URL(request.url);

		if (url.pathname.startsWith("/debug")) {
			return new Response(
				[...request.headers]
					.map(([key, value]) => `${key}: ${value}`)
					.join("\n")
			);
		}

		if (url.pathname.startsWith("/v0/api/verify")) {
			const status = await verifySignature(env, request);
			return new Response(status);
		}

		if (url.pathname === "/v0/api/validate-directory") {
			return validateDirectoryRequest(request, env);
		}

		if (url.pathname.startsWith(HTTP_MESSAGE_SIGNATURES_DIRECTORY)) {
			const directory = await getExampleDirectory();

			const signedHeaders = await directoryResponseHeaders(
				request,
				[await getSigner()],
				{ created: new Date(), expires: new Date(Date.now() + 300_000) }
			);
			return new Response(JSON.stringify(directory), {
				headers: {
					...signedHeaders,
					"content-type": MediaType.HTTP_MESSAGE_SIGNATURES_DIRECTORY,
				},
			});
		}

		const status = await verifySignature(env, request);
		const turnstileSiteKey = getTurnstileSiteKey(env);
		switch (status) {
			case SignatureValidationStatus.NEUTRAL:
				return new Response(generateHTML(undefined, turnstileSiteKey), {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			case SignatureValidationStatus.VALID:
				return new Response(generateHTML(true, turnstileSiteKey), {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			default:
				return new Response(generateHTML(false, turnstileSiteKey), {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
		}
	},
	// On a schedule, send a web-bot-auth signed request to a target endpoint
	async scheduled(ctx, env, ectx) {
		void ectx;
		const headers = { "Signature-Agent": JSON.stringify(env.SIGNATURE_AGENT) };
		const request = new Request(env.TARGET_URL, { headers });
		const created = new Date(ctx.scheduledTime);
		const expires = new Date(created.getTime() + 300_000);
		const signedHeaders = await signatureHeaders(request, await getSigner(), {
			created,
			expires,
		});
		await fetch(
			new Request(request.url, {
				headers: {
					...signedHeaders,
					...headers,
				},
			})
		);
	},
} satisfies ExportedHandler<Env>;
