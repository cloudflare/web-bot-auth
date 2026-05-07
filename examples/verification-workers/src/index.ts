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

function errorResponse(error: string, status = 400): Response {
	return Response.json({ error }, { status });
}

function getTurnstileSiteKey(env: Env): string {
	return getStringProperty(env, "TURNSTILE_SITE_KEY") ?? "";
}

function getStringFormValue(
	formData: FormData,
	name: string
): string | undefined {
	const value = formData.get(name);
	return typeof value === "string" && value.length > 0 ? value : undefined;
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
		return getProperty(body, "success") === true;
	} catch {
		return false;
	}
}

function validateDirectoryURL(url: string): URL | string {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return "URL must be valid";
	}

	if (parsed.protocol !== "https:") {
		return 'Directory URL must use "https:"';
	}
	if (parsed.username !== "" || parsed.password !== "") {
		return "Directory URL must not include credentials";
	}
	if (parsed.port !== "") {
		return "Directory URL must not use a custom port";
	}
	if (parsed.pathname !== HTTP_MESSAGE_SIGNATURES_DIRECTORY) {
		return `Directory URL path must be ${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`;
	}

	return parsed;
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

async function proxyDirectoryRequest(
	request: Request,
	env: Env
): Promise<Response> {
	if (request.method !== "POST") {
		return errorResponse("Method not allowed", 405);
	}

	const origin = request.headers.get("Origin");
	if (origin !== new URL(request.url).origin) {
		return errorResponse("Bad request");
	}

	let formData: FormData;
	try {
		formData = await request.formData();
	} catch {
		return errorResponse("Request body must be form data");
	}

	const url = getStringFormValue(formData, "url");
	const turnstileToken = getStringFormValue(formData, "cf-turnstile-response");
	if (url === undefined || url.length === 0) {
		return errorResponse("Missing url");
	}
	if (turnstileToken === undefined || turnstileToken.length === 0) {
		return errorResponse("Missing Turnstile token");
	}

	const parsed = validateDirectoryURL(url);
	if (typeof parsed === "string") {
		return errorResponse(parsed);
	}

	const turnstileOK = await validateTurnstile(
		env,
		turnstileToken,
		request.headers.get("CF-Connecting-IP")
	);
	if (!turnstileOK) {
		return errorResponse("Turnstile verification failed", 403);
	}

	let response: Response;
	try {
		response = await fetch(parsed.toString(), {
			redirect: "manual",
			signal: AbortSignal.timeout(DIRECTORY_FETCH_TIMEOUT_MS),
		});
	} catch {
		return errorResponse("Directory fetch failed", 502);
	}

	if (!response.ok) {
		return errorResponse(`Directory returned HTTP ${response.status}`, 502);
	}

	let text: string;
	try {
		text = await readTextWithLimit(response, DIRECTORY_RESPONSE_MAX_BYTES);
	} catch {
		return errorResponse("Directory response is too large", 502);
	}

	return new Response(text, {
		headers: {
			"Access-Control-Allow-Origin": origin,
			"Content-Type":
				response.headers.get("Content-Type") ?? "application/json",
		},
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

		if (url.pathname === "/v0/api/proxy-directory") {
			return proxyDirectoryRequest(request, env);
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
