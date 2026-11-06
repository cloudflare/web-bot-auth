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
	HTTP_MESSAGE_SIGNATURES_DIRECTORY,
	SignatureAgentCard,
	jwkToKeyID,
	type SignatureAgentEntry,
	parseRegistry,
	parseSignatureAgentCard,
	sign,
	verify,
	type WebBotSigner,
} from "web-bot-auth";
import { signerFromJWK, verifierFromJWK } from "web-bot-auth/crypto";
import {
	component,
	createSignature,
	verifySignature as verifyMessageSignature,
	type FieldOccurrence,
	type RequestDescriptor,
	type ResponseDescriptor,
} from "http-message-sig";
import { parseDictionary } from "structured-headers";
import { generateDebugHTML } from "./debug-html";
import { invalidHTML, neutralHTML, validHTML } from "./index-html";
import { proxyDirectoryRequest, readTextWithLimit } from "./proxy-directory";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

const DIRECTORY_MEDIA_TYPE =
	"application/http-message-signatures-directory+json";

interface Directory {
	readonly keys: readonly JsonWebKey[];
	readonly purpose: string;
}

function errorMessage(error: unknown): string {
	if (!(error instanceof Error)) return String(error);
	return error.cause === undefined
		? error.message
		: `${error.message}: ${errorMessage(error.cause)}`;
}

async function getExampleDirectory(): Promise<Directory> {
	const signer = await getSigner();
	const key = {
		kid: signer.keyid,
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

function signatureAgentOrigin(env: Env): string {
	return new URL(env.SIGNATURE_AGENT).origin;
}

function getSignatureAgentCard(env: Env): SignatureAgentCard {
	const origin = signatureAgentOrigin(env);
	return parseSignatureAgentCard({
		client_id: `${origin}/signature-agent-card`,
		client_name: "Example Bot",
		client_uri: origin,
		logo_uri: `${origin}/favicon.png`,
		contacts: [],
		jwks_uri: `${origin}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`,
		ips_uri: `${origin}/ips.json`,
		web_bot_auth: {
			"expected-user-agent": "Mozilla/5.0 ExampleBot",
			"rfc9309-product-token": "ExampleBot",
			"rfc9309-compliance": [
				"User-Agent",
				"Allow",
				"Disallow",
				"Content-Usage",
			],
			trigger: "fetcher",
			purpose: "example",
			"rate-control": "429",
		},
	});
}

function registryResponse(env: Env): Response {
	const registry = `${signatureAgentOrigin(env)}/signature-agent-card\n`;
	parseRegistry(registry);
	return new Response(registry, { headers: { "content-type": "text/plain" } });
}

async function getSigner(): Promise<WebBotSigner> {
	return signerFromJWK(jwk);
}

async function fetchResource(uri: string): Promise<Response> {
	const url = new URL(uri);
	if (url.protocol !== "https:" || url.username || url.password || url.hash) {
		throw new Error("discovery requires HTTPS without credentials or fragment");
	}
	return fetch(uri, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
}

async function readResource(response: Response): Promise<string> {
	if (response.status !== 200) {
		await response.body?.cancel();
		throw new Error(`discovery returned HTTP ${response.status}`);
	}
	return readTextWithLimit(response, 64_000);
}

async function fetchDirectory(entry: SignatureAgentEntry, keyid: string) {
	let uri = entry.uri;
	if (entry.type === "cimd") {
		const card = parseSignatureAgentCard(
			JSON.parse(await readResource(await fetchResource(uri))),
			uri
		);
		if (card.jwks !== undefined) return resolveVerifier(card.jwks, keyid);
		if (card.jwks_uri === undefined) throw new Error("card has no keys");
		uri = card.jwks_uri;
	}
	const target = new URL(uri);
	const inferDirectory = entry.type === undefined && target.pathname === "/";
	if (inferDirectory) {
		target.pathname = HTTP_MESSAGE_SIGNATURES_DIRECTORY;
		target.search = "";
	}
	let response = await fetchResource(target.href);
	// Only absence permits fallback; a present directory must pass validation.
	if (inferDirectory && (response.status === 404 || response.status === 410)) {
		await response.body?.cancel();
		target.href = uri;
		response = await fetchResource(uri);
	}
	const body = await readResource(response);
	const wellKnown = target.pathname === HTTP_MESSAGE_SIGNATURES_DIRECTORY;
	if (
		wellKnown &&
		response.headers
			.get("content-type")
			?.split(";", 1)[0]
			?.trim()
			.toLowerCase() !== DIRECTORY_MEDIA_TYPE
	) {
		throw new Error("invalid well-known directory media type");
	}
	const { jwks } = parseSignatureAgentCard({ jwks: JSON.parse(body) });
	if (jwks === undefined) throw new Error("directory has no keys");
	const verifier = await resolveVerifier(jwks, keyid, wellKnown);
	if (wellKnown) {
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(body)
		);
		const advertised = parseDictionary(
			response.headers.get("content-digest") ?? ""
		).get("sha-256")?.[0];
		if (
			!(advertised instanceof ArrayBuffer) ||
			base64(new Uint8Array(advertised)) !== base64(new Uint8Array(digest))
		) {
			throw new Error("directory Content-Digest mismatch");
		}
		const proof = [
			...parseDictionary(response.headers.get("signature-input") ?? ""),
		].find(
			([, [, params]]) =>
				params.get("keyid") === keyid &&
				params.get("tag") === "http-message-signatures-directory"
		);
		if (proof === undefined)
			throw new Error("directory lacks a possession proof");
		await verifyMessageSignature(
			{
				kind: "response",
				status: response.status,
				fields: fields(response.headers),
				request: {
					kind: "request",
					method: "GET",
					targetUri: target.href,
					fields: [],
				},
			},
			{
				label: proof[0],
				policy: {
					algorithms: [verifier.algorithm],
					requiredComponents: [
						component("@authority", { req: true }),
						"content-digest",
					],
					requiredParameters: ["created", "expires", "keyid", "tag"],
					validate: ({ parameters }) =>
						parameters.tag === "http-message-signatures-directory",
				},
				resolveVerifier: () => verifier,
			}
		);
	}
	return verifier;
}

async function resolveVerifier(
	directory: Pick<Directory, "keys">,
	keyid: string,
	wellKnown = false
) {
	if (directory.keys.length > 100)
		throw new Error("directory contains too many keys");
	if (wellKnown) {
		for (const key of directory.keys) {
			if (!("kid" in key)) continue;
			const thumbprint = await jwkToKeyID(
				key,
				(data) => crypto.subtle.digest("SHA-256", data),
				(hash) => base64Url(new Uint8Array(hash))
			).catch(() => undefined);
			if (key.kid !== thumbprint)
				throw new Error("well-known JWK kid must match its thumbprint");
		}
	}
	for (const key of directory.keys) {
		try {
			const verifier = await verifierFromJWK(key);
			if (verifier.keyid === keyid) return verifier;
		} catch {
			continue;
		}
	}
	throw new Error(`unknown key ${keyid}`);
}

function fields(headers: Headers): FieldOccurrence[] {
	const output: FieldOccurrence[] = [];
	headers.forEach((value, name) => output.push({ name, value }));
	return output;
}

function base64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

function base64Url(bytes: Uint8Array): string {
	return base64(bytes)
		.replaceAll("+", "-")
		.replaceAll("/", "_")
		.replace(/=+$/, "");
}

async function signDirectoryResponse(
	request: Request,
	response: Response,
	signer: WebBotSigner
) {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		await response.clone().arrayBuffer()
	);
	response.headers.set(
		"content-digest",
		`sha-256=:${base64(new Uint8Array(digest))}:`
	);
	const requestDescriptor: RequestDescriptor = {
		kind: "request",
		method: request.method,
		targetUri: request.url,
		fields: fields(request.headers),
	};
	const responseDescriptor: ResponseDescriptor = {
		kind: "response",
		status: response.status,
		fields: fields(response.headers),
		request: requestDescriptor,
	};
	const created = Math.floor(Date.now() / 1000);
	return createSignature(responseDescriptor, {
		label: "binding0",
		signer,
		components: [component("@authority", { req: true }), "content-digest"],
		parameters: {
			created,
			expires: created + 300,
			keyid: signer.keyid,
			alg: signer.algorithm,
			tag: "http-message-signatures-directory",
		},
	});
}

const SignatureValidationStatus = {
	NEUTRAL: "neutral",
	INVALID: (message?: string) => `invalid${message ? `: ${message}` : ""}`,
	VALID: "valid",
} as const;
type SignatureValidationStatus = string;

async function verifySignature(
	request: Request
): Promise<SignatureValidationStatus> {
	if (request.headers.get("Signature") === null) {
		return SignatureValidationStatus.NEUTRAL;
	}

	try {
		await verify(request, {
			async resolver(candidate) {
				const entry = candidate.signatureAgent;
				return entry === undefined
					? resolveVerifier(await getExampleDirectory(), candidate.keyid)
					: fetchDirectory(entry, candidate.keyid);
			},
		});
	} catch (e) {
		return SignatureValidationStatus.INVALID(errorMessage(e));
	}

	console.log("Signature verified successfully");
	const signatureAgent = request.headers.get("Signature-Agent");
	if (signatureAgent !== null) {
		console.log(`Signature-Agent: "${signatureAgent}"`);
	}

	return SignatureValidationStatus.VALID;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		void ctx;
		const url = new URL(request.url);

		if (url.pathname.startsWith("/debug")) {
			return new Response(generateDebugHTML(env.TURNSTILE_SITE_KEY ?? ""), {
				headers: { "content-type": "text/html; charset=utf-8" },
			});
		}

		if (url.pathname.startsWith("/v0/api/verify")) {
			const status = await verifySignature(request);
			return new Response(status);
		}

		if (url.pathname === "/v0/api/proxy-directory") {
			return proxyDirectoryRequest(request, env);
		}

		if (url.pathname.startsWith(HTTP_MESSAGE_SIGNATURES_DIRECTORY)) {
			const directory = await getExampleDirectory();
			const response = new Response(JSON.stringify(directory), {
				headers: {
					"content-type": DIRECTORY_MEDIA_TYPE,
				},
			});

			const signedHeaders = await signDirectoryResponse(
				request,
				response,
				await getSigner()
			);
			response.headers.set("Signature", signedHeaders.signature);
			response.headers.set("Signature-Input", signedHeaders.signatureInput);
			return response;
		}

		if (url.pathname === "/signature-agent-card") {
			return Response.json(getSignatureAgentCard(env));
		}

		if (url.pathname === "/test-registry.txt") {
			return registryResponse(env);
		}

		if (url.pathname === "/ips.json") {
			return env.ASSETS.fetch(request);
		}

		const status = await verifySignature(request);
		switch (status) {
			case SignatureValidationStatus.NEUTRAL:
				return new Response(neutralHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			case SignatureValidationStatus.VALID:
				return new Response(validHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			default:
				return new Response(invalidHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
		}
	},
	// On a schedule, send a web-bot-auth signed request to a target endpoint
	async scheduled(ctx, env, ectx) {
		void ectx;
		const headers = {
			"Signature-Agent": `sig1="${signatureAgentOrigin(env)}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}"`,
		};
		const request = new Request(env.TARGET_URL, { headers });
		const created = new Date(ctx.scheduledTime);
		const expires = new Date(created.getTime() + 300_000);
		const signedHeaders = await sign(request, {
			signer: await getSigner(),
			created,
			expires,
		});
		await fetch(
			new Request(request.url, {
				headers: {
					Signature: signedHeaders.signature,
					"Signature-Input": signedHeaders.signatureInput,
					...headers,
				},
			})
		);
	},
} satisfies ExportedHandler<Env>;
