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
	SignatureAgentEntry,
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
	type FieldOccurrence,
	type RequestDescriptor,
	type ResponseDescriptor,
} from "http-message-sig";
import { generateDebugHTML } from "./debug-html";
import { invalidHTML, neutralHTML, validHTML } from "./index-html";
import { proxyDirectoryRequest } from "./proxy-directory";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

const DIRECTORY_MEDIA_TYPE =
	"application/http-message-signatures-directory+json";

interface Directory {
	readonly keys: readonly JsonWebKey[];
	readonly purpose: string;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function jsonWebKeyFromUnknown(value: unknown): JsonWebKey {
	if (!isRecord(value)) {
		throw new Error("JWK must be an object");
	}
	if (typeof value.kty !== "string") {
		throw new Error("JWK kty must be a string");
	}
	const key: JsonWebKey = {
		alg: typeof value.alg === "string" ? value.alg : undefined,
		crv: typeof value.crv === "string" ? value.crv : undefined,
		d: typeof value.d === "string" ? value.d : undefined,
		e: typeof value.e === "string" ? value.e : undefined,
		kty: value.kty,
		kid: typeof value.kid === "string" ? value.kid : undefined,
		n: typeof value.n === "string" ? value.n : undefined,
		x: typeof value.x === "string" ? value.x : undefined,
		y: typeof value.y === "string" ? value.y : undefined,
	};
	if (Array.isArray(value.key_ops)) {
		const keyOps: string[] = [];
		for (const keyOp of value.key_ops) {
			if (typeof keyOp === "string") {
				keyOps.push(keyOp);
			}
		}
		key.key_ops = keyOps;
	}
	if (typeof value.ext === "boolean") {
		key.ext = value.ext;
	}
	return key;
}

function directoryFromUnknown(value: unknown): Directory {
	if (!isRecord(value) || !Array.isArray(value.keys)) {
		throw new Error("directory must contain keys");
	}
	return {
		keys: value.keys.map(jsonWebKeyFromUnknown),
		purpose: typeof value.purpose === "string" ? value.purpose : "",
	};
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

async function fetchJSON(url: string): Promise<unknown> {
	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`failed to fetch ${url}: ${response.status}`);
	}
	return response.json();
}

async function fetchDirectory(entry: SignatureAgentEntry): Promise<Directory> {
	if (entry.type === "directory") {
		const origin = new URL(entry.uri).origin;
		const directoryURL = `${origin}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`;
		console.log(`Fetching Signature-Agent directory from: ${directoryURL}`);
		return directoryFromUnknown(await fetchJSON(directoryURL));
	}

	if (entry.type === "jwks_uri") {
		console.log(`Fetching Signature-Agent JWKS from: ${entry.uri}`);
		return directoryFromUnknown(await fetchJSON(entry.uri));
	}

	const card = parseSignatureAgentCard(await fetchJSON(entry.uri), entry.uri);
	if (card.jwks !== undefined) {
		return { keys: card.jwks.keys, purpose: "" };
	}
	if (card.jwks_uri === undefined) {
		throw new Error("signature agent card must contain jwks or jwks_uri");
	}
	return directoryFromUnknown(await fetchJSON(card.jwks_uri));
}

async function getSigner(): Promise<WebBotSigner> {
	return signerFromJWK(jwk);
}

async function resolveVerifier(directory: Directory, keyid: string) {
	const key = directory.keys.find((candidate) => candidate.kid === keyid);
	if (key === undefined) throw new Error(`unknown key ${keyid}`);
	return verifierFromJWK(key);
}

function fields(headers: Headers): FieldOccurrence[] {
	const output: FieldOccurrence[] = [];
	headers.forEach((value, name) => output.push({ name, value }));
	return output;
}

function base64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
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
	env: Env,
	request: Request
): Promise<SignatureValidationStatus> {
	if (request.headers.get("Signature") === null) {
		return SignatureValidationStatus.NEUTRAL;
	}

	try {
		await verify(request, {
			async resolver(candidate) {
				const entry = candidate.signatureAgent;
				const directory =
					entry === undefined ||
					new URL(entry.uri).origin === new URL(env.SIGNATURE_AGENT).origin
						? await getExampleDirectory()
						: await fetchDirectory(entry);
				return resolveVerifier(directory, candidate.keyid);
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
			const status = await verifySignature(env, request);
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

		const status = await verifySignature(env, request);
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
			"Signature-Agent": `sig1="${env.SIGNATURE_AGENT}";type=directory`,
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
