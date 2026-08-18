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
	SignatureAgentCard,
	SignatureAgentEntry,
	VerifierFactory,
	directoryResponseHeaders,
	helpers,
	jwkToKeyID,
	parseRegistry,
	parseSignatureAgentCard,
	parseSignatureAgentHeader,
	recommendedComponents,
	signatureHeaders,
	verify,
} from "web-bot-auth";
import { generateDebugHTML } from "./debug-html";
import { invalidHTML, neutralHTML, validHTML } from "./index-html";
import { proxyDirectoryRequest } from "./proxy-directory";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };
import { signerFromJWK, verifier } from "web-bot-auth/crypto";

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
		"expected-user-agent": "Mozilla/5.0 ExampleBot",
		"rfc9309-product-token": "ExampleBot",
		"rfc9309-compliance": ["User-Agent", "Allow", "Disallow", "Content-Usage"],
		trigger: "fetcher",
		purpose: "example",
		"rate-control": "429",
		jwks_uri: `${origin}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`,
		ips_uri: `${origin}/ips.json`,
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

async function getSigner(): Promise<Signer> {
	return signerFromJWK(jwk);
}

function verifyEd25519(directory: Directory): VerifierFactory {
	// Awaited inside the factory, which may return a Promise so that key material can be resolved
	// per signature rather than once up front.
	return async (signature, context) =>
		verifier(
			await crypto.subtle.importKey(
				"jwk",
				directory.keys[0],
				{ name: "Ed25519" },
				true,
				["verify"]
			)
		)(signature, context);
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
		if (signatureAgent) {
			const parsed = parseSignatureAgentHeader(signatureAgent);
			const entry = parsed.entries[0];
			if (entry === undefined) {
				throw new Error("Signature-Agent header has no entries");
			}
			if (new URL(entry.uri).origin === new URL(env.SIGNATURE_AGENT).origin) {
				directory = await getExampleDirectory();
			} else {
				directory = await fetchDirectory(entry);
			}
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
					"content-type": MediaType.HTTP_MESSAGE_SIGNATURES_DIRECTORY,
				},
			});

			const signedHeaders = await directoryResponseHeaders(
				{ request, response },
				[await getSigner()],
				{ created: new Date(), expires: new Date(Date.now() + 300_000) }
			);
			response.headers.set("Signature", signedHeaders.Signature);
			response.headers.set("Signature-Input", signedHeaders["Signature-Input"]);
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
		const signedHeaders = await signatureHeaders(request, await getSigner(), {
			components: recommendedComponents("sig1"),
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
