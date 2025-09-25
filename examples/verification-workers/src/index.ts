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
import { invalidHTML, neutralHTML, validHTML } from "./html";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };
import { Ed25519Signer } from "web-bot-auth/crypto";

const getDirectory = async (): Promise<Directory> => {
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
};

const getSigner = async (): Promise<Signer> => {
	return Ed25519Signer.fromJWK(jwk);
};

function verifyEd25519(
	directory: Directory
): (
	data: string,
	signature: Uint8Array,
	params: VerificationParams
) => Promise<void> {
	return async (data, signature, params) => {
		// note that here we use getDirectory, but this is as simple as a fetch
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
	INVALID: "invalid",
	VALID: "valid",
} as const;
type SignatureValidationStatus =
	(typeof SignatureValidationStatus)[keyof typeof SignatureValidationStatus];

async function verifySignature(
	env: Env,
	request: Request
): Promise<SignatureValidationStatus> {
	if (request.headers.get("Signature") === null) {
		return SignatureValidationStatus.NEUTRAL;
	}

	const signatureAgent = request.headers.get("Signature-Agent");
	let directory: Directory;
	if (signatureAgent && !signatureAgent.includes(env.SIGNATURE_AGENT)) {
		// make "some" validatation of the Signature-Agent header before making a request
		let parsed: string;
		try {
			parsed = JSON.parse(signatureAgent);
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
		} catch (_e) {
			console.error(
				`Failed to validate Signature-Agent header: ${signatureAgent}`
			);
			return SignatureValidationStatus.INVALID;
		}
		if (parsed.endsWith("/")) {
			parsed = parsed.slice(0, -1);
		}
		console.log(
			`Fetching \`Signature-Agent\` directory from: "${parsed}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}"`
		);
		directory = await fetch(
			`${parsed}${HTTP_MESSAGE_SIGNATURES_DIRECTORY}`
		).then((r) => r.json());
	} else {
		directory = await getDirectory();
	}

	try {
		await verify(request, verifyEd25519(directory));
	} catch (e) {
		console.error(e);
		return SignatureValidationStatus.INVALID;
	}

	console.log("Signature verified successfully");
	if (signatureAgent) {
		console.log(`Signature-Agent: "${signatureAgent}"`);
	}

	return SignatureValidationStatus.VALID;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
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

		if (url.pathname.startsWith(HTTP_MESSAGE_SIGNATURES_DIRECTORY)) {
			const directory = await getDirectory();

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

		const status = await verifySignature(request);
		switch (status) {
			case SignatureValidationStatus.NEUTRAL:
				return new Response(neutralHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			case SignatureValidationStatus.INVALID:
				return new Response(invalidHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
			case SignatureValidationStatus.VALID:
				return new Response(validHTML, {
					headers: { "content-type": "text/html; charset=utf-8" },
				});
		}
		return new Response("unhandled case", { status: 500 });
	},
	// On a schedule, send a web-bot-auth signed request to a target endpoint
	async scheduled(ctx, env, ectx) {
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
