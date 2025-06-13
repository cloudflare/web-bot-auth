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

async function verifyEd25519(
	data: string,
	signature: Uint8Array,
	params: VerificationParams
) {
	// note that here we use getDirectory, but this is as simple as a fetch
	const directory = await getDirectory();

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

		if (request.headers.get("Signature") === null) {
			return new Response(neutralHTML, {
				headers: { "content-type": "text/html" },
			});
		}

		try {
			await verify(request, verifyEd25519);
		} catch (e) {
			console.error(e);
			return new Response(invalidHTML, {
				headers: { "content-type": "text/html" },
			});
		}
		return new Response(validHTML, {
			headers: { "content-type": "text/html" },
		});
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
