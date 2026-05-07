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

// test/index.spec.ts
import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { afterEach, describe, it, expect, vi } from "vitest";
import worker from "../src/index";

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const sampleURL = "https://example.com";
const validatorURL = `${sampleURL}/v0/api/validate-directory`;
const directoryURL = `${sampleURL}/.well-known/http-message-signatures-directory`;
const turnstileVerifyURL =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";

const validatorHeaders = {
	"CF-Connecting-IP": "192.0.2.1",
};

function validatorRequest(body: Record<string, string>): Request {
	const formData = new FormData();
	for (const [name, value] of Object.entries(body)) {
		formData.append(name, value);
	}
	return new IncomingRequest(validatorURL, {
		body: formData,
		headers: validatorHeaders,
		method: "POST",
	});
}

function mockedFetch(targetResponse: Response): ReturnType<typeof vi.fn> {
	return vi.fn((input: RequestInfo | URL) => {
		const url = input instanceof Request ? input.url : input.toString();
		if (url === turnstileVerifyURL) {
			return Promise.resolve(Response.json({ success: true }));
		}
		return Promise.resolve(targetResponse.clone());
	});
}

async function fetchValidator(body: Record<string, string>): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(validatorRequest(body), env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("/ endpoint", () => {
	it("responds with HTTP 200", async () => {
		const request = new IncomingRequest(sampleURL);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toEqual(200);
	});
});

describe("/debug endpoint", () => {
	it("responds with request headers", async () => {
		const headers = { test: "this is a test header" };
		const request = new Request(`${sampleURL}/debug`, { headers });
		const response = await SELF.fetch(request);
		const headersString = Object.entries(headers)
			.map(([k, v]) => `${k}: ${v}`)
			.join("\n");
		expect(await response.text()).toMatch(headersString);
	});
});

describe("/v0/api/validate-directory endpoint", () => {
	it("rejects non-POST requests", async () => {
		const request = new IncomingRequest(validatorURL, {
			headers: validatorHeaders,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(405);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Method not allowed"],
			warnings: [],
		});
	});

	it("requires a Turnstile token", async () => {
		const response = await fetchValidator({ url: directoryURL });

		expect(response.status).toEqual(400);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Missing Turnstile token"],
			warnings: [],
		});
	});

	it("rejects failed Turnstile verification", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(() => Promise.resolve(Response.json({ success: false })))
		);

		const response = await fetchValidator({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(403);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Turnstile verification failed"],
			warnings: [],
		});
	});

	it("rejects custom target ports", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);

		const response = await fetchValidator({
			url: "https://example.com:8443/.well-known/http-message-signatures-directory",
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(400);
		expect(fetch).not.toHaveBeenCalled();
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Directory URL must not use a custom port"],
			warnings: [],
		});
	});

	it("reports target fetch failures", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn((input: RequestInfo | URL) => {
				const url = input instanceof Request ? input.url : input.toString();
				if (url === turnstileVerifyURL) {
					return Promise.resolve(Response.json({ success: true }));
				}
				return Promise.reject(new Error("network failed"));
			})
		);

		const response = await fetchValidator({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(502);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Directory fetch failed"],
			warnings: [],
		});
	});

	it("does not follow target redirects", async () => {
		const fetch = mockedFetch(
			new Response(null, {
				headers: { Location: "https://example.com:8443/anything" },
				status: 302,
			})
		);
		vi.stubGlobal("fetch", fetch);

		const response = await fetchValidator({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(502);
		expect(fetch).toHaveBeenLastCalledWith(directoryURL, {
			redirect: "manual",
			signal: expect.any(AbortSignal),
		});
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Directory returned HTTP 302"],
			warnings: [],
		});
	});

	it("rejects oversized directory responses", async () => {
		vi.stubGlobal("fetch", mockedFetch(new Response("x".repeat(64_001))));

		const response = await fetchValidator({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(502);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Directory response is too large"],
			warnings: [],
		});
	});

	it("validates a directory and warns on loose content type", async () => {
		const directory = {
			keys: [{}],
			purpose: "",
		};
		vi.stubGlobal(
			"fetch",
			mockedFetch(
				new Response(JSON.stringify(directory), {
					headers: { "Content-Type": "text/plain" },
				})
			)
		);

		const response = await fetchValidator({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});

		expect(response.status).toEqual(200);
		expect(await response.json()).toEqual({
			ok: true,
			errors: [],
			directory,
			warnings: ["Directory returned unexpected Content-Type text/plain"],
		});
	});
});
