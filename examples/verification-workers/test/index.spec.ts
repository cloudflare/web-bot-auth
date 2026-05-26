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
const proxyURL = `${sampleURL}/v0/api/proxy-directory`;
const directoryURL = `${sampleURL}/.well-known/http-message-signatures-directory`;
const turnstileVerifyURL =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";

const validatorHeaders = {
	"CF-Connecting-IP": "192.0.2.1",
	Origin: sampleURL,
};

function validatorRequest(body: Record<string, string>): Request {
	const formData = new FormData();
	for (const [name, value] of Object.entries(body)) {
		formData.append(name, value);
	}
	return new IncomingRequest(proxyURL, {
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

	it("does not render the directory validator", async () => {
		const request = new IncomingRequest(sampleURL);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(await response.text()).not.toContain("directory-validator");
	});
});

describe("/debug endpoint", () => {
	it("responds with HTML", async () => {
		const request = new Request(`${sampleURL}/debug`);
		const response = await SELF.fetch(request);

		expect(response.status).toEqual(200);
		expect(response.headers.get("content-type")).toContain("text/html");
	});

	it("renders directory validation tools", async () => {
		const request = new Request(`${sampleURL}/debug`);
		const response = await SELF.fetch(request);
		const body = await response.text();

		expect(body).toContain("directory-validator");
		expect(body).toContain("Validate key directory");
		expect(body).toContain("Fetched directory");
		expect(body).toContain("signatureDirectoryURL.value = directoryURL");
		expect(body).not.toContain('data-sitekey=""');
	});

	it("renders signature header placeholders", async () => {
		const request = new Request(`${sampleURL}/debug`);
		const response = await SELF.fetch(request);
		const body = await response.text();

		expect(body).toContain("Verify request headers");
		expect(body).toContain("Directory URL");
		expect(body).toContain("Method");
		expect(body).toContain("URL");
		expect(body).toContain("Signature");
		expect(body).toContain("Signature-Agent");
		expect(body).toContain("Signature-Input");
		expect(body).toContain('parts.join("\\n")');
	});
});

describe("/.well-known/http-message-signatures-directory endpoint", () => {
	it("responds with a signed directory", async () => {
		const request = new IncomingRequest(directoryURL);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(200);
		expect(response.headers.get("content-type")).toContain(
			"application/http-message-signatures-directory+json"
		);
		expect(response.headers.get("Signature")).toBeTruthy();
		expect(response.headers.get("Signature-Input")).toBeTruthy();
		expect(await response.json()).toMatchObject({ purpose: "rag" });
	});
});

describe("/v0/api/proxy-directory endpoint", () => {
	it("rejects non-POST requests", async () => {
		const request = new IncomingRequest(proxyURL, {
			headers: validatorHeaders,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(405);
		expect(await response.json()).toEqual({
			error: "Method not allowed",
		});
	});

	it("requires same-origin requests", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);
		const request = validatorRequest({
			url: directoryURL,
			"cf-turnstile-response": "token",
		});
		request.headers.set("Origin", "https://attacker.example");
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toEqual(400);
		expect(fetch).not.toHaveBeenCalled();
		expect(await response.json()).toEqual({ error: "Bad request" });
	});

	it("requires a Turnstile token", async () => {
		const response = await fetchValidator({ url: directoryURL });

		expect(response.status).toEqual(400);
		expect(await response.json()).toEqual({
			error: "Missing Turnstile token",
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
			error: "Turnstile verification failed",
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
			error: "Directory URL must not use a custom port",
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
			error: "Directory fetch failed",
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
			error: "Directory returned HTTP 302",
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
			error: "Directory response is too large",
		});
	});

	it("proxies a directory response", async () => {
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
		expect(response.headers.get("Access-Control-Allow-Origin")).toEqual(
			sampleURL
		);
		expect(response.headers.get("Content-Type")).toEqual("text/plain");
		expect(await response.json()).toEqual(directory);
	});
});
