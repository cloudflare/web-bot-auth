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
import { describe, it, expect } from "vitest";
import worker from "../src/index";

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const sampleURL = "https://example.com";

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
	it("requires a url query parameter", async () => {
		const response = await SELF.fetch(
			new Request(`${sampleURL}/v0/api/validate-directory`)
		);

		expect(response.status).toEqual(400);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ["Missing url query parameter"],
		});
	});

	it("requires an https well-known directory URL", async () => {
		const response = await SELF.fetch(
			new Request(
				`${sampleURL}/v0/api/validate-directory?url=${encodeURIComponent(
					"http://example.com/"
				)}`
			)
		);

		expect(response.status).toEqual(400);
		expect(await response.json()).toEqual({
			ok: false,
			errors: ['Directory URL must use "https:"'],
		});
	});

	it("requires the directory well-known path", async () => {
		const response = await SELF.fetch(
			new Request(
				`${sampleURL}/v0/api/validate-directory?url=${encodeURIComponent(
					"https://example.com/"
				)}`
			)
		);

		expect(response.status).toEqual(400);
		expect(await response.json()).toEqual({
			ok: false,
			errors: [
				"Directory URL path must be /.well-known/http-message-signatures-directory",
			],
		});
	});
});
