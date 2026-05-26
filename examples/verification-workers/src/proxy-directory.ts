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

import { HTTP_MESSAGE_SIGNATURES_DIRECTORY } from "web-bot-auth";

const DIRECTORY_FETCH_TIMEOUT_MS = 5_000;
const DIRECTORY_RESPONSE_MAX_BYTES = 64_000;
const TURNSTILE_VERIFY_URL =
	"https://challenges.cloudflare.com/turnstile/v0/siteverify";

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

function errorResponse(error: string, status = 400): Response {
	return Response.json({ error }, { status });
}

function getStringFormValue(
	formData: FormData,
	name: string
): string | undefined {
	const value = formData.get(name);
	return typeof value === "string" && value.length > 0 ? value : undefined;
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

export async function proxyDirectoryRequest(
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
