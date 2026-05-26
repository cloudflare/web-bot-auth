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

import { theme } from "./index-html";

const directoryPath = "/.well-known/http-message-signatures-directory";

function escapeAttribute(value: string): string {
	return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
}

function turnstileScript(siteKey: string): string {
	return siteKey.length > 0
		? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
		: "";
}

function turnstileWidget(siteKey: string): string {
	return siteKey.length > 0
		? `<div class="cf-turnstile" data-sitekey="${escapeAttribute(siteKey)}"></div>`
		: '<p class="text-muted">Turnstile is not configured for this deployment.</p>';
}

const debugStyle = `<style>
form {
  padding: 1.5rem 3rem 3rem;
  background-color: #DDE8EF;
}
input, select, textarea, button {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
  font-family: open sans, sans-serif;
  font-size: 16px;
  font-weight: 400;
  margin-top: 1rem;
}
select {
  background-color: white;
  border: 1px solid #999;
  box-sizing: border-box;
  padding: 8px 10px;
  width: 100%;
}
button {
  background-color: #2F6F8F;
  border-radius: 0;
}
button:hover { background-color: #255A74; }
input[type="url"],
textarea {
  border: 1px solid #999;
  box-sizing: border-box;
  display: block;
  font: inherit;
  margin: 0.5rem 0 1rem;
  max-width: 720px;
  padding: 8px 10px;
  width: 100%;
}
textarea {
  min-height: 7rem;
  resize: vertical;
}
.debug-tool {
  margin-bottom: 3rem;
}
.header-grid {
  display: grid;
  grid-template-columns: 16rem minmax(0, 1fr);
  gap: 1rem 1.5rem;
  align-items: start;
}
.header-grid .field {
  min-width: 0;
}
.header-grid label {
  font-weight: 600;
  margin-top: 1.7rem;
}
.header-grid textarea {
  margin-bottom: 0;
}
.header-grid input,
.header-grid select {
  margin-bottom: 0;
  max-width: 720px;
}
.validation-result {
  margin-top: 0.75rem;
}
.validation-result ul {
  padding-left: 1.5rem;
}
.validation-result li {
  margin-bottom: 0.25rem;
}
.validation-result pre {
  border: 1px solid #999;
  box-sizing: border-box;
  margin-top: 0.75rem;
  overflow-x: auto;
  padding: 1rem;
  white-space: pre-wrap;
}
@media (max-width: 640px) {
  .header-grid {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .header-grid label {
    margin-top: 1rem;
  }
}
</style>`;

export const generateDebugHTML = (turnstileSiteKey: string) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Debug HTTP Message Signatures</title>
  ${turnstileScript(turnstileSiteKey)}
  ${theme}
  ${debugStyle}
</head>
<body>
  <header id="top">
    <h1>Debug HTTP Message Signatures</h1>
    <h3>Validate key directories and inspect signature inputs.</h3>
  </header>
  <section>
    <p>
      This page collects debugging tools for Web Bot Auth implementations. Start by validating the key directory.
    </p>

    <div class="debug-tool">
      <h2>Validate key directory</h2>
      <p>
        Paste the full HTTPS URL for a <code>/.well-known/http-message-signatures-directory</code> endpoint to check whether it returns a usable directory.
      </p>
      <form id="directory-validator">
        <label for="directory-url">Directory URL</label>
        <input id="directory-url" name="url" type="url" placeholder="https://example.com/.well-known/http-message-signatures-directory" required />
        <p class="text-muted">URL path must end with <code>${directoryPath}</code>.</p>
        ${turnstileWidget(turnstileSiteKey)}
        <button type="submit">Validate directory</button>
        <div id="directory-validation-result" class="validation-result" aria-live="polite"></div>
      </form>
    </div>

    <div class="debug-tool">
      <h2>Get JWK keyid</h2>
      <p>
        Paste a JWK to compute its RFC 7638 SHA-256 thumbprint for use as <code>keyid</code>.
      </p>
      <form id="key-id-calculator">
        <label for="key-id-jwk">JWK</label>
        <textarea id="key-id-jwk" name="jwk" placeholder='{"kty":"OKP","crv":"Ed25519","x":"..."}' required></textarea>
        <button type="submit">Get keyid</button>
        <div id="key-id-result" class="validation-result" aria-live="polite"></div>
      </form>
    </div>

    <div class="debug-tool">
      <h2>Verify request headers</h2>
      <p>
        Paste the signed request target, verification JWK, and HTTP Message Signature headers here.
      </p>
      <form id="signature-header-validator">
        <div class="header-grid">
          <label for="signature-jwk">JWK</label>
          <div class="field">
            <textarea id="signature-jwk" name="jwk" placeholder='{"kty":"OKP","crv":"Ed25519","x":"..."}' required></textarea>
          </div>

          <label for="signature-method">Method</label>
          <div class="field">
            <select id="signature-method" name="method" required>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="PATCH">PATCH</option>
              <option value="DELETE">DELETE</option>
              <option value="HEAD">HEAD</option>
              <option value="OPTIONS">OPTIONS</option>
            </select>
          </div>

          <label for="signature-url">URL</label>
          <div class="field">
            <input id="signature-url" name="url" type="url" placeholder="https://example.com/resource" required />
          </div>

          <label for="signature-header">Signature</label>
          <div class="field">
            <textarea id="signature-header" name="signature" placeholder="sig1=:..." required></textarea>
          </div>

          <label for="signature-agent-header">Signature-Agent</label>
          <div class="field">
            <textarea id="signature-agent-header" name="signature-agent" placeholder='"https://example.com"'></textarea>
            <p class="text-muted">Accepted forms: <code>"&lt;url&gt;"</code> or <code>&lt;label&gt;="&lt;url&gt;"</code>.</p>
          </div>

          <label for="signature-input-header">Signature-Input</label>
          <div class="field">
            <textarea id="signature-input-header" name="signature-input" placeholder='sig1=("@method" "@target-uri");created=...' required></textarea>
          </div>
        </div>

        ${turnstileWidget(turnstileSiteKey)}

        <button type="submit">Verify headers</button>
        <div id="signature-header-validation-result" class="validation-result" aria-live="polite"></div>
      </form>
    </div>
  </section>
  <script>
    const form = document.getElementById("directory-validator");
    const result = document.getElementById("directory-validation-result");
    const keyIDForm = document.getElementById("key-id-calculator");
    const keyIDResult = document.getElementById("key-id-result");
    const keyIDJWK = document.getElementById("key-id-jwk");
    const signatureForm = document.getElementById("signature-header-validator");
    const signatureResult = document.getElementById("signature-header-validation-result");
    const signatureJWK = document.getElementById("signature-jwk");

    const appendMessagesTo = (target, heading, messages) => {
      if (messages.length === 0) {
        return;
      }
      const paragraph = document.createElement("p");
      paragraph.textContent = heading;
      const list = document.createElement("ul");
      for (const message of messages) {
        const item = document.createElement("li");
        item.textContent = message;
        list.append(item);
      }
      target.append(paragraph, list);
    };

    const appendMessages = (heading, messages) => {
      appendMessagesTo(result, heading, messages);
    };

    const directoryURLValidation = (value) => {
      try {
        const url = new URL(value);
        if (!url.pathname.endsWith("${directoryPath}")) {
          return "Directory URL path must end with ${directoryPath}";
        }
      } catch {
        return "Directory URL must be valid";
      }

      return undefined;
    };

    const signatureAgentValidation = (value) => {
      if (value.trim() === "") {
        return undefined;
      }

      const match = value.trim().match(/^(?:[a-z*][a-z0-9_.*-]*=)?"([^"]+)"$/);
      if (!match) {
        return 'Signature-Agent must be "<url>" or <label>="<url>"';
      }

      try {
        new URL(match[1]);
      } catch {
        return "Signature-Agent must contain a valid URL";
      }

      return undefined;
    };

    const validateKeys = async (directory) => {
      const errors = [];
      const warnings = [];
      let imported = 0;

      for (const [index, key] of directory.keys.entries()) {
        if (key.kty !== "OKP" || key.crv !== "Ed25519") {
          warnings.push("keys[" + index + "] is not an Ed25519 OKP key");
          continue;
        }
        try {
          await crypto.subtle.importKey("jwk", key, { name: "Ed25519" }, true, ["verify"]);
          imported += 1;
        } catch {
          errors.push("keys[" + index + "] could not be imported as Ed25519");
        }
      }

      if (imported === 0) {
        errors.push("Directory does not contain an importable Ed25519 key");
      }

      return { errors, warnings };
    };

    const validateDirectory = (directory) => {
      const errors = [];
      if (directory === null || typeof directory !== "object") {
        return { errors: ["Directory must be a JSON object"], warnings: [] };
      }

      if (!Array.isArray(directory.keys)) {
        errors.push("Directory must include a keys array");
      } else if (directory.keys.length === 0) {
        errors.push("Directory keys array must not be empty");
      } else {
        for (const [index, key] of directory.keys.entries()) {
          if (key === null || typeof key !== "object") {
            errors.push("keys[" + index + "] must be a JSON object");
          }
        }
      }

      if (directory.purpose !== undefined && typeof directory.purpose !== "string") {
        errors.push("Directory purpose must be a string when present");
      }

      return { errors, warnings: [] };
    };

    const appendDirectory = (directory) => {
      const heading = document.createElement("p");
      heading.textContent = "Fetched directory";
      const output = document.createElement("pre");
      output.textContent = JSON.stringify(directory, null, 2);
      result.append(heading, output);
    };

    const firstDirectoryKey = (directory) => {
      if (directory === null || typeof directory !== "object" || !Array.isArray(directory.keys) || directory.keys.length === 0) {
        return undefined;
      }
      const key = directory.keys[0];
      return key !== null && typeof key === "object" ? key : undefined;
    };

    const fillJWK = (jwk) => {
      const value = JSON.stringify(jwk, null, 2);
      keyIDJWK.value = value;
      signatureJWK.value = value;
    };

    const parseJWK = (value) => {
      let jwk;
      try {
        jwk = JSON.parse(value);
      } catch {
        throw new Error("JWK must be valid JSON");
      }
      if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
        throw new Error("JWK must be a JSON object");
      }
      return jwk;
    };

    const jwkThumbprintInput = (jwk) => {
      switch (jwk.kty) {
        case "EC":
          return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
        case "OKP":
          return { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
        case "RSA":
          return { e: jwk.e, kty: jwk.kty, n: jwk.n };
        default:
          throw new Error("Unsupported JWK kty");
      }
    };

    const bytesToBase64URL = (bytes) => {
      let binary = "";
      for (const byte of bytes) {
        binary += String.fromCharCode(byte);
      }
      return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    };

    const computeJWKKeyID = async (jwk) => {
      const input = JSON.stringify(jwkThumbprintInput(jwk));
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
      return bytesToBase64URL(new Uint8Array(digest));
    };

    const base64ToBytes = (value) => {
      const decoded = atob(value);
      const bytes = new Uint8Array(decoded.length);
      for (let index = 0; index < decoded.length; index += 1) {
        bytes[index] = decoded.charCodeAt(index);
      }
      return bytes;
    };

    const parseSignatureHeader = (key, header) => {
      const match = header.match(/^([\\w-]+)=:([A-Za-z0-9+/=]+):$/);
      if (!match) {
        throw new Error("Invalid Signature header");
      }
      if (match[1] !== key) {
        throw new Error("Signature label does not match Signature-Input label");
      }
      return base64ToBytes(match[2]);
    };

    const parseSignatureInputHeader = (header) => {
      const match = header.match(/^([\\w-]+)=\\(([^)]*)\\)(.*)$/);
      if (!match) {
        throw new Error("Invalid Signature-Input header");
      }

      const components = [];
      for (const component of match[2].matchAll(/"([^"]+)"/g)) {
        components.push(component[1].toLowerCase());
      }
      if (components.length === 0) {
        throw new Error("Signature-Input must contain at least one component");
      }

      const params = {};
      for (const parameter of match[3].matchAll(/;([^=]+)=("[^"]*"|[^;]+)/g)) {
        const name = parameter[1];
        const rawValue = parameter[2];
        const value = rawValue.startsWith('"') ? rawValue.slice(1, -1) : rawValue;
        params[name] = name === "created" || name === "expires" ? Number.parseInt(value, 10) : value;
      }

      return { key: match[1], components, params, input: header.replace(/^[^=]+=/, "") };
    };

    const componentValue = (component, request, headers) => {
      switch (component) {
        case "@method":
          return request.method.toUpperCase();
        case "@target-uri":
          return request.url.toString();
        case "@authority": {
          const port = request.url.port;
          const includePort = port !== "" && port !== "80" && port !== "443";
          return request.url.hostname + (includePort ? ":" + port : "");
        }
        case "@scheme":
          return request.url.protocol.slice(0, -1);
        case "@request-target":
          return request.url.pathname + request.url.search;
        case "@path":
          return request.url.pathname;
        case "@query":
          return request.url.search;
        default:
          return headers[component] || "";
      }
    };

    const buildSignedData = (parsed, request, headers) => {
      const parts = parsed.components.map((component) => '"' + component + '": ' + componentValue(component, request, headers));
      parts.push('"@signature-params": ' + parsed.input);
      return parts.join("\\n");
    };

    const validateWebBotAuthParams = (params) => {
      if (params.tag !== "web-bot-auth") {
        throw new Error("tag must be 'web-bot-auth'");
      }
      if (!params.keyid) {
        throw new Error("keyid MUST be defined");
      }
      const now = Date.now() / 1000;
      if (typeof params.created === "number" && params.created > now) {
        throw new Error("created in the future");
      }
      if (typeof params.expires === "number" && params.expires < now) {
        throw new Error("signature has expired");
      }
    };

    const verifySignatureLocally = async (data) => {
      const signatureAgentError = signatureAgentValidation(data.get("signature-agent") || "");
      if (signatureAgentError !== undefined) {
        throw new Error(signatureAgentError);
      }

      const key = parseJWK(data.get("jwk"));
      const keyID = await computeJWKKeyID(key);

      const parsed = parseSignatureInputHeader(data.get("signature-input"));
      validateWebBotAuthParams(parsed.params);
      if (parsed.params.keyid !== keyID) {
        throw new Error("JWK keyid does not match Signature-Input keyid");
      }

      const url = new URL(data.get("url"));
      const headers = {
        "signature": data.get("signature"),
        "signature-agent": data.get("signature-agent") || "",
        "signature-input": data.get("signature-input"),
      };
      const request = { method: data.get("method"), url };
      const signedData = buildSignedData(parsed, request, headers);
      const signature = parseSignatureHeader(parsed.key, data.get("signature"));
      const cryptoKey = await crypto.subtle.importKey("jwk", key, { name: "Ed25519" }, true, ["verify"]);
      return crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, signature, new TextEncoder().encode(signedData));
    };

    keyIDForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      keyIDResult.textContent = "Computing keyid...";

      try {
        const jwk = parseJWK(new FormData(keyIDForm).get("jwk"));
        const keyID = await computeJWKKeyID(jwk);
        keyIDResult.textContent = keyID;
        signatureJWK.value = JSON.stringify(jwk, null, 2);
      } catch (error) {
        keyIDResult.textContent = "Keyid calculation failed: " + (error instanceof Error ? error.message : String(error));
      }
    });

    signatureForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(signatureForm);
      signatureResult.textContent = "Verifying signature...";

      try {
        if (await verifySignatureLocally(data)) {
          signatureResult.textContent = "Signature is valid.";
        } else {
          signatureResult.textContent = "Signature check failed: invalid signature";
        }
      } catch (error) {
        signatureResult.textContent = "Signature check failed: " + (error instanceof Error ? error.message : String(error));
      } finally {
        if (window.turnstile) {
          window.turnstile.reset("#signature-header-validator .cf-turnstile");
        }
      }
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const directoryURL = data.get("url");
      result.textContent = "Checking directory...";

      const directoryError = directoryURLValidation(directoryURL);
      if (directoryError !== undefined) {
        result.replaceChildren();
        appendMessages("Directory check failed", [directoryError]);
        return;
      }

      try {
        const response = await fetch("/v0/api/proxy-directory", { method: "POST", body: data });
        const errors = [];
        const warnings = [];
        let directory;

        if (!response.ok) {
          const body = await response.json();
          errors.push(body.error || "Directory fetch failed");
        } else {
          const contentType = response.headers.get("Content-Type");
          const mediaType = contentType ? contentType.split(";", 1)[0].trim().toLowerCase() : "";
          if (mediaType !== "application/http-message-signatures-directory+json" && mediaType !== "application/json") {
            warnings.push("Directory returned unexpected Content-Type " + (contentType || "none"));
          }

          directory = await response.json();
          const shapeValidation = validateDirectory(directory);
          errors.push(...shapeValidation.errors);
          warnings.push(...shapeValidation.warnings);

          if (errors.length === 0) {
            const keyValidation = await validateKeys(directory);
            errors.push(...keyValidation.errors);
            warnings.push(...keyValidation.warnings);
          }
        }

        result.replaceChildren();
        if (errors.length === 0) {
          const paragraph = document.createElement("p");
          paragraph.textContent = "Directory looks valid.";
          result.append(paragraph);
        } else {
          appendMessages("Directory check failed", errors);
        }
        appendMessages("Warnings", warnings);
        if (typeof directory !== "undefined") {
          appendDirectory(directory);
          const key = firstDirectoryKey(directory);
          if (key !== undefined) {
            fillJWK(key);
          }
        }
      } catch {
        result.textContent = "Directory check failed.";
      } finally {
        if (window.turnstile) {
          window.turnstile.reset("#directory-validator .cf-turnstile");
        }
      }
    });
  </script>
</body>
</html>`;
