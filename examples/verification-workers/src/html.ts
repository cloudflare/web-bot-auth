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

const generateHTML = (status?: boolean) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Identify Bots with HTTP Message Signatures</title>
  <style>* {
  margin: 0;
  padding: 0;
  border: none;
}

html { font-size: 62.5%; }

body {
  margin: 0;
  font-family: open sans, HelveticaNeue, Helvetica Neue, Helvetica, Arial, sans-serif;
  font-size: 1.5em;
  font-weight: 400;
  line-height: 1.6;
  color: #222;
}

h1 {
  font-family: Montserrat, helvetica, arial, sans-serif;
  font-size: 6rem;
  font-weight: 700;
  line-height: 6.5rem;
  text-align: center;
  color: black;
}
h3 {
  font-size: 2rem;
  font-weight: 600;
  line-height: 2.4rem;
  padding-top: 3rem;
  padding-bottom: .5rem;
}
h4 {
  font-size: 1.6rem;
  font-weight: 600;
  line-height: 2.6rem;
  padding: 1.4rem 0 1rem;
}
p {
  font-size: 1.6rem;
  padding-bottom: 1.3rem;
}
a { color: #125CCA; }
a:hover { color: #3BA3BB; }

header {
  position: relative;
  width: 100%;
  padding: 40px 0 65px;
  background-color: #DDE8EF;
}

header.success {
  background-color: #B3E1EF;
}

header.failure {
  background-color: #d44613;
}

header h3 {
  text-align: center;
}

.toc li {
  display: inline-block;
  position: relative;
  width: 49%;
  box-sizing: border-box;
  background-color: #DDE8EF;
  list-style-type: none;
  text-align: center;
}
.toc li:not(:first-of-type) {
  margin-left: 2%;
}
.toc li:hover { background-color: #B3E1EF; }
.toc a {
  display: inline-block;
  width: 100%;
  padding: 2px 0 3px;
  font-weight: 600;
  text-decoration: none;
  color: #464646;
}

section {
  position: relative;
  margin: 20px 0;
  padding: 0 20px;
}
section > * {
  max-width: 640px;
  margin: 0 auto;
}

.illustrated {  }
img {
  display: block;
  margin: 0 auto;
  padding: 2rem 0;
}
.illustration {
  max-height: 350px;
  max-width: 100%;
}

#intro {
  padding-top: 65px;
}
#intro p {
  font-weight: 400;
  font-size: 1.8rem;
  line-height: 3rem;
  padding-top: 2rem;
}

/*table style from bootstrap*/
table {
  width: 100%;
  margin-bottom: 20px;
  padding: 1rem 0;
}
table th,
table td {
  padding: 8px;
  line-height: 1.42857143;
  vertical-align: top;
  border-bottom: 1px solid #ddd;
}
table > thead > tr > th {
  vertical-align: bottom;
  border-bottom: 2px solid #ddd;
}
.table-condensed th,
.table-condensed td {
  padding: 5px;
}

.form-inline {
  padding: 1.5rem 3rem 3rem;
  background-color: #DDE8EF;
}
label { display: block; }
input, button {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
  font-family: open sans, sans-serif;
  font-size: 16px;
  font-weight: 400;
  margin-top: 1rem;
}
input {
  padding: 6px 12px;
  width: 45%;
}
button {
  color: white;
  background-color: #F1592A;
  border-radius: 6px;
  padding: 6px 12px;
}
button:hover,
button:focus {
  outline: none;
  box-shadow: 0 0 0 3px #3BA3BD;
}
button:active {
  box-shadow: inset 0 1px 1px 1px rgba(0,0,0,.4);
}

.question-list {
  margin-bottom: 2rem;
}
.question-list li {
  margin-left: 1.8rem;
}

footer {
  border-top: 1px solid #ccc;
  padding: 1rem 3rem;
}
.text-muted {
  font-size: 13px;
  color: #888;
}
</style>
</head>
<body>
  <header id="top" ${status !== undefined ? `class="${status ? "success" : "failure"}"` : ""}>
    <h1>Identify Bots with HTTP Message Signatures</h1>
    <h3>
    ${status === undefined ? "Your browser does not support HTTP Message Signatures" : ""}
    ${status === false ? "The Signature you sent does not validate against test public key" : ""}
    ${status === true ? "You successfully authenticated as owning the test public key" : ""}
    </h3>
  </header>
  <section>
    <p>
      HTTP Message Signatures are a mechanism to create, encode, and verify signatures over components of an HTTP message.
      They are standardised by the IETF in <a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421</a>.

      This website validates the presence of such signature as defined in <a href="https://github.com/thibmeu/http-message-signatures-directory">draft-meunier-web-bot-auth-architecture</a>.
    </p>
    <p>
      This website checks for an Ed25519 signature on incoming request. They should be signed by a test public key defined in <a href="https://datatracker.ietf.org/doc/html/rfc9421#name-example-ed25519-test-key">Appendix B.1.4 of RFC 9421</a>.
    </p>

    <h2>Why do platforms and websites need this?</h2>
    <p>
      As a platform provider, I would like to ensure websites are able to identify requests originating from my service.
      At the moment, I share IP ranges, but this is long to deploy, cumbersome to maintain, and costly, especially with the multiplication of services, and the need to localise outgoing traffic with a forward proxy.
      It's even more pressing as I onboard multiple companies on my platform that need to have their own identity.
      And user agent headers do not have any integrity protection.
    </p>
    <p>
      It's time for websites to know who's calling, and for platforms to prove it.
    </p>

    <h2>How to retrieve the public key used by this website</h2>
    <p>
      We define a key directory accessible under <a>/.well-known/http-message-signatures-directory</a>

      The directory looks as follow
      </p>
      <pre>{
  "keys": [
    {
      "kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U",
      "kty":"OKP",
      "crv":"Ed25519",
      "x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
      "nbf": 1743465600000
    }
  ]
}
      </pre>

      <p>
      Parameters are defined as follow:

      <ul>
        <li><strong>keys</strong>: an array of serialised JSON Web Key defined by <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517</a>
          <ul style="padding-left:1em">
          <li><strong>kid</strong>: JWK Thumbprint as defined in <a href="https://www.rfc-editor.org/rfc/rfc7638.html">RFC 7638</a></li>
          <li><strong>nbf</strong>: start of the validity of the public key as a unix timestamp in milliseconds defined by <a href="https://www.rfc-editor.org/rfc/rfc7519.html">RFC 7519</a></li>
          <li><strong>exp</strong>: end of the validity of the public key as a unix timestamp in milliseconds defined by <a href="https://www.rfc-editor.org/rfc/rfc7519.html">RFC 7519</a></li>
          <li><strong>...jwk</strong>: JWK public cryptographic material</li>
          </ul>
        </li>
        <li><strong>purpose</strong>: represents what a signature means. Examples could be the draft for <a href="https://github.com/martinthomson/sup-ai">Short usage preference proposed</a>.</li>
      </ul>
    </p>

    <h2>It's hard to debug. How can this website help?</h2>
    <p>
    This website expose an endpoint dropping incoming request headers on <a>/debug</a>
    </p>

    <h2>I have comments and want to contribute. Where do I go?</h2>
    <p>
    First off, this is fantastic news!
    </p>
    <p>
    To contribute to this website, you can go to <a href="https://github.com/cloudflareresearch/web-bot-auth">cloudflareresearch/web-bot-auth</a>.
    </p>
    <p>
    To contribute to the standard discussion, the current draft is hosted on <a href="https://github.com/thibmeu/http-message-signatures-directory">thibmeu/http-message-signatures-directory</a>, and is being discussed on <a href="https://mailarchive.ietf.org/arch/browse/web-bot-auth/">web-bot-auth</a> IETF mailing list.
    </p>
  </section>
</body>
</html>`;

export const neutralHTML = generateHTML();
export const invalidHTML = generateHTML(false);
export const validHTML = generateHTML(true);
