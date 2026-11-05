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

package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	httpsiggo "github.com/remitly-oss/httpsig-go"
)

func TestNewValidatorRejectsEmptyKeys(t *testing.T) {
	_, err := NewValidator(keySpecs{})
	if err == nil {
		t.Fatal("expected empty key set to fail")
	}
}

func TestNewValidatorAcceptsMultipleKeys(t *testing.T) {
	keys := keySpecs{}
	firstJWK, _, firstKeyID := testJWK(t)
	secondJWK, secondPrivateKey, secondKeyID := testJWK(t)

	if firstKeyID == secondKeyID {
		t.Fatal("test generated duplicate key IDs")
	}
	if _, err := keys.addJWK(firstJWK); err != nil {
		t.Fatalf("add first key: %v", err)
	}
	if _, err := keys.addJWK(secondJWK); err != nil {
		t.Fatalf("add second key: %v", err)
	}

	validator, err := NewValidator(keys)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req := signedRequest(t, secondPrivateKey, secondKeyID)
	keyID, err := validator.Validate(req)
	if err != nil {
		t.Fatalf("validate request signed with second key: %v", err)
	}
	if keyID != secondKeyID {
		t.Fatalf("keyID = %q, want %q", keyID, secondKeyID)
	}
}

func TestKeySpecsCanSkipInvalidKeys(t *testing.T) {
	keys := keySpecs{}
	if _, err := keys.addJWK(json.RawMessage(`not json`)); err == nil {
		t.Fatal("expected invalid key to fail")
	}

	validJWK, privateKey, keyID := testJWK(t)
	if _, err := keys.addJWK(validJWK); err != nil {
		t.Fatalf("add valid key: %v", err)
	}

	validator, err := NewValidator(keys)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

	req := signedRequest(t, privateKey, keyID)
	if _, err := validator.Validate(req); err != nil {
		t.Fatalf("validate request signed with valid key: %v", err)
	}
}

func TestNewValidatorAcceptsAnySignatureLabel(t *testing.T) {
	validator, privateKey, keyID := newTestValidator(t)

	req := signedRequestWithLabel(t, privateKey, keyID, "bot-auth")
	gotKeyID, err := validator.Validate(req)
	if err != nil {
		t.Fatalf("validate request: %v", err)
	}
	if gotKeyID != keyID {
		t.Fatalf("keyID = %q, want %q", gotKeyID, keyID)
	}
}

func TestKeySpecsIgnoresDuplicateKeys(t *testing.T) {
	keys := keySpecs{}
	jwk, _, keyID := testJWK(t)

	firstKeyID, err := keys.addJWK(jwk)
	if err != nil {
		t.Fatalf("add key: %v", err)
	}
	secondKeyID, err := keys.addJWK(jwk)
	if err != nil {
		t.Fatalf("add duplicate key: %v", err)
	}
	if firstKeyID != keyID || secondKeyID != keyID {
		t.Fatalf("key IDs = %q, %q; want %q", firstKeyID, secondKeyID, keyID)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
}

func testJWK(t *testing.T) (json.RawMessage, ed25519.PrivateKey, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	jwk := json.RawMessage(fmt.Sprintf(
		`{"kty":"OKP","crv":"Ed25519","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(publicKey),
	))
	keySpec, err := keySpecFromJWK(jwk)
	if err != nil {
		t.Fatalf("parse generated JWK: %v", err)
	}

	return jwk, privateKey, keySpec.KeyID
}

// newTestValidator returns a validator that trusts one generated key.
func newTestValidator(t *testing.T) (*SignatureValidator, ed25519.PrivateKey, string) {
	t.Helper()

	keys := keySpecs{}
	jwk, privateKey, keyID := testJWK(t)
	if _, err := keys.addJWK(jwk); err != nil {
		t.Fatalf("add key: %v", err)
	}
	validator, err := NewValidator(keys)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return validator, privateKey, keyID
}

func signedRequest(t *testing.T, privateKey ed25519.PrivateKey, keyID string) *http.Request {
	t.Helper()
	return signedRequestWithLabel(t, privateKey, keyID, "sig1")
}

func signedRequestWithLabel(t *testing.T, privateKey ed25519.PrivateKey, keyID string, label string) *http.Request {
	t.Helper()
	return signedRequestWith(t, privateKey, keyID, signingOptions{label: label})
}

type signingOptions struct {
	label          string
	tag            string
	metadata       []httpsiggo.Metadata
	fields         []httpsiggo.SignedField
	signatureAgent string
}

func signedRequestWith(t *testing.T, privateKey ed25519.PrivateKey, keyID string, opts signingOptions) *http.Request {
	t.Helper()

	if opts.label == "" {
		opts.label = "sig1"
	}
	if opts.tag == "" {
		opts.tag = webBotAuthTag
	}
	if opts.metadata == nil {
		opts.metadata = []httpsiggo.Metadata{httpsiggo.MetaCreated, httpsiggo.MetaExpires, httpsiggo.MetaKeyID, httpsiggo.MetaTag}
	}
	if opts.fields == nil {
		opts.fields = httpsiggo.Fields("@authority")
	}
	req := httptest.NewRequest("GET", "https://example.com/data", nil)
	if opts.signatureAgent != "" {
		req.Header.Set("Signature-Agent", opts.signatureAgent)
	}
	signer, err := httpsiggo.NewSigner(httpsiggo.SigningProfile{
		Algorithm: httpsiggo.Algo_ED25519,
		Fields:    opts.fields,
		Metadata:  opts.metadata,
		Label:     opts.label,
	}, httpsiggo.SigningKey{
		Key:       privateKey,
		MetaKeyID: keyID,
		MetaTag:   opts.tag,
	})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}

func TestValidateAppliesWebBotAuthRules(t *testing.T) {
	validator, privateKey, keyID := newTestValidator(t)
	agentMember := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{"key": "sig1"}}
	otherMember := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{"key": "sig2"}}
	legacyAgent := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{}}
	authority := httpsiggo.Fields("@authority")[0]
	twoAgents := `sig1="https://bot.example", sig2="https://other.example"`

	for _, tc := range []struct {
		name  string
		opts  signingOptions
		valid bool
		// mutate, when set, changes the request after signing.
		mutate func(*http.Request)
		// wantErr, when set, is a substring the rejection error must contain.
		wantErr string
	}{
		{name: "covered member", opts: signingOptions{signatureAgent: `sig1="https://bot.example"`, fields: []httpsiggo.SignedField{authority, agentMember}}, valid: true},
		{name: "covered legacy string", opts: signingOptions{signatureAgent: `"https://bot.example"`, fields: []httpsiggo.SignedField{authority, legacyAgent}}, valid: true},
		{name: "covered member and another label's member", opts: signingOptions{signatureAgent: twoAgents, fields: []httpsiggo.SignedField{authority, agentMember, otherMember}}, valid: true},
		{name: "other tag", opts: signingOptions{tag: "other"}},
		{name: "no tag", opts: signingOptions{metadata: []httpsiggo.Metadata{httpsiggo.MetaCreated, httpsiggo.MetaExpires, httpsiggo.MetaKeyID}}},
		{name: "no expires", opts: signingOptions{metadata: []httpsiggo.Metadata{httpsiggo.MetaCreated, httpsiggo.MetaKeyID, httpsiggo.MetaTag}}},
		{name: "Signature-Agent not covered", opts: signingOptions{signatureAgent: `sig1="https://bot.example"`}},
		{name: "whole Signature-Agent dictionary covered", opts: signingOptions{signatureAgent: `sig1="https://bot.example"`, fields: []httpsiggo.SignedField{authority, legacyAgent}}},
		{name: "only another label's member covered", opts: signingOptions{signatureAgent: twoAgents, fields: []httpsiggo.SignedField{authority, otherMember}}},
		{
			name:    "covered member missing from Signature-Agent",
			opts:    signingOptions{signatureAgent: `sig1="https://bot.example"`, fields: []httpsiggo.SignedField{authority, agentMember}},
			mutate:  func(r *http.Request) { r.Header.Set("Signature-Agent", `sig2="https://bot.example"`) },
			wantErr: "does not cover its Signature-Agent member",
		},
		{name: "Signature-Agent neither Dictionary nor String", opts: signingOptions{signatureAgent: `https://bot.example`, fields: []httpsiggo.SignedField{authority, legacyAgent}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := signedRequestWith(t, privateKey, keyID, tc.opts)
			if tc.mutate != nil {
				tc.mutate(req)
			}
			_, err := validator.Validate(req)
			if tc.valid && err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("expected the request to be rejected")
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// signatureAgentMemberBase returns the RFC 9421 signature base for a signature that covers
// @authority and the Signature-Agent member keyed to label. member is the member's
// serialized value, and params is the signature's Signature-Input member value.
func signatureAgentMemberBase(authority, label, member, params string) string {
	return fmt.Sprintf("\"@authority\": %s\n\"signature-agent\";key=%q: %s\n\"@signature-params\": %s",
		authority, label, member, params)
}

// TestSignatureAgentMemberBaseMatchesTestVector checks signatureAgentMemberBase against
// the ed25519 vector that covers a Signature-Agent member in
// packages/web-bot-auth/test/test_data/web_bot_auth_architecture_v2.json. The vector
// signs with test-key-ed25519 from Appendix B.1.4 of RFC 9421.
func TestSignatureAgentMemberBaseMatchesTestVector(t *testing.T) {
	publicKey, err := base64.RawURLEncoding.DecodeString("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString("RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==")
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	params := `("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`

	base := signatureAgentMemberBase("example.com", "agent2", `"https://signature-agent.test"`, params)
	if !ed25519.Verify(publicKey, []byte(base), signature) {
		t.Fatalf("test vector signature does not verify over base:\n%s", base)
	}
}

// skipIfHTTPSigGoIgnoresKey skips a test while go.mod pins httpsig-go v1.2.2 without a
// replace directive. v1.2.2 ignores the key parameter of a covered component, so it
// computes the signature base over the whole Signature-Agent field. remitly-oss/httpsig-go#39
// fixes this. A dependency update to any other version runs the test, so the test fails
// if that version still lacks the fix.
func skipIfHTTPSigGoIgnoresKey(t *testing.T) {
	t.Helper()

	goMod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	pinned := regexp.MustCompile(`(?m)^\s*github\.com/remitly-oss/httpsig-go v1\.2\.2\s*$`)
	replaced := regexp.MustCompile(`github\.com/remitly-oss/httpsig-go(\s+v\S+)?\s*=>`)
	if pinned.Match(goMod) && !replaced.Match(goMod) {
		t.Skip("httpsig-go v1.2.2 ignores the key parameter; see remitly-oss/httpsig-go#39")
	}
}

// TestValidateAcceptsIndependentlySignedSignatureAgentMember signs the RFC 9421 signature
// base without httpsig-go. The cases in TestValidateAppliesWebBotAuthRules sign and verify
// with the same library, so they pass even when both compute the same wrong base.
func TestValidateAcceptsIndependentlySignedSignatureAgentMember(t *testing.T) {
	skipIfHTTPSigGoIgnoresKey(t)

	validator, privateKey, keyID := newTestValidator(t)
	created := time.Now().Unix()
	params := fmt.Sprintf(`("@authority" "signature-agent";key="sig1");created=%d;expires=%d;keyid="%s";alg="ed25519";tag="%s"`,
		created, created+60, keyID, webBotAuthTag)
	base := signatureAgentMemberBase("example.com", "sig1", `"https://bot.example"`, params)
	signature := ed25519.Sign(privateKey, []byte(base))

	req := httptest.NewRequest("GET", "https://example.com/data", nil)
	req.Header.Set("Signature-Agent", `sig1="https://bot.example", sig2="https://other.example"`)
	req.Header.Set("Signature-Input", "sig1="+params)
	req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(signature)+":")

	if _, err := validator.Validate(req); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestValidateChoosesAmongSeveralSignatures sends a valid web-bot-auth signature after one
// that must not be used, in a single header line and in separate header lines.
func TestValidateChoosesAmongSeveralSignatures(t *testing.T) {
	validator, privateKey, keyID := newTestValidator(t)
	_, untrustedKey, untrustedKeyID := testJWK(t)
	valid := signedRequestWith(t, privateKey, keyID, signingOptions{label: "sig2"})

	for _, first := range []struct {
		name string
		req  *http.Request
	}{
		{name: "other tag", req: signedRequestWith(t, privateKey, keyID, signingOptions{label: "sig1", tag: "other"})},
		{name: "untrusted key", req: signedRequestWith(t, untrustedKey, untrustedKeyID, signingOptions{label: "sig1"})},
	} {
		for _, layout := range []struct {
			name    string
			combine func(first, second string) []string
		}{
			{name: "one header line", combine: func(first, second string) []string { return []string{first + ", " + second} }},
			{name: "separate header lines", combine: func(first, second string) []string { return []string{first, second} }},
		} {
			t.Run(first.name+", "+layout.name, func(t *testing.T) {
				req := httptest.NewRequest("GET", "https://example.com/data", nil)
				for _, header := range []string{"Signature-Input", "Signature"} {
					req.Header[header] = layout.combine(first.req.Header.Get(header), valid.Header.Get(header))
				}
				gotKeyID, err := validator.Validate(req)
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				if gotKeyID != keyID {
					t.Fatalf("keyID = %q, want %q", gotKeyID, keyID)
				}
			})
		}
	}
}
