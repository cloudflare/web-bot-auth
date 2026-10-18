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
	"testing"

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
	keys := keySpecs{}
	jwk, privateKey, keyID := testJWK(t)
	if _, err := keys.addJWK(jwk); err != nil {
		t.Fatalf("add key: %v", err)
	}
	validator, err := NewValidator(keys)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}

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
	keys := keySpecs{}
	jwk, privateKey, keyID := testJWK(t)
	if _, err := keys.addJWK(jwk); err != nil {
		t.Fatalf("add key: %v", err)
	}
	validator, err := NewValidator(keys)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	agentMember := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{"key": "sig1"}}
	otherMember := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{"key": "sig2"}}
	legacyAgent := httpsiggo.SignedField{Name: "signature-agent", Parameters: map[string]any{}}
	authority := httpsiggo.Fields("@authority")[0]
	twoAgents := `sig1="https://bot.example", sig2="https://other.example"`

	for _, tc := range []struct {
		name  string
		opts  signingOptions
		valid bool
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
		{name: "covered member missing from Signature-Agent", opts: signingOptions{signatureAgent: `sig2="https://bot.example"`, fields: []httpsiggo.SignedField{authority, agentMember}}},
		{name: "Signature-Agent neither Dictionary nor String", opts: signingOptions{signatureAgent: `https://bot.example`, fields: []httpsiggo.SignedField{authority, legacyAgent}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator.Validate(signedRequestWith(t, privateKey, keyID, tc.opts))
			if tc.valid && err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("expected the request to be rejected")
			}
		})
	}
}
