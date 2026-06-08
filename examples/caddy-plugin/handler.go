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
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	sfv "github.com/dunglas/httpsfv"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
)

type SignatureValidator struct {
	keys httpsig.KeyFetcher
}

type keySpecs map[string]httpsig.KeySpec

func (ks keySpecs) addJWK(keyData []byte) (string, error) {
	keySpec, err := keySpecFromJWK(keyData)
	if err != nil {
		return "", err
	}
	if _, exists := ks[keySpec.KeyID]; exists {
		return keySpec.KeyID, nil
	}
	ks[keySpec.KeyID] = keySpec
	return keySpec.KeyID, nil
}

func keySpecFromJWK(keyData []byte) (httpsig.KeySpec, error) {
	pubKey, err := jwk.ParseKey(keyData)
	if err != nil {
		return httpsig.KeySpec{}, fmt.Errorf("parsing public key: %w", err)
	}

	thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return httpsig.KeySpec{}, fmt.Errorf("cannot generate key id from key: %w", err)
	}
	keyID := base64.RawURLEncoding.EncodeToString(thumbprint)
	publicKey, err := jwk.PublicRawKeyOf(pubKey)
	if err != nil {
		return httpsig.KeySpec{}, fmt.Errorf("extracting public key: %w", err)
	}

	return httpsig.KeySpec{
		KeyID:  keyID,
		Algo:   httpsig.Algo_ED25519,
		PubKey: publicKey,
	}, nil
}

func NewValidator(keys keySpecs) (*SignatureValidator, error) {
	if len(keys) == 0 {
		return nil, errors.New("no signature keys loaded")
	}

	return &SignatureValidator{keys: keyman.NewKeyFetchInMemory(keys)}, nil
}

func verifyProfile(label string) httpsig.VerifyProfile {
	return httpsig.VerifyProfile{
		AllowedAlgorithms:    []httpsig.Algorithm{httpsig.Algo_ED25519},
		RequiredFields:       httpsig.Fields("@authority"),
		RequiredMetadata:     httpsig.DefaultVerifyProfile.RequiredMetadata,
		DisallowedMetadata:   []httpsig.Metadata{},
		CreatedValidDuration: time.Minute * 5, // Signatures must have been created within the last 5 minutes
		ExpiredSkew:          time.Minute,     // If the created parameter is present, the Date header cannot be more than a minute off.
		SignatureLabel:       label,
	}
}

func signatureLabels(r *http.Request) ([]string, error) {
	signatureInput := r.Header.Get("Signature-Input")
	if signatureInput == "" {
		return nil, errors.New("missing signature-input header")
	}
	dictionary, err := sfv.UnmarshalDictionary([]string{signatureInput})
	if err != nil {
		return nil, err
	}
	return dictionary.Names(), nil
}

func (v *SignatureValidator) Validate(r *http.Request) (string, error) {
	labels, err := signatureLabels(r)
	if err != nil {
		return "", err
	}
	var lastErr error
	for _, label := range labels {
		verifier, err := httpsig.NewVerifier(v.keys, verifyProfile(label))
		if err != nil {
			return "", fmt.Errorf("creating verifier: %w", err)
		}
		result, err := verifier.Verify(r)
		if err != nil {
			lastErr = err
			continue
		}
		if !result.Verified {
			lastErr = errors.New("request not signed or signature is invalid")
			continue
		}

		keyID, err := result.KeyID()
		if err != nil {
			return "", err
		}
		return keyID, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("request not signed or signature is invalid")
}
