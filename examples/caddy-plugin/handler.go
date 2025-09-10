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

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/remitly-oss/httpsig-go"
	"github.com/remitly-oss/httpsig-go/keyman"
)

type SignatureValidator struct {
	Verifier *httpsig.Verifier
}

func NewValidator(keyData []byte) (*SignatureValidator, error) {
	pubKey, err := jwk.ParseKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key id from key: %w", err)
	}
	keyid := base64.RawURLEncoding.EncodeToString(thumbprint)
	pk, _ := jwk.PublicRawKeyOf(pubKey)

	kf := keyman.NewKeyFetchInMemory(map[string]httpsig.KeySpec{
		keyid: {
			KeyID:  keyid,
			Algo:   httpsig.Algo_ED25519,
			PubKey: pk,
		},
	})

	verifier, err := httpsig.NewVerifier(kf, httpsig.VerifyProfile{
		AllowedAlgorithms:    []httpsig.Algorithm{httpsig.Algo_ED25519},
		RequiredFields:       httpsig.Fields("@authority"),
		RequiredMetadata:     httpsig.DefaultVerifyProfile.RequiredMetadata,
		DisallowedMetadata:   []httpsig.Metadata{},
		CreatedValidDuration: time.Minute * 5, // Signatures must have been created within the last 5 minutes
		DateFieldSkew:        time.Minute,     // If the created parameter is present, the Date header cannot be more than a minute off.
	})
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return &SignatureValidator{Verifier: verifier}, nil
}

func (v *SignatureValidator) Validate(r *http.Request) error {
	result, err := v.Verifier.Verify(r)
	if err != nil {
		return err
	}

	if !result.Verified {
		return errors.New("request not signed or signature is invalid")
	}

	return nil
}
