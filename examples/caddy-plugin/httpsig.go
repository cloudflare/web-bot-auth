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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("httpsig", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Middleware
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return &m, err
	},
	)
}

type Directory struct {
	Keys []json.RawMessage `json:"keys"`
}

type SignatureAgentCard struct {
	Name                *string           `json:"name"`
	Contact             *string           `json:"contact"`
	Logo                *string           `json:"logo"`
	ExpectedUserAgent   *string           `json:"expected-user-agent"`
	RFC9309ProductToken *string           `json:"rfc9309-product-token"`
	RFC9309Compliance   []string          `json:"rfc9309-compliance"`
	Trigger             *string           `json:"trigger"`
	Purpose             *string           `json:"purpose"`
	TargetedContent     *string           `json:"targeted-content"`
	RateControl         *string           `json:"rate-control"`
	RateExpectation     *string           `json:"rate-expectation"`
	KnownURLs           []string          `json:"known-urls"`
	Keys                []json.RawMessage `json:"keys"`
}

// Middleware struct to hold the configuration for the handler
type Middleware struct {
	RegistryURLs []string `json:"registry,omitempty"`
	validator    []SignatureValidator
	logger       *zap.Logger
}

// CaddyModule function to provide module information to Caddy
func (m Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.httpsig",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision method for setting up the validator with the public key
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	var signatureAgentCardURLs []string
	for _, u := range m.RegistryURLs {
		_, err := url.Parse(u)
		if err != nil {
			m.logger.Warn("failed to parse registry URL", zap.String("url", u), zap.Error(err))
			continue
		}

		// here we only fetch the first registry, but we could fetch multiple and aggregate keys
		resp, err := http.Get(m.RegistryURLs[0])
		if err != nil {
			m.logger.Warn("failed to fetch registry", zap.String("url", u), zap.Error(err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			m.logger.Warn("failed to fetch registry", zap.String("url", u), zap.Error(err))
			continue
		}

		// read the body as text
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			m.logger.Warn("failed to read registry response", zap.Error(err))
			continue
		}
		signatureAgentCardURLs = append(signatureAgentCardURLs, strings.Split(string(body), "\n")...)
	}

	for _, u := range signatureAgentCardURLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		_, err := url.Parse(u)
		if err != nil {
			m.logger.Warn("failed to parse signature-agent card URL", zap.String("url", u), zap.Error(err))
			continue
		}

		resp, err := http.Get(u)
		if err != nil {
			m.logger.Warn("failed to fetch signature-agent card", zap.String("url", u), zap.Error(err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			m.logger.Warn("failed to fetch signature-agent card", zap.String("url", u), zap.Error(err))
			continue
		}

		var card SignatureAgentCard
		err = json.NewDecoder(resp.Body).Decode(&card)
		if err != nil {
			m.logger.Warn("failed to decode signature-agent card", zap.String("url", u), zap.Error(err))
			continue
		}

		if card.Keys == nil || len(card.Keys) == 0 {
			m.logger.Warn("no keys found in the signature-agent card", zap.String("url", u))
			continue
		}

		validator, err := NewValidator(card.Keys[0])
		if err != nil {
			m.logger.Warn("failed to create validator for signature-agent card", zap.String("url", u), zap.Error(err))
			continue
		}
		m.validator = append(m.validator, *validator)
	}
	return nil
}

// ServeHTTP method to handle the request and validate the signature
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var err error
	for _, validator := range m.validator {
		// Try to validate the request with each validator
		err = validator.Validate(r)
		if err == nil {
			// If validation is successful, proceed to the next handler
			return next.ServeHTTP(w, r)
		}
	}
	m.logger.Info("Invalid HTTP signature", zap.Error(err))
	http.Error(w, "Invalid HTTP signature", http.StatusUnauthorized)
	return nil
}

// UnmarshalCaddyfile method to allow configuration via the Caddyfile
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "registry":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RegistryURLs = append(m.RegistryURLs, d.Val())
			default:
				return d.Errf("unknown option '%s'", d.Val())
			}
		}
	}
	return nil
}
