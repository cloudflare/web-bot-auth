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
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var nopLogger = zap.NewNop()

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("httpsig", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Middleware
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return &m, err
	},
	)
}

type Middleware struct {
	DirectoryBase   string   `json:"directory_base,omitempty"`
	RegistryURLs    []string `json:"registry,omitempty"`
	FailOnLoadError bool     `json:"fail_on_load_error,omitempty"`
	validator       *SignatureValidator
	keyNets         map[string][]*net.IPNet
	logger          *zap.Logger
}

func (m Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.httpsig",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	keys := keySpecs{}
	m.keyNets = map[string][]*net.IPNet{}
	loadErrors := []error{}
	record := func(message string, err error, fields ...zap.Field) {
		if err == nil {
			err = errors.New(message)
		}
		loadErrors = append(loadErrors, fmt.Errorf("%s: %w", message, err))
		m.log().Warn(message, append(fields, zap.Error(err))...)
	}

	if m.DirectoryBase != "" {
		m.addKeysFromDirectory(keys, m.DirectoryBase, record)
	}
	for _, registryURL := range m.RegistryURLs {
		m.addKeysFromRegistry(keys, registryURL, record)
	}

	validator, err := NewValidator(keys)
	if err != nil {
		record("failed to create validator", err)
	} else {
		m.validator = validator
	}

	if m.FailOnLoadError && len(loadErrors) > 0 {
		return errors.Join(loadErrors...)
	}
	return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if m.validator == nil {
		m.log().Warn("HTTP signature validator is unavailable")
		http.Error(w, "HTTP signature validator is unavailable", http.StatusServiceUnavailable)
		return nil
	}

	keyID, err := m.validator.Validate(r)
	if err != nil {
		m.log().Info("Invalid HTTP signature", zap.Error(err))
		http.Error(w, "Invalid HTTP signature", http.StatusUnauthorized)
		return nil
	}

	if len(m.keyNets[keyID]) > 0 && !m.remoteIPAllowed(r.RemoteAddr, m.keyNets[keyID]) {
		m.log().Info("IP not in allowlist", zap.String("remote_addr", r.RemoteAddr))
		http.Error(w, "IP not allowed", http.StatusUnauthorized)
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "directory_base":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.DirectoryBase = d.Val()
			case "registry":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RegistryURLs = append(m.RegistryURLs, d.Val())
			case "fail_on_load_error":
				if !d.NextArg() {
					return d.ArgErr()
				}
				value, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid fail_on_load_error value %q", d.Val())
				}
				m.FailOnLoadError = value
			default:
				return d.Errf("unknown option '%s'", d.Val())
			}
		}
	}
	return nil
}

func (m *Middleware) log() *zap.Logger {
	if m.logger != nil {
		return m.logger
	}
	return nopLogger
}

func (m *Middleware) remoteIPAllowed(remoteAddr string, nets []*net.IPNet) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, ipNet := range nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
