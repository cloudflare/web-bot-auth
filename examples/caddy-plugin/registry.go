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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

type JWKSResponse struct {
	Keys []json.RawMessage `json:"keys"`
}

type JAFARPrefix struct {
	IPv4Prefix string `json:"ipv4Prefix,omitempty"`
	IPv6Prefix string `json:"ipv6Prefix,omitempty"`
}

type JAFARIPList struct {
	Prefixes []JAFARPrefix `json:"prefixes"`
}

type SignatureAgentCard struct {
	JWKSUri *string           `json:"jwks_uri"`
	IPSUri  *string           `json:"ips_uri"`
	Keys    []json.RawMessage `json:"keys"`
}

func (m *Middleware) addKeysFromRegistry(keys keySpecs, registryURL string, record func(string, error, ...zap.Field)) {
	for _, cardURL := range cardURLsFromRegistry(registryURL, record) {
		m.addKeysFromCard(keys, cardURL, record)
	}
}

func cardURLsFromRegistry(registryURL string, record func(string, error, ...zap.Field)) []string {
	if err := validateHTTPURL(registryURL); err != nil {
		record("failed to parse registry URL", err, zap.String("url", registryURL))
		return nil
	}

	resp, err := provisioningHTTPClient.Get(registryURL)
	if err != nil {
		record("failed to fetch registry", err, zap.String("url", registryURL))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		record("failed to fetch registry", fmt.Errorf("status %s", resp.Status), zap.String("url", registryURL))
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		record("failed to read registry response", err, zap.String("url", registryURL))
		return nil
	}

	cardURLs := []string{}
	for _, cardURL := range strings.Split(string(body), "\n") {
		cardURL = stripRegistryComment(cardURL)
		if cardURL != "" {
			cardURLs = append(cardURLs, cardURL)
		}
	}
	return cardURLs
}

func (m *Middleware) addKeysFromCard(keys keySpecs, cardURL string, record func(string, error, ...zap.Field)) {
	if err := validateHTTPURL(cardURL); err != nil {
		record("failed to parse signature-agent card URL", err, zap.String("url", cardURL))
		return
	}

	var card SignatureAgentCard
	if err := fetchJSON(cardURL, &card); err != nil {
		record("failed to fetch signature-agent card", err, zap.String("url", cardURL))
		return
	}

	cardKeys := card.Keys
	if card.JWKSUri != nil {
		var jwks JWKSResponse
		if err := fetchHTTPSJSON(*card.JWKSUri, &jwks); err != nil {
			record("failed to fetch jwks_uri", err, zap.String("url", *card.JWKSUri))
			return
		}
		cardKeys = jwks.Keys
	}
	keyIDs := addKeys(keys, cardKeys, cardURL, record)

	if card.IPSUri != nil && len(keyIDs) > 0 {
		m.addAllowedNets(*card.IPSUri, keyIDs, record)
	}
}

func addKeys(keys keySpecs, jwks []json.RawMessage, source string, record func(string, error, ...zap.Field)) []string {
	if len(jwks) == 0 {
		record("no keys found", nil, zap.String("url", source))
		return nil
	}
	keyIDs := []string{}
	for _, key := range jwks {
		keyID, err := keys.addJWK(key)
		if err != nil {
			record("failed to import key", err, zap.String("url", source))
			continue
		}
		keyIDs = append(keyIDs, keyID)
	}
	return keyIDs
}

func (m *Middleware) addAllowedNets(ipsURL string, keyIDs []string, record func(string, error, ...zap.Field)) {
	var ipList JAFARIPList
	if err := fetchHTTPSJSON(ipsURL, &ipList); err != nil {
		record("failed to fetch ips_uri", err, zap.String("url", ipsURL))
		return
	}

	nets := []*net.IPNet{}
	for _, prefix := range ipList.Prefixes {
		cidr := prefix.IPv4Prefix
		if cidr == "" {
			cidr = prefix.IPv6Prefix
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			record("failed to parse CIDR", err, zap.String("cidr", cidr))
			continue
		}
		nets = append(nets, ipNet)
	}
	for _, keyID := range keyIDs {
		m.keyNets[keyID] = append(m.keyNets[keyID], nets...)
	}
}

func stripRegistryComment(line string) string {
	for index := 0; index < len(line); index++ {
		if line[index] == '#' && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			return strings.TrimSpace(line[:index])
		}
	}
	return strings.TrimSpace(line)
}

func validateHTTPURL(rawURL string) error {
	u, err := parseURL(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("unsupported scheme")
	}
	return nil
}
