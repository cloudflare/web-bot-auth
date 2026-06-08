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
	"net/url"
	"strings"

	"go.uber.org/zap"
)

const directoryPath = "/.well-known/http-message-signatures-directory"

type Directory struct {
	Keys []json.RawMessage `json:"keys"`
}

func (m *Middleware) addKeysFromDirectory(keys keySpecs, directoryBase string, record func(string, error, ...zap.Field)) {
	directoryURL, err := buildDirectoryURL(directoryBase)
	if err != nil {
		record("failed to parse directory_base", err, zap.String("directory_base", directoryBase))
		return
	}

	var directory Directory
	if err := fetchJSON(directoryURL, &directory); err != nil {
		record("failed to fetch directory", err, zap.String("url", directoryURL))
		return
	}
	addKeys(keys, directory.Keys, directoryURL, record)
}

func buildDirectoryURL(directoryBase string) (string, error) {
	base := directoryBase
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("missing scheme or host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("unsupported scheme")
	}
	u.Path = strings.TrimRight(u.Path, "/") + directoryPath
	return u.String(), nil
}
