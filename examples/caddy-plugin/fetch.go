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
	"net/http"
	"net/url"
	"time"
)

var provisioningHTTPClient = &http.Client{Timeout: 10 * time.Second}

func parseURL(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("missing scheme or host")
	}
	return u, nil
}

func fetchJSON(target string, value interface{}) error {
	if err := validateHTTPURL(target); err != nil {
		return err
	}
	return fetchJSONUnchecked(target, value)
}

func fetchHTTPSJSON(target string, value interface{}) error {
	u, err := parseURL(target)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return errors.New("must use https")
	}
	return fetchJSONUnchecked(target, value)
}

func fetchJSONUnchecked(target string, value interface{}) error {
	resp, err := provisioningHTTPClient.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(value)
}
