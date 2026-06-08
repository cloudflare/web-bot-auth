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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestServeHTTPWithoutValidatorReturnsUnavailable(t *testing.T) {
	middleware := Middleware{}
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/data", nil)

	err := middleware.ServeHTTP(recorder, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler should not run")
		return nil
	}))
	if err != nil {
		t.Fatalf("serve http: %v", err)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

func TestUnmarshalCaddyfileSupportsDirectoryAndRegistry(t *testing.T) {
	dispenser := caddyfile.NewTestDispenser(`httpsig {
		directory_base example.com
		registry https://example.com/registry.txt
		fail_on_load_error true
	}`)
	middleware := Middleware{}

	if err := middleware.UnmarshalCaddyfile(dispenser); err != nil {
		t.Fatalf("unmarshal caddyfile: %v", err)
	}
	if middleware.DirectoryBase != "example.com" {
		t.Fatalf("directory_base = %q", middleware.DirectoryBase)
	}
	if len(middleware.RegistryURLs) != 1 || middleware.RegistryURLs[0] != "https://example.com/registry.txt" {
		t.Fatalf("registry URLs = %v", middleware.RegistryURLs)
	}
	if !middleware.FailOnLoadError {
		t.Fatal("fail_on_load_error was not parsed")
	}
}

func TestDirectoryURL(t *testing.T) {
	url, err := buildDirectoryURL("example.com")
	if err != nil {
		t.Fatalf("directory URL: %v", err)
	}
	if url != "https://example.com/.well-known/http-message-signatures-directory" {
		t.Fatalf("url = %q", url)
	}

	url, err = buildDirectoryURL("http://localhost:8787/base/")
	if err != nil {
		t.Fatalf("directory URL with scheme: %v", err)
	}
	if !strings.HasPrefix(url, "http://localhost:8787/base/.well-known/") {
		t.Fatalf("url = %q", url)
	}
}

func TestStripRegistryComment(t *testing.T) {
	line := stripRegistryComment("https://example.com/card # comment")
	if line != "https://example.com/card" {
		t.Fatalf("line = %q", line)
	}
}
