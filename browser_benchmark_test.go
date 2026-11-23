// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"os"
	"testing"
)

func BenchmarkOpenBrowserWithPreference(b *testing.B) {
	const authURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=00000000-0000-0000-0000-000000000000&response_type=code&redirect_uri=http%3A%2F%2Flocalhost%3A8400%2Fcallback&scope=openid+profile&state=bench-state-12345"

	ops := &browserOps{
		goos:   osLinux,
		getenv: func(string) string { return "" },
		lookPath: func(file string) (string, error) {
			if file == "microsoft-edge" {
				return "/usr/bin/microsoft-edge", nil
			}
			return "", os.ErrNotExist
		},
		stat:     func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		startCmd: func(string, ...string) error { return nil },
		runCmd:   func(context.Context, string, ...string) error { return nil },
	}
	opt := withBrowserOps(ops)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := OpenBrowserWithPreference(ctx, authURL, "msedge", opt); err != nil {
			b.Fatal(err)
		}
	}
}
