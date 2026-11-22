// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"io"
	"net/http"
	"testing"
)

func BenchmarkDeferredCallbackRoundTrip(b *testing.B) {
	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>Benchmark Success</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>Benchmark Failure</body></html>"),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ctx, cancel := context.WithCancel(context.Background())
		cs, err := StartCallbackServer(ctx, 0, "bench-state",
			WithCallbackPages(pages),
			WithDeferredCompletion(),
		)
		if err != nil {
			b.Fatal(err)
		}
		go func() {
			<-cs.ResultChan()
			cs.Complete(true)
		}()
		resp, err := http.Get(cs.RedirectURI + "/?code=bench&state=bench-state") //nolint:noctx // benchmark
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		_ = cs.Close()
		cancel()
	}
}
