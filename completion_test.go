// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeferredCompletion_HoldsResponseUntilCompleteTrue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>CUSTOM SUCCESS</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>CUSTOM FAILURE</body></html>"),
	}
	cs, err := StartCallbackServer(ctx, 0, "state-123",
		WithCallbackPages(pages),
		WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	type httpOutcome struct {
		resp *http.Response
		body []byte
		err  error
	}
	respCh := make(chan httpOutcome, 1)
	go func() {
		resp, getErr := http.Get(cs.RedirectURI + "/?code=auth-code-xyz&state=state-123") //nolint:noctx // test code
		if getErr != nil {
			respCh <- httpOutcome{err: getErr}
			return
		}
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			respCh <- httpOutcome{err: readErr}
			return
		}
		respCh <- httpOutcome{resp: resp, body: b}
	}()

	// ResultChan must deliver immediately while the HTTP response stays pending.
	select {
	case res := <-cs.ResultChan():
		require.NoError(t, res.Err)
		assert.Equal(t, "auth-code-xyz", res.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("ResultChan blocked waiting for Complete")
	}

	// Browser response must still be withheld before Complete is called.
	select {
	case out := <-respCh:
		t.Fatalf("HTTP response completed prematurely before Complete(): %+v", out)
	case <-time.After(80 * time.Millisecond):
	}

	// Duplicate Complete calls: first wins, subsequent calls are safe no-ops.
	cs.Complete(true)
	cs.Complete(false)

	var out httpOutcome
	select {
	case out = <-respCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deferred HTTP response")
	}
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusOK, out.resp.StatusCode)
	assert.Equal(t, string(pages.SuccessHTML), string(out.body))
	assert.Equal(t, "nosniff", out.resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", out.resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", out.resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, finalPageCSP, out.resp.Header.Get("Content-Security-Policy"))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, cs.Shutdown(shutdownCtx))
}

func TestDeferredCompletion_CompleteFalseServesCustomFailureAndNon2xx(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>CUSTOM SUCCESS</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>CUSTOM FAILURE</body></html>"),
	}
	cs, err := StartCallbackServer(ctx, 0, "st",
		WithCallbackPages(pages),
		WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	done := make(chan struct{})
	var status int
	var body string
	go func() {
		defer close(done)
		resp, getErr := http.Get(cs.RedirectURI + "/?code=bad-exchange-code&state=st") //nolint:noctx // test code
		if !assert.NoError(t, getErr) {
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		status = resp.StatusCode
		body = string(b)
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "bad-exchange-code", res.Code)

	cs.Complete(false)
	cs.Complete(true) // late call ignored

	<-done
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, string(pages.FailureHTML), body)
}

func TestDeferredCompletion_ContextCancelSettlesAsSafeFailure(t *testing.T) {
	flowCtx, cancelFlow := context.WithCancel(context.Background())
	cs, err := StartCallbackServer(flowCtx, 0, "st", WithDeferredCompletion())
	require.NoError(t, err)
	defer cs.Close()

	done := make(chan struct{})
	var status int
	var body string
	go func() {
		defer close(done)
		resp, getErr := http.Get(cs.RedirectURI + "/?code=abc&state=st") //nolint:noctx // test code
		if !assert.NoError(t, getErr) {
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		status = resp.StatusCode
		body = string(b)
	}()

	<-cs.ResultChan()
	cancelFlow()

	// Graceful shutdown with a separate cleanup context drains the failure page.
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCleanup()
	require.NoError(t, cs.Shutdown(cleanupCtx))

	<-done
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, defaultFailureHTML, body)
	assert.Contains(t, body, "color-scheme: dark")
	assert.Contains(t, body, "<style>")
}

func TestDeferredCompletion_DefaultSuccessFallbackCard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := StartCallbackServer(ctx, 0, "st-def", WithDeferredCompletion())
	require.NoError(t, err)
	defer cs.Close()

	done := make(chan struct{})
	var status int
	var body string
	var csp string
	go func() {
		defer close(done)
		resp, getErr := http.Get(cs.RedirectURI + "/?code=ok-code&state=st-def") //nolint:noctx // test code
		if !assert.NoError(t, getErr) {
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		status = resp.StatusCode
		body = string(b)
		csp = resp.Header.Get("Content-Security-Policy")
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "ok-code", res.Code)

	cs.Complete(true)
	<-done

	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, finalPageCSP, csp)
	assert.Equal(t, defaultSuccessHTML, body)
}

func TestBuiltInFallbackPages_StyledDarkCardsAndOfflineSafe(t *testing.T) {
	tests := []struct {
		name        string
		html        string
		wantHeading string
		wantAccent  string
		wantText    []string
	}{
		{
			name:        "defaultSuccessHTML",
			html:        defaultSuccessHTML,
			wantHeading: "<h1>Authentication Successful</h1>",
			wantAccent:  "#a4f6c5",
			wantText: []string{
				"You can close this window and return to the terminal.",
			},
		},
		{
			name:        "defaultFailureHTML",
			html:        defaultFailureHTML,
			wantHeading: "<h1>Authentication Failed</h1>",
			wantAccent:  "#ffc28e",
			wantText: []string{
				"We couldn't finish connecting you. Check the terminal for details and run the login command again.",
				"You can close this window.",
			},
		},
		{
			name:        "authErrorHTML",
			html:        authErrorHTML("access_denied: consent required"),
			wantHeading: "<h1>Authentication Failed</h1>",
			wantAccent:  "#ffc28e",
			wantText: []string{
				"access_denied: consent required",
				"<h2>Troubleshooting</h2>",
				"Troubleshooting",
				"log in to your identity provider",
				"You can close this window.",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lower := strings.ToLower(tt.html)
			assert.Contains(t, tt.html, "<!DOCTYPE html>")
			assert.Contains(t, tt.html, "color-scheme: dark")
			assert.Contains(t, tt.html, "<style>")
			assert.Contains(t, tt.html, "#05152a")
			assert.Contains(t, tt.html, "#071e3d")
			assert.Contains(t, tt.html, "system-ui")
			assert.Contains(t, tt.html, tt.wantAccent)
			assert.Contains(t, tt.html, tt.wantHeading)
			for _, sub := range tt.wantText {
				assert.Contains(t, tt.html, sub)
			}
			assert.Equal(t, 1, strings.Count(lower, "<h1"), "page must contain exactly one h1")
			assert.NotContains(t, lower, "<script", "final page must contain zero scripts")
			assert.NotContains(t, lower, "http://", "final page must contain zero external http URLs")
			assert.NotContains(t, lower, "https://", "final page must contain zero external https URLs")
			assert.NotContains(t, lower, "<link", "final page must not reference external stylesheets")
			assert.NotContains(t, lower, "url(", "final page must not reference external CSS URLs")
		})
	}
}

func TestDeferredCompletion_PasteBackShutdownWithoutBrowserCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cs, err := StartCallbackServer(ctx, 0, "st", WithDeferredCompletion())
	require.NoError(t, err)

	// Simulate paste-back winning: no HTTP request ever hit cs.RedirectURI.
	start := time.Now()
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCleanup()
	require.NoError(t, cs.Shutdown(cleanupCtx))
	assert.Less(t, time.Since(start), 500*time.Millisecond, "idle server shutdown must not wait on a browser")
}

func TestDeferredCompletion_InvalidCallbacksNeverShowSuccessOrProviderError(t *testing.T) {
	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>SECRET SUCCESS MARKER</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>SAFE CUSTOM FAILURE</body></html>"),
	}

	tests := []struct {
		name       string
		query      string
		wantStatus int
		wantErrSub string
	}{
		{
			name:       "provider denial hides error_description in HTML",
			query:      "/?error=access_denied&error_description=AADSTS65001+secret+detail",
			wantStatus: http.StatusBadRequest,
			wantErrSub: "AADSTS65001 secret detail",
		},
		{
			name:       "missing code",
			query:      "/",
			wantStatus: http.StatusBadRequest,
			wantErrSub: "no authorization code received",
		},
		{
			name:       "state mismatch",
			query:      "/?code=abc&state=wrong",
			wantStatus: http.StatusForbidden,
			wantErrSub: "state parameter mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cs, err := StartCallbackServer(ctx, 0, "expected",
				WithCallbackPages(pages),
				WithDeferredCompletion(),
			)
			require.NoError(t, err)
			defer cs.Close()

			resp, err := http.Get(cs.RedirectURI + tt.query) //nolint:noctx // test code
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			assert.Equal(t, string(pages.FailureHTML), string(body))
			assert.NotContains(t, string(body), "SECRET SUCCESS MARKER")
			assert.NotContains(t, string(body), "AADSTS65001")
			assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))

			res := <-cs.ResultChan()
			require.Error(t, res.Err)
			assert.Contains(t, res.Err.Error(), tt.wantErrSub)
		})
	}
}

func TestWithCallbackPages_WithoutDeferredServesImmediately(t *testing.T) {
	ctx := context.Background()
	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>IMMEDIATE CUSTOM SUCCESS</body></html>"),
	}
	cs, err := StartCallbackServer(ctx, 0, "st", WithCallbackPages(pages))
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?code=ok&state=st") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, string(pages.SuccessHTML), string(body))
	assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
}

func TestImplicitDeferredCompletion_BridgeCSPAndFinalDocument(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>IMPLICIT BLUEPRINT SUCCESS</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>IMPLICIT BLUEPRINT FAILURE</body></html>"),
	}
	cs, err := StartImplicitCallbackServer(ctx, 0, "imp-state",
		WithCallbackPages(pages),
		WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	// 1. Bridge GET serves script-hash CSP + iframe srcdoc renderer.
	bridgeResp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	require.NoError(t, err)
	defer bridgeResp.Body.Close()
	bridgeBody, err := io.ReadAll(bridgeResp.Body)
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(implicitBridgeScript))
	wantHash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	assert.Contains(t, bridgeResp.Header.Get("Content-Security-Policy"), wantHash)
	assert.Contains(t, string(bridgeBody), "frame.srcdoc = xhr.responseText")
	assert.Contains(t, string(bridgeBody), `frame.setAttribute("sandbox", "")`)

	// 2. Token POST delivers result immediately and waits for Complete before replying.
	done := make(chan struct{})
	var postStatus int
	var postBody string
	var postCSP string
	go func() {
		defer close(done)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, cs.origin+"/token",
			strings.NewReader("access_token=imp-tok&token_type=Bearer&state=imp-state"))
		if !assert.NoError(t, reqErr) {
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", cs.origin)
		resp, doErr := http.DefaultClient.Do(req)
		if !assert.NoError(t, doErr) {
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		postStatus = resp.StatusCode
		postBody = string(b)
		postCSP = resp.Header.Get("Content-Security-Policy")
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "imp-tok", res.AccessToken)

	cs.Complete(true)
	<-done
	assert.Equal(t, http.StatusOK, postStatus)
	assert.Equal(t, string(pages.SuccessHTML), postBody)
	assert.Equal(t, finalPageCSP, postCSP)
	assert.NotContains(t, postBody, "imp-tok")
}

func TestDeferredCompletion_ContextTimeoutFlushes503FailurePage(t *testing.T) {
	flowCtx, flowCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer flowCancel()

	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>NEVER-SUCCESS</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>TIMEOUT-SAFE-FAILURE</body></html>"),
	}

	cs, err := StartCallbackServer(flowCtx, 0, "st-timeout",
		WithCallbackPages(pages),
		WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	type browserOutcome struct {
		status int
		body   string
		err    error
	}
	outCh := make(chan browserOutcome, 1)
	go func() {
		resp, getErr := http.Get(cs.RedirectURI + "/?code=c-timeout&state=st-timeout") //nolint:noctx
		if getErr != nil {
			outCh <- browserOutcome{err: getErr}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, readErr := io.ReadAll(resp.Body)
		outCh <- browserOutcome{status: resp.StatusCode, body: string(b), err: readErr}
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "c-timeout", res.Code)

	// Wait for flowCtx deadline to expire without calling Complete; the fresh
	// post-wait socket write deadline must still flush 503 + FailureHTML cleanly.
	out := <-outCh
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusServiceUnavailable, out.status)
	assert.Equal(t, string(pages.FailureHTML), out.body)

	require.NoError(t, cs.Shutdown(context.Background()))
}

func TestComplete_ConcurrentRaceSafety(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := StartCallbackServer(ctx, 0, "st", WithDeferredCompletion())
	require.NoError(t, err)
	defer cs.Close()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(v bool) {
			defer wg.Done()
			cs.Complete(v)
		}(i%2 == 0)
	}
	wg.Wait()
}

func TestWithCallbackPages_ClonesCallerSlices(t *testing.T) {
	ctx := context.Background()
	rawSuccess := []byte("<!doctype html><html><body>ORIGINAL SUCCESS</body></html>")
	rawFailure := []byte("<!doctype html><html><body>ORIGINAL FAILURE</body></html>")

	cs, err := StartCallbackServer(ctx, 0, "st", WithCallbackPages(CallbackPages{
		SuccessHTML: rawSuccess,
		FailureHTML: rawFailure,
	}))
	require.NoError(t, err)
	defer cs.Close()

	// Mutate caller-owned slices after passing them into WithCallbackPages.
	copy(rawSuccess, "MUTATED!")
	copy(rawFailure, "MUTATED!")

	resp, err := http.Get(cs.RedirectURI + "/?code=ok&state=st") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "<!doctype html><html><body>ORIGINAL SUCCESS</body></html>", string(body))
}

func TestDeferredCompletion_ClientDisconnectUnblocksHandler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := StartCallbackServer(ctx, 0, "st-disc", WithDeferredCompletion())
	require.NoError(t, err)
	defer cs.Close()

	reqCtx, cancelReq := context.WithCancel(context.Background())
	reqDone := make(chan error, 1)
	go func() {
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, cs.RedirectURI+"/?code=disc-code&state=st-disc", nil)
		if reqErr != nil {
			reqDone <- reqErr
			return
		}
		resp, doErr := http.DefaultClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		reqDone <- doErr
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "disc-code", res.Code)

	// Simulate user closing the browser tab before Complete is called.
	cancelReq()
	<-reqDone

	// Server Shutdown with nil context must still complete promptly without hanging.
	start := time.Now()
	require.NoError(t, cs.Shutdown(nil)) //nolint:staticcheck // testing nil context guard
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestDeferredCompletion_DefaultFailureOnInvalidCallbacksAndImplicitMissingToken(t *testing.T) {
	t.Run("auth code error without custom pages serves defaultFailureHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartCallbackServer(ctx, 0, "st", WithDeferredCompletion())
		require.NoError(t, err)
		defer cs.Close()

		resp, err := http.Get(cs.RedirectURI + "/?error=access_denied&error_description=secret") //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, defaultFailureHTML, string(body))
		assert.NotContains(t, string(body), "secret")
		assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
	})

	t.Run("implicit missing access_token in enhanced mode serves defaultFailureHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartImplicitCallbackServer(ctx, 0, "st", WithDeferredCompletion())
		require.NoError(t, err)
		defer cs.Close()

		resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("token_type=Bearer")) //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, defaultFailureHTML, string(body))
		assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
	})

	t.Run("zero-value CallbackServer Complete, Close, and Shutdown are safe no-ops", func(t *testing.T) {
		var zero CallbackServer
		assert.NotPanics(t, func() {
			zero.Complete(true)
		})
		assert.NoError(t, zero.Close())
		assert.NoError(t, zero.Shutdown(context.Background()))
	})

	t.Run("implicit malformed form POST in enhanced mode serves defaultFailureHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartImplicitCallbackServer(ctx, 0, "st", WithDeferredCompletion())
		require.NoError(t, err)
		defer cs.Close()

		resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("access_token=%ZZ")) //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, defaultFailureHTML, string(body))
		assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
	})
}

func TestDeferredCompletion_OutlivesServerReadWriteTimeouts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>NEVER-200</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>HELD-PAST-READ-TIMEOUT</body></html>"),
	}
	cs, err := StartCallbackServer(ctx, 0, "st-rw",
		withServerIOTimeout(50*time.Millisecond),
		WithCallbackPages(pages),
		WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	type outcome struct {
		status int
		body   string
		err    error
	}
	outCh := make(chan outcome, 1)
	go func() {
		resp, getErr := http.Get(cs.RedirectURI + "/?code=slow-mfa&state=st-rw") //nolint:noctx // test code
		if getErr != nil {
			outCh <- outcome{err: getErr}
			return
		}
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		outCh <- outcome{status: resp.StatusCode, body: string(b), err: readErr}
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "slow-mfa", res.Code)

	// Hold past 3x the 50ms ReadTimeout/WriteTimeout before settling failure.
	time.Sleep(160 * time.Millisecond)
	cs.Complete(false)

	out := <-outCh
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusServiceUnavailable, out.status)
	assert.Equal(t, string(pages.FailureHTML), out.body)
}

func TestDeferredCompletion_ShutdownSettlesUnsettledCallbackImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := StartCallbackServer(ctx, 0, "st-unsettled", WithDeferredCompletion())
	require.NoError(t, err)
	defer cs.Close()

	type outcome struct {
		status int
		body   string
		err    error
	}
	outCh := make(chan outcome, 1)
	go func() {
		resp, getErr := http.Get(cs.RedirectURI + "/?code=early-abort&state=st-unsettled") //nolint:noctx // test code
		if getErr != nil {
			outCh <- outcome{err: getErr}
			return
		}
		defer resp.Body.Close()
		b, readErr := io.ReadAll(resp.Body)
		outCh <- outcome{status: resp.StatusCode, body: string(b), err: readErr}
	}()

	res := <-cs.ResultChan()
	require.NoError(t, res.Err)
	assert.Equal(t, "early-abort", res.Code)

	// Caller aborts and calls Shutdown without calling Complete; Shutdown must
	// settle as 503 failure immediately rather than waiting 10s.
	start := time.Now()
	require.NoError(t, cs.Shutdown(context.Background()))
	assert.Less(t, time.Since(start), 500*time.Millisecond)

	out := <-outCh
	require.NoError(t, out.err)
	assert.Equal(t, http.StatusServiceUnavailable, out.status)
	assert.Equal(t, defaultFailureHTML, out.body)
}

func TestWithCallbackPages_AsymmetricFallback(t *testing.T) {
	t.Run("custom SuccessHTML with empty FailureHTML falls back to defaultFailureHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartCallbackServer(ctx, 0, "st",
			WithCallbackPages(CallbackPages{
				SuccessHTML: []byte("<!doctype html><html><body>CUSTOM SUCCESS</body></html>"),
			}),
			WithDeferredCompletion(),
		)
		require.NoError(t, err)
		defer cs.Close()

		done := make(chan struct{})
		var status int
		var body string
		go func() {
			defer close(done)
			resp, getErr := http.Get(cs.RedirectURI + "/?code=c&state=st") //nolint:noctx // test code
			if !assert.NoError(t, getErr) {
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			status = resp.StatusCode
			body = string(b)
		}()

		<-cs.ResultChan()
		cs.Complete(false)
		<-done

		assert.Equal(t, http.StatusServiceUnavailable, status)
		assert.Equal(t, defaultFailureHTML, body)
	})

	t.Run("empty SuccessHTML with custom FailureHTML falls back to defaultSuccessHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartCallbackServer(ctx, 0, "st",
			WithCallbackPages(CallbackPages{
				FailureHTML: []byte("<!doctype html><html><body>CUSTOM FAILURE</body></html>"),
			}),
			WithDeferredCompletion(),
		)
		require.NoError(t, err)
		defer cs.Close()

		done := make(chan struct{})
		var status int
		var body string
		go func() {
			defer close(done)
			resp, getErr := http.Get(cs.RedirectURI + "/?code=c&state=st") //nolint:noctx // test code
			if !assert.NoError(t, getErr) {
				return
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			status = resp.StatusCode
			body = string(b)
		}()

		<-cs.ResultChan()
		cs.Complete(true)
		<-done

		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, defaultSuccessHTML, body)
	})
}

func TestWithCallbackPages_EmptyStructUsesEnhancedSafeFallbacks(t *testing.T) {
	t.Run("success serves defaultSuccessHTML", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartCallbackServer(ctx, 0, "st", WithCallbackPages(CallbackPages{}))
		require.NoError(t, err)
		defer cs.Close()

		resp, err := http.Get(cs.RedirectURI + "/?code=ok&state=st") //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, defaultSuccessHTML, string(body))
		assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
	})

	t.Run("OAuth error serves defaultFailureHTML without exposing provider details", func(t *testing.T) {
		ctx := context.Background()
		cs, err := StartCallbackServer(ctx, 0, "st", WithCallbackPages(CallbackPages{}))
		require.NoError(t, err)
		defer cs.Close()

		resp, err := http.Get(cs.RedirectURI + "/?error=access_denied&error_description=AADSTS99999+sensitive") //nolint:noctx // test code
		require.NoError(t, err)
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, defaultFailureHTML, string(body))
		assert.NotContains(t, string(body), "AADSTS99999")
		assert.NotContains(t, string(body), "Troubleshooting", "empty WithCallbackPages must opt into enhanced safe failure page")
		assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assert.Contains(t, res.Err.Error(), "AADSTS99999 sensitive")
	})
}

func TestDeferredCompletion_PostCancellationCompleteTrueNeverServes200(t *testing.T) {
	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>UNEXPECTED-200</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>CANCELLED-503</body></html>"),
	}

	t.Run("cancel while handler parked before Complete(true)", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			flowCtx, cancelFlow := context.WithCancel(context.Background())
			cs, err := StartCallbackServer(flowCtx, 0, "st-race",
				WithCallbackPages(pages),
				WithDeferredCompletion(),
			)
			require.NoError(t, err)

			type outcome struct {
				status int
				body   string
				err    error
			}
			outCh := make(chan outcome, 1)
			go func() {
				resp, getErr := http.Get(cs.RedirectURI + "/?code=c&state=st-race") //nolint:noctx // test code
				if getErr != nil {
					outCh <- outcome{err: getErr}
					return
				}
				defer resp.Body.Close()
				b, readErr := io.ReadAll(resp.Body)
				outCh <- outcome{status: resp.StatusCode, body: string(b), err: readErr}
			}()

			<-cs.ResultChan()
			cancelFlow()
			cs.Complete(true)

			out := <-outCh
			require.NoError(t, out.err)
			require.Equal(t, http.StatusServiceUnavailable, out.status, "iteration %d", i)
			require.Equal(t, string(pages.FailureHTML), out.body, "iteration %d", i)
			_ = cs.Close()
		}
	})

	t.Run("callback arrives after cancel and Complete(true)", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			flowCtx, cancelFlow := context.WithCancel(context.Background())
			cs, err := StartCallbackServer(flowCtx, 0, "st-late",
				WithCallbackPages(pages),
				WithDeferredCompletion(),
			)
			require.NoError(t, err)

			cancelFlow()
			cs.Complete(true)

			resp, err := http.Get(cs.RedirectURI + "/?code=c&state=st-late") //nolint:noctx // test code
			require.NoError(t, err)
			b, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, readErr)
			require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "iteration %d", i)
			require.Equal(t, string(pages.FailureHTML), string(b), "iteration %d", i)
			_ = cs.Close()
		}
	})
}

func TestDeferredCompletion_CompleteTrueImmediatelyBeforeCancelAlwaysServes200(t *testing.T) {
	pages := CallbackPages{
		SuccessHTML: []byte("<!doctype html><html><body>SETTLED-200</body></html>"),
		FailureHTML: []byte("<!doctype html><html><body>UNEXPECTED-503</body></html>"),
	}

	for i := 0; i < 100; i++ {
		flowCtx, cancelFlow := context.WithCancel(context.Background())
		cs, err := StartCallbackServer(flowCtx, 0, "st-ok",
			WithCallbackPages(pages),
			WithDeferredCompletion(),
		)
		require.NoError(t, err)

		type outcome struct {
			status int
			body   string
			err    error
		}
		outCh := make(chan outcome, 1)
		go func() {
			resp, getErr := http.Get(cs.RedirectURI + "/?code=c&state=st-ok") //nolint:noctx // test code
			if getErr != nil {
				outCh <- outcome{err: getErr}
				return
			}
			defer resp.Body.Close()
			b, readErr := io.ReadAll(resp.Body)
			outCh <- outcome{status: resp.StatusCode, body: string(b), err: readErr}
		}()

		<-cs.ResultChan()
		cs.Complete(true)
		cancelFlow()

		out := <-outCh
		require.NoError(t, out.err)
		require.Equal(t, http.StatusOK, out.status, "iteration %d", i)
		require.Equal(t, string(pages.SuccessHTML), out.body, "iteration %d", i)
		_ = cs.Close()
	}
}

func TestCallbackServer_ResponsesCarryFixedContentLengthAndSurviveImmediateClose(t *testing.T) {
	assertFixedLength := func(t *testing.T, resp *http.Response, body []byte) {
		t.Helper()
		assert.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"))
		assert.NotContains(t, resp.TransferEncoding, "chunked")
	}

	t.Run("legacy success with immediate Close on ResultChan", func(t *testing.T) {
		for i := 0; i < 25; i++ {
			cs, err := StartCallbackServer(context.Background(), 0, "st")
			require.NoError(t, err)

			go func() {
				<-cs.ResultChan()
				_ = cs.Close()
			}()

			resp, err := http.Get(cs.RedirectURI + "/?code=ok&state=st") //nolint:noctx // test code
			require.NoError(t, err)
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, readErr)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, defaultSuccessHTML, string(body))
			assertFixedLength(t, resp, body)
		}
	})

	t.Run("legacy error and 405 plain error with immediate Close on ResultChan", func(t *testing.T) {
		csErr, err := StartCallbackServer(context.Background(), 0, "st")
		require.NoError(t, err)
		go func() {
			<-csErr.ResultChan()
			_ = csErr.Close()
		}()
		respErr, err := http.Get(csErr.RedirectURI + "/?error=access_denied") //nolint:noctx // test code
		require.NoError(t, err)
		errBody, readErr := io.ReadAll(respErr.Body)
		_ = respErr.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, http.StatusBadRequest, respErr.StatusCode)
		assertFixedLength(t, respErr, errBody)

		cs405, err := StartCallbackServer(context.Background(), 0, "st")
		require.NoError(t, err)
		go func() {
			<-cs405.ResultChan()
			_ = cs405.Close()
		}()
		resp405, err := http.Post(cs405.RedirectURI+"/", "text/plain", strings.NewReader("")) //nolint:noctx // test code
		require.NoError(t, err)
		body405, readErr := io.ReadAll(resp405.Body)
		_ = resp405.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, http.StatusMethodNotAllowed, resp405.StatusCode)
		assertFixedLength(t, resp405, body405)
	})

	t.Run("implicit bridge GET and token POST carry fixed Content-Length", func(t *testing.T) {
		cs, err := StartImplicitCallbackServer(context.Background(), 0, "st")
		require.NoError(t, err)

		bridgeResp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
		require.NoError(t, err)
		bridgeBody, readErr := io.ReadAll(bridgeResp.Body)
		_ = bridgeResp.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, implicitCallbackHTML, string(bridgeBody))
		assertFixedLength(t, bridgeResp, bridgeBody)

		go func() {
			<-cs.ResultChan()
			_ = cs.Close()
		}()
		postResp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("access_token=tok&state=st")) //nolint:noctx // test code
		require.NoError(t, err)
		postBody, readErr := io.ReadAll(postResp.Body)
		_ = postResp.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, http.StatusOK, postResp.StatusCode)
		assert.Equal(t, defaultSuccessHTML, string(postBody))
		assertFixedLength(t, postResp, postBody)
	})
}
