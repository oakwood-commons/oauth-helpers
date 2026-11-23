// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	oauth "github.com/oakwood-commons/oauth-helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_PKCE_FullFlow tests PKCE verifier generation and challenge
// derivation as an end-to-end pair.
func TestIntegration_PKCE_FullFlow(t *testing.T) {
	verifier, err := oauth.GenerateCodeVerifier()
	require.NoError(t, err)
	assert.Len(t, verifier, 43)

	challenge := oauth.GenerateCodeChallenge(verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge, "challenge must differ from verifier")

	// Same verifier always produces the same challenge
	challenge2 := oauth.GenerateCodeChallenge(verifier)
	assert.Equal(t, challenge, challenge2)
}

// TestIntegration_AuthCodeFlow_Success simulates a complete authorization code
// callback flow: start server, receive code, and verify result.
func TestIntegration_AuthCodeFlow_Success(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	state := "integration-test-state-abc123"
	cs, err := oauth.StartCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer cs.Close()

	// Simulate the identity provider redirecting with code and state
	callbackURL := fmt.Sprintf("%s/?code=integration-auth-code&state=%s", cs.RedirectURI, state)
	resp, err := http.Get(callbackURL) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "Authentication Successful")

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "integration-auth-code", result.Code)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_AuthCodeFlow_CSRFRejection verifies that missing or
// mismatched state parameters on both error and code callbacks return 403
// without terminating the wait for the legitimate redirect.
func TestIntegration_AuthCodeFlow_CSRFRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "legitimate-state")
	require.NoError(t, err)
	defer cs.Close()

	// Forged error and code callbacks with missing or wrong state must return 403
	// without poisoning ResultChan.
	for _, forgedPath := range []string{
		"/?error=access_denied",
		"/?error=access_denied&state=attacker-state",
		"/?code=stolen-code",
		"/?code=stolen-code&state=attacker-state",
	} {
		resp, getErr := http.Get(cs.RedirectURI + forgedPath) //nolint:noctx // test code
		require.NoError(t, getErr)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("forged callback must not terminate wait, got: %+v", result)
	default:
	}

	// Real redirect with matching state succeeds.
	resp, err := http.Get(cs.RedirectURI + "/?code=legitimate-code&state=legitimate-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "legitimate-code", result.Code)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_AuthCodeFlow_OAuthError simulates the identity provider
// returning an error with matching state (e.g., user denied consent).
func TestIntegration_AuthCodeFlow_OAuthError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "err-state-123")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?error=consent_required&error_description=User+denied+access&state=err-state-123") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "consent_required")
		assert.Contains(t, result.Err.Error(), "User denied access")
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_AuthCodeFlow_MethodNotAllowed verifies that non-GET requests
// to the callback endpoint return 405 without poisoning ResultChan.
func TestIntegration_AuthCodeFlow_MethodNotAllowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "method-state")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Post(cs.RedirectURI+"/?code=test&state=method-state", "text/plain", nil) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("POST must not poison ResultChan, got: %+v", result)
	default:
	}

	validResp, err := http.Get(cs.RedirectURI + "/?code=ok&state=method-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "ok", result.Code)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_ImplicitFlow_Success simulates a complete implicit grant
// callback flow: start server, POST token fragment data, and verify result.
func TestIntegration_ImplicitFlow_Success(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	state := "implicit-state-xyz789"
	cs, err := oauth.StartImplicitCallbackServer(ctx, 0, state)
	require.NoError(t, err)
	defer cs.Close()

	// Step 1: Verify the landing page serves JavaScript that extracts the fragment
	resp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	assert.Contains(t, string(body), "window.location.hash")

	// Step 2: Simulate the JavaScript POSTing the parsed fragment
	tokenData := fmt.Sprintf("access_token=implicit-token-123&token_type=Bearer&expires_in=7200&state=%s", state)
	resp, err = http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "implicit-token-123", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)
		assert.Equal(t, "7200", result.ExpiresIn)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_ImplicitFlow_CSRFRejection verifies that the implicit flow
// rejects missing or mismatched state parameters with 403 without poisoning
// ResultChan.
func TestIntegration_ImplicitFlow_CSRFRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartImplicitCallbackServer(ctx, 0, "expected-implicit-state")
	require.NoError(t, err)
	defer cs.Close()

	for _, forgedBody := range []string{
		"access_token=tok&token_type=Bearer",
		"access_token=tok&token_type=Bearer&state=wrong-state",
		"error=access_denied&error_description=spoofed",
		"error=access_denied&error_description=spoofed&state=wrong-state",
	} {
		resp, postErr := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(forgedBody)) //nolint:noctx // test code
		require.NoError(t, postErr)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("forged implicit POST must not poison ResultChan, got: %+v", result)
	default:
	}

	validResp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("access_token=valid-tok&token_type=Bearer&state=expected-implicit-state")) //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "valid-tok", result.AccessToken)
	case <-ctx.Done():
		t.Fatal("timed out waiting for valid implicit callback result")
	}
}

// TestIntegration_CallbackServer_CustomHostPath tests that callback servers
// can be configured with custom host and path options.
func TestIntegration_CallbackServer_CustomHostPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "",
		oauth.WithCallbackHost("127.0.0.1"),
		oauth.WithCallbackPath("/auth/callback"),
	)
	require.NoError(t, err)
	defer cs.Close()

	assert.Contains(t, cs.RedirectURI, "http://127.0.0.1:")
	assert.Contains(t, cs.RedirectURI, "/auth/callback")

	resp, err := http.Get(cs.RedirectURI + "?code=custom-path-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "custom-path-code", result.Code)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_CallbackServer_DisallowedHost verifies that non-loopback
// hosts are rejected at construction time.
func TestIntegration_CallbackServer_DisallowedHost(t *testing.T) {
	ctx := context.Background()

	_, err := oauth.StartCallbackServer(ctx, 0, "",
		oauth.WithCallbackHost("0.0.0.0"),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

// TestIntegration_OpenBrowser_SchemeValidation verifies that OpenBrowser
// rejects non-HTTP schemes.
func TestIntegration_OpenBrowser_SchemeValidation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"file scheme rejected", "file:///etc/passwd", true},
		{"javascript scheme rejected", "javascript:alert(1)", true},
		{"ftp scheme rejected", "ftp://example.com", true},
		{"empty string rejected", "", true},
		// Note: we don't test valid http/https URLs here because they would
		// actually open a browser window in the test environment.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := oauth.OpenBrowser(ctx, tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "non-HTTP scheme")
			}
		})
	}
}

// TestIntegration_OpenBrowserWithPreference_Validation verifies URL hardening
// (empty host, whitespace, ASCII control characters) and pre-canceled context
// handling without opening a real browser.
func TestIntegration_OpenBrowserWithPreference_Validation(t *testing.T) {
	ctx := context.Background()

	invalidURLs := []struct {
		name        string
		rawURL      string
		errContains string
	}{
		{"empty host rejected", "https:///callback", "empty host"},
		{"whitespace rejected", "https://example.com/auth?a=1 b=2", "control characters or whitespace"},
		{"newline rejected", "https://example.com/auth\n", "control characters or whitespace"},
		{"DEL rejected", "https://example.com/auth\x7f", "control characters or whitespace"},
	}

	for _, tt := range invalidURLs {
		t.Run(tt.name, func(t *testing.T) {
			var warned bool
			err := oauth.OpenBrowserWithPreference(
				ctx,
				tt.rawURL,
				"msedge",
				oauth.WithWarningHandler(func(string) { warned = true }),
			)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.False(t, warned, "URL validation failure must fail up front without warning/fallback")
		})
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	err := oauth.OpenBrowserWithPreference(canceledCtx, "HTTPS://example.com/authorize?a=1&b=2", "msedge")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestIntegration_ValidateCallbackHostPath tests the config-time validation
// function for host and path combinations.
func TestIntegration_ValidateCallbackHostPath(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		path    string
		wantErr bool
	}{
		{"defaults valid", "", "", false},
		{"localhost valid", "localhost", "/", false},
		{"127.0.0.1 valid", "127.0.0.1", "/callback", false},
		{"IPv6 loopback valid", "::1", "/auth", false},
		{"external host rejected", "example.com", "/", true},
		{"0.0.0.0 rejected", "0.0.0.0", "/", true},
		{"path traversal rejected", "localhost", "/../etc/passwd", true},
		{"query in path rejected", "localhost", "/callback?foo=bar", true},
		{"reserved token path rejected", "localhost", "/token", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := oauth.ValidateCallbackHostPath(tt.host, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestIntegration_ServerClose_Idempotent verifies that Close can be called
// multiple times without panicking.
func TestIntegration_ServerClose_Idempotent(t *testing.T) {
	ctx := context.Background()
	cs, err := oauth.StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)

	err = cs.Close()
	assert.NoError(t, err)

	// Second close should not panic or return a surprising error
	err = cs.Close()
	assert.NoError(t, err)
}

// TestIntegration_HTMLResponse_ContentType verifies that HTML responses include
// the correct Content-Type header.
func TestIntegration_HTMLResponse_ContentType(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?code=test-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	assert.Contains(t, ct, "text/html")
}

// TestIntegration_XSSPrevention verifies that error messages in HTML responses
// are properly escaped to prevent XSS attacks.
func TestIntegration_XSSPrevention(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Inject a script tag via the error parameter
	xssPayload := "<script>alert('xss')</script>"
	resp, err := http.Get(fmt.Sprintf("%s/?error=%s", cs.RedirectURI, url.QueryEscape(xssPayload))) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// The raw script tag must NOT appear in the HTML output
	assert.NotContains(t, string(body), "<script>")
	// The escaped version should be present without double-escaping
	assert.Contains(t, string(body), "&lt;script&gt;")
	assert.NotContains(t, string(body), "&amp;lt;")
	assert.Contains(t, string(body), "color-scheme: dark")

	// Drain the result channel
	<-cs.ResultChan()
}

// TestIntegration_DeferredCompletion_FullLifecycle verifies end-to-end deferred
// callback completion with custom HTML pages and graceful shutdown.
func TestIntegration_DeferredCompletion_FullLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pages := oauth.CallbackPages{
		SuccessHTML: []byte("<!DOCTYPE html><html><body><h1>Connected</h1></body></html>"),
		FailureHTML: []byte("<!DOCTYPE html><html><body><h1>Sign-in Failed</h1></body></html>"),
	}
	cs, err := oauth.StartCallbackServer(ctx, 0, "int-def-state",
		oauth.WithCallbackPages(pages),
		oauth.WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer cs.Close()

	type deferredOutcome struct {
		status int
		body   string
		csp    string
		err    error
	}
	outCh := make(chan deferredOutcome, 1)
	go func() {
		resp, getErr := http.Get(cs.RedirectURI + "/?code=int-def-code&state=int-def-state") //nolint:noctx // test code
		if getErr != nil {
			outCh <- deferredOutcome{err: getErr}
			return
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		outCh <- deferredOutcome{
			status: resp.StatusCode,
			body:   string(body),
			csp:    resp.Header.Get("Content-Security-Policy"),
			err:    readErr,
		}
	}()

	result := <-cs.ResultChan()
	require.NoError(t, result.Err)
	assert.Equal(t, "int-def-code", result.Code)

	cs.Complete(true)

	select {
	case out := <-outCh:
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusOK, out.status)
		assert.Equal(t, string(pages.SuccessHTML), out.body)
		assert.NotEmpty(t, out.csp)
	case <-ctx.Done():
		t.Fatal("timed out waiting for deferred callback response")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	require.NoError(t, cs.Shutdown(shutdownCtx))

	// Also verify Complete(false) delivers 503 + FailureHTML end-to-end.
	csFail, err := oauth.StartCallbackServer(ctx, 0, "int-def-fail-state",
		oauth.WithCallbackPages(pages),
		oauth.WithDeferredCompletion(),
	)
	require.NoError(t, err)
	defer csFail.Close()

	failCh := make(chan deferredOutcome, 1)
	go func() {
		resp, getErr := http.Get(csFail.RedirectURI + "/?code=int-fail-code&state=int-def-fail-state") //nolint:noctx // test code
		if getErr != nil {
			failCh <- deferredOutcome{err: getErr}
			return
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		failCh <- deferredOutcome{
			status: resp.StatusCode,
			body:   string(body),
			csp:    resp.Header.Get("Content-Security-Policy"),
			err:    readErr,
		}
	}()

	failRes := <-csFail.ResultChan()
	require.NoError(t, failRes.Err)
	csFail.Complete(false)

	select {
	case out := <-failCh:
		require.NoError(t, out.err)
		assert.Equal(t, http.StatusServiceUnavailable, out.status)
		assert.Equal(t, string(pages.FailureHTML), out.body)
		assert.NotEmpty(t, out.csp)
	case <-ctx.Done():
		t.Fatal("timed out waiting for deferred failure response")
	}

	require.NoError(t, csFail.Shutdown(context.Background()))
}

// TestIntegration_ErrorControlCharAndLengthSanitization verifies end-to-end
// sanitization of C0, DEL, C1, ANSI CSI, OSC, and overlong error fields in both
// authorization-code and implicit callback servers.
func TestIntegration_ErrorControlCharAndLengthSanitization(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rawErr := "\x1b[31maccess_denied\x7f\u009b" + strings.Repeat("x", 200)
	rawDesc := "\x1b]52;c;ZXY=\x07\x00\u009dFAKE\r\nLINE2 " + strings.Repeat("y", 600)

	checkErr := func(t *testing.T, got error) {
		t.Helper()
		require.Error(t, got)
		msg := got.Error()
		assert.True(t, utf8.ValidString(msg))
		assert.Contains(t, msg, "access_denied")
		assert.Contains(t, msg, "FAKE LINE2")
		assert.NotContains(t, msg, "\x1b")
		for _, r := range msg {
			assert.False(t, unicode.IsControl(r), "control rune %U must not appear in %q", r, msg)
		}
		assert.LessOrEqual(t, utf8.RuneCountInString(msg), len("OAuth error: ")+128+len(": ")+512)
	}

	csAuth, err := oauth.StartCallbackServer(ctx, 0, "int-san-state")
	require.NoError(t, err)
	defer csAuth.Close()

	q := url.Values{
		"state":             {"int-san-state"},
		"error":             {rawErr},
		"error_description": {rawDesc},
	}
	respAuth, err := http.Get(csAuth.RedirectURI + "/?" + q.Encode()) //nolint:noctx // test code
	require.NoError(t, err)
	_ = respAuth.Body.Close()
	assert.Equal(t, http.StatusBadRequest, respAuth.StatusCode)
	checkErr(t, (<-csAuth.ResultChan()).Err)

	csImp, err := oauth.StartImplicitCallbackServer(ctx, 0, "int-imp-san-state")
	require.NoError(t, err)
	defer csImp.Close()

	form := url.Values{
		"state":             {"int-imp-san-state"},
		"error":             {rawErr},
		"error_description": {rawDesc},
	}
	respImp, err := http.Post(csImp.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode())) //nolint:noctx // test code
	require.NoError(t, err)
	_ = respImp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, respImp.StatusCode)
	checkErr(t, (<-csImp.ResultChan()).Err)
}
