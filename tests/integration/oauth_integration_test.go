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

// TestIntegration_AuthCodeFlow_CSRFRejection verifies that a mismatched state
// parameter is rejected, preventing CSRF attacks.
func TestIntegration_AuthCodeFlow_CSRFRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "legitimate-state")
	require.NoError(t, err)
	defer cs.Close()

	// Attacker sends a different state value
	resp, err := http.Get(cs.RedirectURI + "/?code=stolen-code&state=attacker-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "state parameter mismatch")
		assert.Empty(t, result.Code)
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
	}
}

// TestIntegration_AuthCodeFlow_OAuthError simulates the identity provider
// returning an error (e.g., user denied consent).
func TestIntegration_AuthCodeFlow_OAuthError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?error=consent_required&error_description=User+denied+access") //nolint:noctx // test code
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
// to the callback endpoint are rejected.
func TestIntegration_AuthCodeFlow_MethodNotAllowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Post(cs.RedirectURI+"/?code=test", "text/plain", nil) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "method not allowed")
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
// rejects mismatched state parameters.
func TestIntegration_ImplicitFlow_CSRFRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := oauth.StartImplicitCallbackServer(ctx, 0, "expected-implicit-state")
	require.NoError(t, err)
	defer cs.Close()

	tokenData := "access_token=tok&token_type=Bearer&state=wrong-state"
	resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "state parameter mismatch")
	case <-ctx.Done():
		t.Fatal("timed out waiting for callback result")
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
	// The escaped version should be present
	assert.Contains(t, string(body), "&lt;script&gt;")

	// Drain the result channel
	<-cs.ResultChan()
}
