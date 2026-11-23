// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartCallbackServer(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	assert.Contains(t, cs.RedirectURI, "http://localhost:")
}

func TestCallbackServer_ReceivesCode(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Simulate the OAuth redirect
	resp, err := http.Get(cs.RedirectURI + "/?code=test-auth-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlBody := string(body)
	assert.Contains(t, htmlBody, "Authentication Successful")
	assert.Contains(t, htmlBody, "You can close this window and return to the terminal.")
	assert.Contains(t, htmlBody, "color-scheme: dark")
	assert.Contains(t, htmlBody, "<style>")
	assert.Equal(t, 1, strings.Count(strings.ToLower(htmlBody), "<h1"))
	assert.NotContains(t, strings.ToLower(htmlBody), "<script")
	assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "test-auth-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_ReceivesError(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Simulate an OAuth error redirect
	resp, err := http.Get(cs.RedirectURI + "/?error=access_denied&error_description=user+cancelled") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "access_denied")
		assert.Contains(t, result.Err.Error(), "user cancelled")
		assert.Empty(t, result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_NoCode(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// No code or error params
	resp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "no authorization code received")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := StartCallbackServer(ctx, 0, "")
	// Should fail because the context is already cancelled
	assert.Error(t, err)
}

func TestCallbackServer_Close(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)

	err = cs.Close()
	assert.NoError(t, err)

	// Verify the server is no longer accepting connections
	resp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	if resp != nil {
		resp.Body.Close()
	}
	assert.Error(t, err, "request should fail after server is closed")
}

func TestCallbackServer_HTMLEscapesErrors(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Send an error with HTML characters
	resp, err := http.Get(fmt.Sprintf("%s/?error=%s", cs.RedirectURI, "<script>alert('xss')</script>")) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlBody := string(body)
	assert.Contains(t, htmlBody, "color-scheme: dark")
	assert.Contains(t, htmlBody, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;")
	assert.NotContains(t, strings.ToLower(htmlBody), "<script")
	assert.NotContains(t, htmlBody, "&amp;lt;", "already-escaped error message must not be double-escaped")
	assert.Equal(t, finalPageCSP, resp.Header.Get("Content-Security-Policy"))

	// The error channel should still receive the result
	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_FixedPort(t *testing.T) {
	ctx := context.Background()

	// Use a fixed port; pick a high port unlikely to collide.
	cs, err := StartCallbackServer(ctx, 18947, "")
	require.NoError(t, err)
	defer cs.Close()

	assert.Equal(t, "http://localhost:18947", cs.RedirectURI)

	// Verify it actually serves on that port.
	resp, err := http.Get(cs.RedirectURI + "/?code=fixed-port-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "fixed-port-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_FixedPortAlreadyInUse(t *testing.T) {
	ctx := context.Background()

	// Bind a port first.
	cs1, err := StartCallbackServer(ctx, 18948, "")
	require.NoError(t, err)
	defer cs1.Close()

	// Second attempt on the same port should fail.
	_, err = StartCallbackServer(ctx, 18948, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "18948")
}

func TestCallbackServer_StateValidation_Matches(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "random-state-123")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?code=test-code&state=random-state-123") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "test-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_StateValidation_Mismatch(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "expected-state")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?code=test-code&state=wrong-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("mismatched state must not deliver a CallbackResult, got: %+v", result)
	default:
	}

	// Legitimate redirect afterwards still succeeds.
	validResp, err := http.Get(cs.RedirectURI + "/?code=real-code&state=expected-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "real-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid callback result")
	}
}

func TestCallbackServer_StateValidation_Missing(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "expected-state")
	require.NoError(t, err)
	defer cs.Close()

	// Code present but state missing from callback: rejected without terminating wait.
	resp, err := http.Get(cs.RedirectURI + "/?code=test-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("missing state must not deliver a CallbackResult, got: %+v", result)
	default:
	}

	// Legitimate redirect afterwards still succeeds.
	validResp, err := http.Get(cs.RedirectURI + "/?code=real-code&state=expected-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "real-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid callback result")
	}
}

func TestCallbackServer_ErrorAndNonGetGuardsDoNotPoisonResultChan(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "secret-state")
	require.NoError(t, err)
	defer cs.Close()

	// 1. Issue #17 repro: GET /?error=access_denied&error_description=%1b[31mFAKE with missing state.
	respMissing, err := http.Get(cs.RedirectURI + "/?error=access_denied&error_description=%1b[31mFAKE") //nolint:noctx // test code
	require.NoError(t, err)
	_ = respMissing.Body.Close()
	assert.Equal(t, http.StatusForbidden, respMissing.StatusCode)

	// 2. GET /?error=access_denied with wrong state.
	respWrong, err := http.Get(cs.RedirectURI + "/?error=access_denied&state=forged-state") //nolint:noctx // test code
	require.NoError(t, err)
	_ = respWrong.Body.Close()
	assert.Equal(t, http.StatusForbidden, respWrong.StatusCode)

	// 3. GET / with neither code nor state.
	respBare, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	require.NoError(t, err)
	_ = respBare.Body.Close()
	assert.Equal(t, http.StatusForbidden, respBare.StatusCode)

	// 4. POST / returns 405 Method Not Allowed without poisoning ResultChan.
	respPost, err := http.Post(cs.RedirectURI+"/?error=access_denied&state=secret-state", "text/plain", strings.NewReader("body")) //nolint:noctx // test code
	require.NoError(t, err)
	postBody, err := io.ReadAll(respPost.Body)
	_ = respPost.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, respPost.StatusCode)
	assert.Equal(t, http.MethodGet, respPost.Header.Get("Allow"))
	assert.NotEmpty(t, respPost.Header.Get("Content-Length"))
	assert.Contains(t, string(postBody), "method not allowed")

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("forged requests must not poison ResultChan, got: %+v", result)
	default:
	}

	// 5. Subsequent valid redirect still completes the flow cleanly.
	respOK, err := http.Get(cs.RedirectURI + "/?code=ok-after-attacks&state=secret-state") //nolint:noctx // test code
	require.NoError(t, err)
	_ = respOK.Body.Close()
	assert.Equal(t, http.StatusOK, respOK.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "ok-after-attacks", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid callback result")
	}
}

func TestCallbackServer_ErrorWithValidState_ReturnsError(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "valid-state-xyz")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?error=access_denied&error_description=user+denied&state=valid-state-xyz") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Equal(t, "OAuth error: access_denied: user denied", result.Err.Error())
		assert.Empty(t, result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback error result")
	}
}

func TestCallbackServer_ErrorAndCodeTogether_PrioritizesError(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "valid-state")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/?error=server_error&code=ambiguous&state=valid-state") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "server_error")
		assert.Empty(t, result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback error result")
	}
}

func TestCallbackServer_NoExpectedState_SkipsValidation(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Empty state skips validation -- backward-compatible behavior
	resp, err := http.Get(cs.RedirectURI + "/?code=test-code") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "test-code", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

// ---------- implicit grant callback tests ----------

func TestStartImplicitCallbackServer(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	assert.Contains(t, cs.RedirectURI, "http://localhost:")
}

func TestImplicitCallbackServer_ServesHTMLPage(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	htmlBody := string(body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, htmlBody, "window.location.hash")
	assert.Contains(t, htmlBody, "/token")
	assert.Contains(t, htmlBody, "Completing authentication...")
	assert.Contains(t, htmlBody, `<p id="status">Processing...</p>`)
	assert.Contains(t, htmlBody, "color-scheme: dark")
	assert.Contains(t, htmlBody, ".spinner")
	assert.Contains(t, htmlBody, "prefers-reduced-motion: reduce")
	assert.Equal(t, 1, strings.Count(htmlBody, "<h1"), "bridge page must have exactly one h1")
	assert.NotContains(t, htmlBody, "https://", "bridge page must remain self-contained offline")
	assert.NotContains(t, htmlBody, "http://", "bridge page must remain self-contained offline")
	assert.Equal(t, implicitBridgeCSP(), resp.Header.Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
}

func TestImplicitCallbackServer_ReceivesToken(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Simulate the JavaScript POSTing the fragment data
	tokenData := "access_token=test-implicit-token&token_type=Bearer&expires_in=3600"
	resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "test-implicit-token", result.AccessToken)
		assert.Equal(t, "Bearer", result.TokenType)
		assert.Equal(t, "3600", result.ExpiresIn)
		assert.Empty(t, result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestImplicitCallbackServer_MissingToken(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// POST with no access_token
	resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("token_type=Bearer")) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "no access_token")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestImplicitCallbackServer_OAuthError(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	errorData := "error=access_denied&error_description=user+cancelled"
	resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(errorData)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
		assert.Contains(t, result.Err.Error(), "access_denied")
		assert.Contains(t, result.Err.Error(), "user cancelled")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestImplicitCallbackServer_StateValidation_Matches(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "my-state-123")
	require.NoError(t, err)
	defer cs.Close()

	tokenData := "access_token=tok&token_type=Bearer&state=my-state-123"
	resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "tok", result.AccessToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestImplicitCallbackServer_StateValidation_Mismatch(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "expected-state")
	require.NoError(t, err)
	defer cs.Close()

	for _, payload := range []string{
		"access_token=tok&token_type=Bearer&state=wrong-state",
		"error=access_denied&error_description=spoofed&state=wrong-state",
	} {
		resp, postErr := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(payload)) //nolint:noctx // test code
		require.NoError(t, postErr)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("mismatched implicit state must not poison ResultChan, got: %+v", result)
	default:
	}

	validResp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("access_token=real-tok&token_type=Bearer&state=expected-state")) //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "real-tok", result.AccessToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for valid implicit callback result")
	}
}

func TestImplicitCallbackServer_StateValidation_Missing(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "my-state")
	require.NoError(t, err)
	defer cs.Close()

	// Missing state on both token and error payloads must return 403 without poisoning ResultChan.
	for _, payload := range []string{
		"access_token=tok&token_type=Bearer",
		"error=access_denied&error_description=spoofed",
	} {
		resp, postErr := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(payload)) //nolint:noctx // test code
		require.NoError(t, postErr)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	}

	// Non-POST and malformed body also must not poison ResultChan.
	getResp, err := http.Get(cs.RedirectURI + "/token?access_token=tok&state=my-state") //nolint:noctx // test code
	require.NoError(t, err)
	_ = getResp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, getResp.StatusCode)
	assert.Equal(t, http.MethodPost, getResp.Header.Get("Allow"))

	badResp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("%ZZ")) //nolint:noctx // test code
	require.NoError(t, err)
	_ = badResp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, badResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		t.Fatalf("unauthenticated implicit requests must not poison ResultChan, got: %+v", result)
	default:
	}

	validResp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader("access_token=tok&token_type=Bearer&state=my-state")) //nolint:noctx // test code
	require.NoError(t, err)
	defer validResp.Body.Close()
	assert.Equal(t, http.StatusOK, validResp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		require.NoError(t, result.Err)
		assert.Equal(t, "tok", result.AccessToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestImplicitCallbackServer_RejectsGET(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(cs.RedirectURI + "/token?access_token=tok") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestImplicitCallbackServer_RejectsCrossOrigin(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	tokenData := "access_token=tok&token_type=Bearer"
	req, err := http.NewRequest(http.MethodPost, cs.origin+"/token", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestImplicitCallbackServer_AllowsSameOrigin(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	tokenData := "access_token=tok&token_type=Bearer"
	req, err := http.NewRequest(http.MethodPost, cs.origin+"/token", strings.NewReader(tokenData)) //nolint:noctx // test code
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", cs.origin)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "tok", result.AccessToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestAuthErrorHTML_ContainsTroubleshooting(t *testing.T) {
	page := authErrorHTML("something &lt;went&gt; wrong")
	assert.Contains(t, page, "Authentication Failed")
	assert.Contains(t, page, "something &lt;went&gt; wrong")
	assert.NotContains(t, page, "&amp;lt;", "pre-escaped input must not be double-escaped")
	assert.Contains(t, page, "Troubleshooting")
	assert.Contains(t, page, "<h2>Troubleshooting</h2>")
	assert.Contains(t, page, "log in to your identity provider")
	assert.Contains(t, page, "You can close this window.")
	assert.Contains(t, page, "color-scheme: dark")
	assert.Contains(t, page, "<style>")
	assert.Equal(t, 1, strings.Count(strings.ToLower(page), "<h1"))
	assert.NotContains(t, strings.ToLower(page), "<script")
	assert.NotContains(t, strings.ToLower(page), "http://")
	assert.NotContains(t, strings.ToLower(page), "https://")
}

func TestCallbackServer_ErrorPageIncludesTroubleshooting(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	resp, err := http.Get(fmt.Sprintf("%s/?error=access_denied&error_description=user+not+found", cs.RedirectURI)) //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "Troubleshooting")
	assert.Contains(t, string(body), "log in to your identity provider")

	select {
	case result := <-cs.ResultChan():
		assert.Error(t, result.Err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_WithCallbackHost(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "", WithCallbackHost("127.0.0.1"))
	require.NoError(t, err)
	defer cs.Close()

	assert.Contains(t, cs.RedirectURI, "http://127.0.0.1:")
	assert.NotContains(t, cs.RedirectURI, "localhost")

	resp, err := http.Get(cs.RedirectURI + "/?code=host-test") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "host-test", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_WithCallbackPath(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "", WithCallbackPath("/auth/callback"))
	require.NoError(t, err)
	defer cs.Close()

	assert.Contains(t, cs.RedirectURI, "/auth/callback")

	resp, err := http.Get(cs.RedirectURI + "?code=path-test") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "path-test", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_WithBothHostAndPath(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 18949, "",
		WithCallbackHost("127.0.0.1"),
		WithCallbackPath("/oauth/redirect"),
	)
	require.NoError(t, err)
	defer cs.Close()

	assert.Equal(t, "http://127.0.0.1:18949/oauth/redirect", cs.RedirectURI)

	resp, err := http.Get(cs.RedirectURI + "?code=both-test") //nolint:noctx // test code
	require.NoError(t, err)
	defer resp.Body.Close()

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "both-test", result.Code)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestStartCallbackServer_InvalidHost(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"external IP", "0.0.0.0"},
		{"remote host", "evil.com"},
		{"private IP", "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := StartCallbackServer(ctx, 0, "", WithCallbackHost(tt.host))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not allowed")
		})
	}
}

func TestStartCallbackServer_InvalidPath(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"no leading slash", "auth/callback"},
		{"path traversal", "/auth/../secret"},
		{"double dot", "/.."},
		{"reserved /token path", "/token"},
		{"query string", "/callback?code=abc"},
		{"fragment", "/callback#section"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, err := StartCallbackServer(ctx, 0, "", WithCallbackPath(tt.path))
			require.Error(t, err)
		})
	}
}

func TestStartImplicitCallbackServer_InvalidHost(t *testing.T) {
	ctx := context.Background()
	_, err := StartImplicitCallbackServer(ctx, 0, "", WithCallbackHost("0.0.0.0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestStartImplicitCallbackServer_WithPath(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "",
		WithCallbackHost("127.0.0.1"),
		WithCallbackPath("/auth/callback"),
	)
	require.NoError(t, err)
	defer cs.Close()

	// Verify the RedirectURI includes the path
	assert.Contains(t, cs.RedirectURI, "http://127.0.0.1:")
	assert.Contains(t, cs.RedirectURI, "/auth/callback")

	// Verify that the origin field is scheme://host:port only (no path)
	assert.Equal(t, cs.origin, strings.TrimSuffix(cs.RedirectURI, "/auth/callback"))
}

func TestStartCallbackServer_IPv6Host(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "", WithCallbackHost("::1"))
	require.NoError(t, err)
	defer cs.Close()

	// IPv6 address must be bracketed in the URI
	assert.Contains(t, cs.RedirectURI, "http://[::1]:")
}

func TestStartCallbackServer_DefaultPathOmitsSlash(t *testing.T) {
	ctx := context.Background()
	cs, err := StartCallbackServer(ctx, 0, "")
	require.NoError(t, err)
	defer cs.Close()

	// Default path "/" is omitted from the redirect URI to preserve the
	// traditional format expected by OAuth providers doing exact matching.
	assert.False(t, strings.HasSuffix(cs.RedirectURI, "/"),
		"expected default RedirectURI %q to not end with /", cs.RedirectURI)
}

func TestImplicitCallbackServer_OriginCheckWithPath(t *testing.T) {
	ctx := context.Background()
	cs, err := StartImplicitCallbackServer(ctx, 0, "",
		WithCallbackPath("/auth/callback"),
	)
	require.NoError(t, err)
	defer cs.Close()

	// POST to /token with the correct Origin (scheme://host:port, no path).
	// This should succeed -- the bug was that it compared Origin against the
	// full RedirectURI which includes the path, causing a 403.
	tokenURL := cs.origin + "/token"
	body := strings.NewReader("access_token=test-token&token_type=bearer")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", cs.origin)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case result := <-cs.ResultChan():
		assert.NoError(t, result.Err)
		assert.Equal(t, "test-token", result.AccessToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for implicit callback result")
	}
}

func TestValidateCallbackHostPath(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		path    string
		wantErr bool
	}{
		{"empty defaults are valid", "", "", false},
		{"localhost valid", "localhost", "/", false},
		{"127.0.0.1 valid", "127.0.0.1", "/auth/callback", false},
		{"::1 valid", "::1", "/", false},
		{"external host rejected", "evil.com", "/", true},
		{"0.0.0.0 rejected", "0.0.0.0", "/", true},
		{"path traversal rejected", "localhost", "/auth/../secret", true},
		{"no leading slash rejected", "localhost", "auth/callback", true},
		{"/token reserved", "localhost", "/token", true},
		{"query string rejected", "localhost", "/callback?code=abc", true},
		{"fragment rejected", "localhost", "/callback#section", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCallbackHostPath(tt.host, tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func assertNoControlRunes(t *testing.T, s string) {
	t.Helper()
	assert.True(t, utf8.ValidString(s), "sanitized string must be valid UTF-8: %q", s)
	for i, r := range s {
		assert.False(t, unicode.IsControl(r), "unexpected control rune %U at byte %d in %q", r, i, s)
		assert.False(t, isDisallowedControlRune(r), "unexpected disallowed rune %U at byte %d in %q", r, i, s)
	}
}

func TestSanitizeOAuthError(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxRunes int
		want     string
	}{
		{
			name:     "plain ASCII unchanged",
			input:    "access_denied",
			maxRunes: maxOAuthErrorRunes,
			want:     "access_denied",
		},
		{
			name:     "unicode text preserved",
			input:    "accès refusé: 権限がありません",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "accès refusé: 権限がありません",
		},
		{
			name:     "empty or non-positive maxRunes",
			input:    "access_denied",
			maxRunes: 0,
			want:     "",
		},
		{
			name:     "ANSI CSI escape sequence stripped of ESC",
			input:    "\x1b[31mFAKE ERROR\x1b[0m",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "[31mFAKE ERROR[0m",
		},
		{
			name:     "OSC 52 clipboard sequence stripped of ESC and BEL",
			input:    "\x1b]52;c;Y3VybCBldmls\x07clipboard",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "]52;c;Y3VybCBldmlsclipboard",
		},
		{
			name:     "C0, DEL, C1 runes and all bidi control ranges removed",
			input:    "a\x00b\x07c\x08d\x7fe\u0080f\u009bg\u009dh\u009fi\u061cj\u200ek\u200fl\u202am\u202en\u202co\u2066p\u2069q",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "abcdefghijklmnopq",
		},
		{
			name:     "raw invalid UTF-8 C1 bytes dropped",
			input:    "bad\x9b31m\x80\x9ftext",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "bad31mtext",
		},
		{
			name:     "whitespace controls and repeated spaces normalized and trimmed",
			input:    "\r\n\t  line one\r\n   line two\u2028line three\u2029\n  ",
			maxRunes: maxOAuthErrorDescRunes,
			want:     "line one line two line three",
		},
		{
			name:     "leading spaces do not exhaust maxRunes budget",
			input:    strings.Repeat(" ", 200) + "access_denied",
			maxRunes: maxOAuthErrorRunes,
			want:     "access_denied",
		},
		{
			name:     "whitespace separator landing on maxRunes boundary does not emit trailing space",
			input:    "ab\nc",
			maxRunes: 3,
			want:     "ab",
		},
		{
			name:     "only control characters yields empty string",
			input:    "\x00\x07\x1b\x7f\u0085\u009b\r\n\t",
			maxRunes: maxOAuthErrorRunes,
			want:     "",
		},
		{
			name:     "overlong ASCII capped at maxRunes",
			input:    strings.Repeat("x", 300),
			maxRunes: maxOAuthErrorRunes,
			want:     strings.Repeat("x", maxOAuthErrorRunes),
		},
		{
			name:     "overlong multi-byte UTF-8 capped by rune count without splitting UTF-8",
			input:    strings.Repeat("é", 700),
			maxRunes: maxOAuthErrorDescRunes,
			want:     strings.Repeat("é", maxOAuthErrorDescRunes),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeOAuthError(tt.input, tt.maxRunes)
			assert.Equal(t, tt.want, got)
			assertNoControlRunes(t, got)
			if tt.maxRunes > 0 {
				assert.LessOrEqual(t, utf8.RuneCountInString(got), tt.maxRunes)
			}
		})
	}

	assert.Equal(t, "unknown_error: details", formatOAuthError("\x1b\x07", "details"))
}

func TestCallbackServers_SanitizeControlCharsAndCapLength(t *testing.T) {
	maliciousErr := "\x1b[31maccess_denied\x7f\u009b\u202e" + strings.Repeat("E", 250)
	maliciousDesc := "\x1b]52;c;cHduZWQ=\x07\x00\u009d\u2066line1\r\nline2 " + strings.Repeat("D", 700)

	extractErrorDetail := func(t *testing.T, htmlDoc string) string {
		t.Helper()
		const startTag = `<p class="error-detail">`
		_, after, ok := strings.Cut(htmlDoc, startTag)
		require.True(t, ok, "expected %s in HTML response", startTag)
		detail, _, ok := strings.Cut(after, "</p>")
		require.True(t, ok, "expected closing </p> after error-detail")
		return detail
	}

	t.Run("authorization code callback", func(t *testing.T) {
		cs, err := StartCallbackServer(context.Background(), 0, "st-san")
		require.NoError(t, err)
		defer cs.Close()

		q := url.Values{
			"state":             {"st-san"},
			"error":             {maliciousErr},
			"error_description": {maliciousDesc},
		}
		resp, err := http.Get(cs.RedirectURI + "/?" + q.Encode()) //nolint:noctx // test code
		require.NoError(t, err)
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assertNoControlRunes(t, extractErrorDetail(t, string(body)))

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assertNoControlRunes(t, res.Err.Error())
		assert.NotContains(t, res.Err.Error(), "\x1b")
		assert.LessOrEqual(t, utf8.RuneCountInString(res.Err.Error()), len("OAuth error: ")+maxOAuthErrorRunes+len(": ")+maxOAuthErrorDescRunes)
	})

	t.Run("authorization code missing code with control-char error_description", func(t *testing.T) {
		cs, err := StartCallbackServer(context.Background(), 0, "st-nocode")
		require.NoError(t, err)
		defer cs.Close()

		q := url.Values{
			"state":             {"st-nocode"},
			"error_description": {"\x1b[31mFAKE\x07"},
		}
		resp, err := http.Get(cs.RedirectURI + "/?" + q.Encode()) //nolint:noctx // test code
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assertNoControlRunes(t, res.Err.Error())
		assert.Equal(t, "OAuth error: no authorization code received: [31mFAKE", res.Err.Error())
	})

	t.Run("implicit token POST callback", func(t *testing.T) {
		cs, err := StartImplicitCallbackServer(context.Background(), 0, "st-imp-san")
		require.NoError(t, err)
		defer cs.Close()

		form := url.Values{
			"state":             {"st-imp-san"},
			"error":             {maliciousErr},
			"error_description": {maliciousDesc},
		}
		resp, err := http.Post(cs.RedirectURI+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode())) //nolint:noctx // test code
		require.NoError(t, err)
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, readErr)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assertNoControlRunes(t, extractErrorDetail(t, string(body)))

		res := <-cs.ResultChan()
		require.Error(t, res.Err)
		assertNoControlRunes(t, res.Err.Error())
		assert.NotContains(t, res.Err.Error(), "\x1b")
		assert.LessOrEqual(t, utf8.RuneCountInString(res.Err.Error()), len("OAuth error: ")+maxOAuthErrorRunes+len(": ")+maxOAuthErrorDescRunes)
	})
}
