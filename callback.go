// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CallbackResult holds the outcome of a local OAuth callback.
type CallbackResult struct {
	// Code is the authorization code received from the identity provider.
	Code string
	// AccessToken is the token received directly via implicit grant flow.
	AccessToken string //nolint:gosec // struct field, not a hardcoded credential
	// TokenType is the token type from an implicit grant response (e.g. "Bearer").
	TokenType string
	// ExpiresIn is the token lifetime in seconds from an implicit grant response.
	ExpiresIn string
	// Err is set if an error was received instead of a code.
	Err error
}

// implicitTokenPath is the path used by the implicit grant flow to receive
// POSTed token data from the browser. It is reserved and cannot be used as
// a custom callback path.
const implicitTokenPath = "/token"

// allowedCallbackHosts is the set of hosts permitted for the OAuth callback
// server. Only loopback addresses are allowed to prevent binding on external
// interfaces.
var allowedCallbackHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"::1":       true,
}

// ValidateCallbackHostPath validates callback host and path values
// without starting a server. This is intended for config-time validation.
func ValidateCallbackHostPath(host, path string) error {
	cfg := &callbackConfig{
		host: host,
		path: path,
	}
	if host == "" {
		cfg.host = "localhost"
	}
	if path == "" {
		cfg.path = "/"
	}
	return validateCallbackConfig(cfg)
}

// CallbackOption configures optional parameters for the callback server.
type CallbackOption func(*callbackConfig)

const (
	defaultServerIOTimeout   = 30 * time.Second
	defaultServerIdleTimeout = 60 * time.Second
)

type callbackConfig struct {
	host string
	path string
	// pages holds the deferred-completion final documents (WithCallbackPages).
	pages CallbackPages
	// customPages records that WithCallbackPages was explicitly configured,
	// even when both HTML slices are empty (requesting safe generic fallbacks).
	customPages bool
	// deferred enables hold-the-response-until-Complete behavior.
	deferred bool
	// ioTimeout sets ReadTimeout, ReadHeaderTimeout, and WriteTimeout on http.Server.
	ioTimeout time.Duration
}

func withServerIOTimeout(d time.Duration) CallbackOption {
	return func(c *callbackConfig) {
		c.ioTimeout = d
	}
}

// WithCallbackHost sets the host used in the redirect URI (default: "localhost").
// Only loopback addresses are allowed: "localhost", "127.0.0.1", or "::1".
func WithCallbackHost(host string) CallbackOption {
	return func(c *callbackConfig) {
		c.host = host
	}
}

// WithCallbackPath sets the path component of the redirect URI (default: "/").
// The path must start with "/" and must not contain ".." segments.
func WithCallbackPath(path string) CallbackOption {
	return func(c *callbackConfig) {
		c.path = path
	}
}

// validateCallbackConfig validates the callback configuration.
func validateCallbackConfig(cfg *callbackConfig) error {
	if !allowedCallbackHosts[cfg.host] {
		return fmt.Errorf("callback host %q is not allowed: must be localhost, 127.0.0.1, or ::1", cfg.host)
	}
	if cfg.path != "" && cfg.path != "/" {
		if !strings.HasPrefix(cfg.path, "/") {
			return fmt.Errorf("callback path %q must start with /", cfg.path)
		}
		if strings.Contains(cfg.path, "..") {
			return fmt.Errorf("callback path %q must not contain '..' segments", cfg.path)
		}
		if strings.ContainsAny(cfg.path, "?#") {
			return fmt.Errorf("callback path %q must not contain query or fragment characters", cfg.path)
		}
		if cfg.path == implicitTokenPath {
			return fmt.Errorf("callback path %q is reserved for internal use by the implicit grant flow", cfg.path)
		}
	}
	return nil
}

// newCallbackServer creates and starts a listener, returning a CallbackServer
// with the RedirectURI set (including the configured path). The caller is
// responsible for registering HTTP handlers and calling Serve.
func newCallbackServer(ctx context.Context, port int, expectedState string, opts ...CallbackOption) (*CallbackServer, *callbackConfig, error) {
	cfg := callbackConfig{
		host:      "localhost",
		path:      "/",
		ioTimeout: defaultServerIOTimeout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := validateCallbackConfig(&cfg); err != nil {
		return nil, nil, err
	}

	// Format the host for use in addresses and URIs.
	// IPv6 addresses need brackets in host:port notation and URLs.
	listenHost := cfg.host
	uriHost := cfg.host
	if strings.Contains(cfg.host, ":") {
		listenHost = "[" + cfg.host + "]"
		uriHost = "[" + cfg.host + "]"
	}

	addr := listenHost + ":0"
	if port > 0 {
		addr = fmt.Sprintf("%s:%d", listenHost, port)
	}

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("starting local redirect server on %s: %w", addr, err)
	}

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		listener.Close()
		return nil, nil, fmt.Errorf("unexpected listener address type: %T", listener.Addr())
	}

	// Build the origin (scheme://host:port) separately for CORS checks.
	origin := fmt.Sprintf("http://%s:%d", uriHost, tcpAddr.Port)

	// Build the full redirect URI including the path.
	// When path is the default "/", omit it to preserve the traditional
	// redirect URI format (http://host:port) expected by existing OAuth
	// providers that do exact string matching.
	redirectURI := origin
	if cfg.path != "" && cfg.path != "/" {
		redirectURI += cfg.path
	}

	cs := &CallbackServer{
		RedirectURI:   redirectURI,
		origin:        origin,
		listener:      listener,
		resultCh:      make(chan CallbackResult, 1),
		expectedState: expectedState,
		ctx:           ctx,
		pages:         cfg.pages,
		customPages:   cfg.customPages,
		deferred:      cfg.deferred,
		completeSig:   make(chan struct{}),
	}
	if ctx != nil {
		cs.stopCancelWatch = context.AfterFunc(ctx, func() {
			cs.Complete(false)
		})
	}

	return cs, &cfg, nil
}

// CallbackServer manages a local HTTP server that listens for an OAuth redirect
// and captures the authorization code.
type CallbackServer struct {
	// RedirectURI is the localhost URI the identity provider should redirect to
	// (e.g. "http://localhost:54321/auth/callback").
	RedirectURI string

	// origin is the scheme://host:port portion of the redirect URI, used for
	// CORS Origin header validation in the implicit grant flow.
	origin string

	listener net.Listener
	server   *http.Server
	resultCh chan CallbackResult

	expectedState string
	resultOnce    sync.Once

	// ctx is the server's (flow) context; bounds deferred completion waits.
	ctx context.Context
	// stopCancelWatch unregisters the context.AfterFunc cancellation watcher.
	stopCancelWatch func() bool
	// pages holds the deferred-completion final documents.
	pages CallbackPages
	// customPages indicates WithCallbackPages was explicitly passed.
	customPages bool
	// deferred indicates WithDeferredCompletion was requested.
	deferred bool
	// Complete bookkeeping: completeOnce guards a one-shot settle;
	// completeOK is the settled outcome; completeSig is closed on settle.
	completeOnce sync.Once
	completeOK   bool
	completeSig  chan struct{}
}

// StartCallbackServer creates and starts a local HTTP server on a localhost
// port. When port is 0 an ephemeral port is chosen by the OS; when port > 0
// the server binds to that specific port so the redirect URI is predictable
// (useful when the app registration only allows specific redirect URIs).
//
// expectedState is the OAuth state parameter that must match the value returned
// in the callback. If non-empty, the callback handler rejects responses whose
// state does not match, preventing CSRF attacks. The state is set before the
// server begins accepting connections to close any race window.
//
// Options allow configuring the callback host (default "localhost") and path
// (default "/") for OAuth2 servers that validate the exact redirect URI, custom
// completion HTML (WithCallbackPages), and deferred browser completion
// (WithDeferredCompletion).
//
// The server waits for a single OAuth redirect, extracts the authorization
// code (or error), and sends it on the channel returned by ResultChan().
//
// The caller is responsible for calling Close() or Shutdown(ctx) when done.
func StartCallbackServer(ctx context.Context, port int, expectedState string, opts ...CallbackOption) (*CallbackServer, error) {
	cs, cfg, err := newCallbackServer(ctx, port, expectedState, opts...)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.path, cs.handleCallback)

	cs.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       cfg.ioTimeout,
		ReadHeaderTimeout: cfg.ioTimeout,
		WriteTimeout:      cfg.ioTimeout,
		IdleTimeout:       defaultServerIdleTimeout,
	}

	go func() {
		if sErr := cs.server.Serve(cs.listener); sErr != nil && sErr != http.ErrServerClosed {
			cs.sendResult(CallbackResult{Err: fmt.Errorf("redirect server error: %w", sErr)})
		}
	}()

	return cs, nil
}

// ResultChan returns the channel that will receive exactly one CallbackResult
// once the OAuth redirect arrives (or an error occurs).
func (cs *CallbackServer) ResultChan() <-chan CallbackResult {
	return cs.resultCh
}

// Close shuts down the callback server and its listener. Any unsettled
// deferred callback is marked failed before closing.
func (cs *CallbackServer) Close() error {
	if cs.server == nil {
		return nil
	}
	cs.Complete(false)
	if cs.stopCancelWatch != nil {
		cs.stopCancelWatch()
	}
	return cs.server.Close()
}

// sendResult delivers exactly one result to the channel. Subsequent calls are
// no-ops, preventing goroutine leaks when duplicate requests or server errors
// arrive after the first result has already been consumed.
func (cs *CallbackServer) sendResult(r CallbackResult) {
	cs.resultOnce.Do(func() {
		cs.resultCh <- r
	})
}

const authErrorHTMLPrefix = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication Failed</title>
<style>` + fallbackCardBaseCSS + `
  .card { width: min(34rem, 100%); max-width: 34rem; border-color: rgba(255, 194, 142, 0.45); }
  .badge { background: rgba(255, 194, 142, 0.14); color: #ffc28e; }
  .error-detail { margin: 14px 0 0; padding: 10px 14px; border-radius: 8px; background: rgba(255, 194, 142, 0.08); border: 1px solid rgba(255, 194, 142, 0.25); color: #ffc28e; font-size: 0.9rem; line-height: 1.5; overflow-wrap: anywhere; }
  h2 { margin: 20px 0 8px; font-size: 0.95rem; font-weight: 600; line-height: 1.35; color: #eff7ff; }
  ul { margin: 0; padding-left: 20px; color: #9bafc4; font-size: 0.9rem; line-height: 1.55; }
  li + li { margin-top: 6px; }
  code { padding: 2px 6px; border-radius: 4px; background: rgba(155, 175, 196, 0.14); color: #eff7ff; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; }
  .footer { margin-top: 16px; font-size: 0.85rem; color: #8da4bd; }
</style>
</head>
<body>
<main class="card" role="alert">
  <div class="row"><span class="badge" aria-hidden="true"><svg class="icon" viewBox="0 0 16 16" fill="none" focusable="false"><path d="M8 5V8.5M8 11H8.01" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/></svg></span><h1>Authentication Failed</h1></div>
  <p class="error-detail">`

const authErrorHTMLSuffix = `</p>
  <h2>Troubleshooting</h2>
  <ul>
    <li>Open a browser and log in to your identity provider (e.g. Azure, GitHub, Google) before retrying the CLI login.</li>
    <li>Ensure your account has the required permissions for the requested scopes.</li>
    <li>If you need additional scopes (e.g. for GitHub), re-run login with the --scope flag: <code>auth login &lt;handler&gt; --scope &lt;scope&gt;</code></li>
    <li>Check that cookies and JavaScript are enabled in the browser that opened this page.</li>
  </ul>
  <p class="footer">You can close this window.</p>
</main>
</body></html>`

// authErrorHTML returns a self-contained dark-card HTML error page with the
// error message and troubleshooting advice. The escapedErrMsg argument must
// already be HTML-escaped by the caller.
func authErrorHTML(escapedErrMsg string) string {
	return authErrorHTMLPrefix + escapedErrMsg + authErrorHTMLSuffix
}

func writePlainError(w http.ResponseWriter, msg string, status int) {
	body := msg + "\n"
	h := w.Header()
	h.Del("Content-Encoding")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func flushResponse(w http.ResponseWriter) {
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.Flush()
	}
}

func (cs *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePlainError(w, "method not allowed", http.StatusMethodNotAllowed)
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("method not allowed: %s", r.Method)})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errMsg := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = "no authorization code received"
		}
		if errDesc != "" {
			errMsg = fmt.Sprintf("%s: %s", errMsg, errDesc)
		}
		cs.writeErrorPage(w, http.StatusBadRequest, html.EscapeString(errMsg))
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("OAuth error: %s", errMsg)})
		return
	}

	// Validate state parameter to prevent CSRF attacks.
	// expectedState is set at construction before Serve() begins, so no
	// synchronization is required.
	if cs.expectedState != "" {
		gotHash := sha256.Sum256([]byte(r.URL.Query().Get("state")))
		expHash := sha256.Sum256([]byte(cs.expectedState))
		if subtle.ConstantTimeCompare(gotHash[:], expHash[:]) != 1 {
			errMsg := "state parameter mismatch (possible CSRF attack)"
			cs.writeErrorPage(w, http.StatusForbidden, html.EscapeString(errMsg))
			flushResponse(w)
			cs.sendResult(CallbackResult{Err: fmt.Errorf("OAuth error: %s", errMsg)})
			return
		}
	}

	cs.completeSuccess(w, r, CallbackResult{Code: code})
}

// StartImplicitCallbackServer creates a local HTTP server for the OAuth2
// implicit grant flow (response_type=token). The identity provider redirects
// to the callback URL with the access token in the URL fragment
// (#access_token=...). Because browsers do not send fragments to the server,
// the server serves an HTML page with JavaScript that extracts the fragment
// and POSTs the token back to a /token endpoint on the same server.
//
// If expectedState is non-empty, a provided state value must match it. Unlike
// StartCallbackServer, the implicit flow accepts a missing state value and
// only rejects explicit mismatches.
//
// Options allow configuring the callback host (default "localhost"), path
// (default "/"), custom completion HTML (WithCallbackPages), and deferred
// browser completion (WithDeferredCompletion).
//
// The caller is responsible for calling Close() or Shutdown(ctx) when done.
func StartImplicitCallbackServer(ctx context.Context, port int, expectedState string, opts ...CallbackOption) (*CallbackServer, error) {
	cs, cfg, err := newCallbackServer(ctx, port, expectedState, opts...)
	if err != nil {
		return nil, err
	}

	// For implicit flow, the configured path serves the HTML page that extracts
	// the fragment, and /token receives the POSTed token data.
	mux := http.NewServeMux()
	mux.HandleFunc(cfg.path, cs.handleImplicitCallback)
	mux.HandleFunc(implicitTokenPath, cs.handleImplicitTokenPost)

	cs.server = &http.Server{
		Handler:           mux,
		ReadTimeout:       cfg.ioTimeout,
		ReadHeaderTimeout: cfg.ioTimeout,
		WriteTimeout:      cfg.ioTimeout,
		IdleTimeout:       defaultServerIdleTimeout,
	}

	go func() {
		if sErr := cs.server.Serve(cs.listener); sErr != nil && sErr != http.ErrServerClosed {
			cs.sendResult(CallbackResult{Err: fmt.Errorf("redirect server error: %w", sErr)})
		}
	}()

	return cs, nil
}

// handleImplicitCallback serves the HTML page that extracts the access token
// from the URL fragment and POSTs it back to the local server.
func (cs *CallbackServer) handleImplicitCallback(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", implicitBridgeCSP())
	h.Set("Content-Length", strconv.Itoa(len(implicitCallbackHTML)))
	w.WriteHeader(http.StatusOK)
	// The JavaScript extracts fragment parameters and POSTs them as form data
	// to /token on the same origin. This runs entirely on localhost.
	_, _ = io.WriteString(w, implicitCallbackHTML)
}

const maxImplicitTokenBody = 8192

// handleImplicitTokenPost receives the token POSTed by the JavaScript on the
// implicit grant callback page.
func (cs *CallbackServer) handleImplicitTokenPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writePlainError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject cross-origin requests. A simple POST with application/x-www-form-urlencoded
	// Content-Type is not subject to CORS preflight, so a malicious page could inject
	// a forged token. When Origin is present it must match the local callback server's
	// origin (scheme://host:port), not the full redirect URI which may include a path.
	if origin := r.Header.Get("Origin"); origin != "" && origin != cs.origin {
		writePlainError(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxImplicitTokenBody))
	if err != nil {
		if cs.enhancedMode() {
			cs.writeErrorPage(w, http.StatusBadRequest, "")
		} else {
			writePlainError(w, "bad request", http.StatusBadRequest)
		}
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("read implicit token POST: %w", err)})
		return
	}

	params, err := url.ParseQuery(string(body))
	if err != nil {
		if cs.enhancedMode() {
			cs.writeErrorPage(w, http.StatusBadRequest, "")
		} else {
			writePlainError(w, "bad request", http.StatusBadRequest)
		}
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("parse implicit token POST: %w", err)})
		return
	}

	// Validate state parameter first to reject CSRF before processing any payload.
	// Some OAuth2 servers omit state from the implicit grant fragment.
	// Per RFC 6749 section 4.2.2, state is only REQUIRED in the response if it was
	// present in the request, but not all servers comply. Accept missing state (server
	// didn't echo it back); reject only when the server returns a *different* state
	// value.
	//
	// SECURITY NOTE: Accepting a missing state weakens CSRF protection. An attacker
	// who can induce a redirect without a state parameter could potentially inject a
	// token. Callers handling sensitive flows should prefer the authorization code
	// grant (StartCallbackServer) which strictly rejects missing state.
	if cs.expectedState != "" {
		returnedState := params.Get("state")
		if returnedState != "" {
			gotHash := sha256.Sum256([]byte(returnedState))
			expHash := sha256.Sum256([]byte(cs.expectedState))
			if subtle.ConstantTimeCompare(gotHash[:], expHash[:]) != 1 {
				errMsg := "state parameter mismatch (possible CSRF attack)"
				cs.writeErrorPage(w, http.StatusForbidden, html.EscapeString(errMsg))
				flushResponse(w)
				cs.sendResult(CallbackResult{Err: fmt.Errorf("OAuth error: %s", errMsg)})
				return
			}
		}
	}

	// Check for OAuth error in fragment
	if errCode := params.Get("error"); errCode != "" {
		errDesc := params.Get("error_description")
		errMsg := errCode
		if errDesc != "" {
			errMsg = fmt.Sprintf("%s: %s", errCode, errDesc)
		}
		cs.writeErrorPage(w, http.StatusBadRequest, html.EscapeString(errMsg))
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("OAuth error: %s", errMsg)})
		return
	}

	accessToken := params.Get("access_token")
	if accessToken == "" {
		if cs.enhancedMode() {
			cs.writeErrorPage(w, http.StatusBadRequest, "")
		} else {
			writePlainError(w, "missing access_token", http.StatusBadRequest)
		}
		flushResponse(w)
		cs.sendResult(CallbackResult{Err: fmt.Errorf("OAuth error: no access_token in redirect fragment")})
		return
	}

	cs.completeSuccess(w, r, CallbackResult{
		AccessToken: accessToken,
		TokenType:   params.Get("token_type"),
		ExpiresIn:   params.Get("expires_in"),
	})
}

// implicitBridgeScript extracts the URL fragment (#access_token=...), clears it
// from the address bar, POSTs it to /token on the same localhost origin, and
// renders the server's final HTML document inside a script-disabled sandboxed
// iframe so bridge JS and final-page DOM remain isolated.
const implicitBridgeScript = `
(function() {
  var hash = window.location.hash.substring(1);
  if (!hash) {
    document.body.className = "error";
    document.getElementById("status").textContent = "No token received.";
    return;
  }
  history.replaceState(null, "", window.location.pathname);
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "` + implicitTokenPath + `", true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.onload = function() {
    var ct = xhr.getResponseHeader("Content-Type") || "";
    if (xhr.responseText && ct.indexOf("text/html") !== -1) {
      var frame = document.createElement("iframe");
      frame.setAttribute("sandbox", "");
      frame.setAttribute("title", "Authentication status");
      frame.style.cssText = "position:fixed;inset:0;width:100%;height:100%;border:0;margin:0;padding:0;";
      frame.srcdoc = xhr.responseText;
      document.body.textContent = "";
      document.body.style.margin = "0";
      document.body.appendChild(frame);
      return;
    }
    if (xhr.status === 200) {
      document.body.className = "done";
      document.getElementById("status").textContent = "Authentication successful. You can close this window.";
    } else {
      document.body.className = "error";
      document.getElementById("status").textContent = "Authentication failed: " + xhr.statusText;
    }
  };
  xhr.onerror = function() {
    document.body.className = "error";
    document.getElementById("status").textContent = "Failed to communicate with local server.";
  };
  xhr.send(hash);
})();
`

// implicitCallbackHTML is the HTML page served by the implicit grant callback
// server. It extracts the access token from the URL fragment (#access_token=...)
// and POSTs it to /token on the same localhost server. Inline styles use a
// brand-neutral dark card so the interstitial avoids a white unstyled flash
// while POST /token awaits deferred completion and renders cleanly if a
// client-side fragment/network error leaves the user on this page.
const implicitCallbackHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; min-height: 100svh; display: grid; place-items: center; padding: 24px; background: #05152a; color: #eff7ff; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .card { width: min(28rem, 100%); padding: 32px 36px; border-radius: 12px; background: #071e3d; border: 1px solid rgba(120, 148, 175, 0.28); box-shadow: 0 20px 48px rgba(0, 0, 0, 0.4); }
  .row { display: flex; align-items: center; gap: 14px; }
  .spinner { width: 18px; height: 18px; flex-shrink: 0; border-radius: 50%; border: 2px solid rgba(155, 175, 196, 0.25); border-top-color: #38bdf8; animation: spin .75s linear infinite; }
  h1 { margin: 0; font-size: 1.15rem; font-weight: 600; letter-spacing: -0.015em; line-height: 1.3; }
  #status { margin: 12px 0 0; font-size: 0.925rem; line-height: 1.55; color: #9bafc4; }
  body.done .spinner, body.error .spinner { display: none; }
  body.done .card { border-color: rgba(164, 246, 197, 0.4); }
  body.done #status { color: #a4f6c5; }
  body.error .card { border-color: rgba(255, 194, 142, 0.45); }
  body.error #status { color: #ffc28e; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) { .spinner { animation: none; border-color: #38bdf8; } }
</style>
</head>
<body>
<main class="card" role="status" aria-live="polite">
  <div class="row"><span class="spinner" aria-hidden="true"></span><h1>Completing authentication...</h1></div>
  <p id="status">Processing...</p>
</main>
<script>` + implicitBridgeScript + `</script>
</body></html>`
