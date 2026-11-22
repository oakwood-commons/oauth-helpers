// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// defaultShutdownTimeout bounds a Shutdown call whose context has no deadline
// (or a further-out one), so a stalled final response cannot hold shutdown
// indefinitely.
const defaultShutdownTimeout = 10 * time.Second

// deferredWriteWindow bounds a browser-held deferred response when the
// server's context has no deadline of its own, so the handler never blocks
// unbounded.
const deferredWriteWindow = 30 * time.Minute

// finalPageCSP is the Content-Security-Policy applied to custom and deferred
// final HTML responses: inline styles and data: images are allowed, while all
// scripts, frames, forms, and external network requests are blocked.
const finalPageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

// CallbackPages holds the final HTML documents a callback server shows when
// custom pages or deferred completion are configured. Both documents are
// opaque: the server serves them byte-for-byte and never interpolates codes,
// tokens, or provider errors into them. An empty SuccessHTML or FailureHTML
// falls back to the corresponding generic safe helper page.
type CallbackPages struct {
	// SuccessHTML is the HTML document shown when authentication succeeds.
	SuccessHTML []byte
	// FailureHTML is the HTML document shown when authentication fails.
	FailureHTML []byte
}

// WithCallbackPages supplies complete HTML documents for the callback server's
// success and failure responses. Non-empty slices are cloned so later caller
// mutations cannot race with HTTP handlers.
func WithCallbackPages(pages CallbackPages) CallbackOption {
	var cloned CallbackPages
	if len(pages.SuccessHTML) > 0 {
		cloned.SuccessHTML = append([]byte(nil), pages.SuccessHTML...)
	}
	if len(pages.FailureHTML) > 0 {
		cloned.FailureHTML = append([]byte(nil), pages.FailureHTML...)
	}
	return func(c *callbackConfig) {
		c.pages = cloned
	}
}

// WithDeferredCompletion enables deferred completion: a valid callback still
// delivers its CallbackResult to ResultChan() immediately (so token exchange
// and credential storage can proceed), while the browser HTTP response is held
// until Complete(true) or Complete(false) is called (or the server's context
// finishes, settling as failure).
func WithDeferredCompletion() CallbackOption {
	return func(c *callbackConfig) {
		c.deferred = true
	}
}

// Complete settles a deferred-completion flow. The first call wins; late,
// duplicate, or post-cancellation calls are no-ops. It is safe to call from
// any goroutine, concurrently, on a zero-value CallbackServer, and after the
// server context finished or the server closed. In non-deferred mode it is an
// inert no-op.
func (cs *CallbackServer) Complete(success bool) {
	cs.completeOnce.Do(func() {
		cs.completeOK = success
		if cs.completeSig != nil {
			close(cs.completeSig)
		}
	})
}

// Shutdown gracefully drains in-flight final responses using a bounded cleanup
// context. If Complete was not yet called on a deferred server, Shutdown first
// settles the outcome as failure (503) so any parked browser request flushes
// immediately instead of stalling until timeout. Callers should pass a fresh
// context (for example derived from context.Background()) rather than an
// already-cancelled login context; an unbounded or longer deadline is capped at
// defaultShutdownTimeout. If draining does not finish in time, the server is
// force-closed and an error is returned. When no HTTP callback arrived (for
// example when paste-back won), callers can call Close() directly or
// Shutdown(ctx), which returns immediately when idle.
func (cs *CallbackServer) Shutdown(ctx context.Context) error {
	if cs.server == nil {
		return nil
	}
	cs.Complete(false)
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > defaultShutdownTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultShutdownTimeout)
		defer cancel()
	}
	if err := cs.server.Shutdown(ctx); err != nil {
		_ = cs.Close()
		return fmt.Errorf("graceful callback shutdown: %w", err)
	}
	return nil
}

func (cs *CallbackServer) hasCustomPages() bool {
	return len(cs.pages.SuccessHTML) > 0 || len(cs.pages.FailureHTML) > 0
}

func (cs *CallbackServer) enhancedMode() bool {
	return cs.deferred || cs.hasCustomPages()
}

// resolveDeferred blocks until Complete is called, the server context finishes,
// deferredWriteWindow elapses, or the client HTTP request disconnects.
func (cs *CallbackServer) resolveDeferred(reqCtx context.Context) (settled, clientGone bool) {
	timer := time.NewTimer(deferredWriteWindow)
	defer timer.Stop()

	select {
	case <-cs.completeSig:
		return cs.completeOK, false
	case <-cs.ctx.Done():
		return false, false
	case <-timer.C:
		return false, false
	case <-reqCtx.Done():
		return false, true
	}
}

// finalDocument returns the body and HTTP status code for a settled callback.
// Failure responses always carry a non-2xx status code (503) even when a custom
// FailureHTML document is provided, so status-aware callers and XHR bridges
// never mistake a failed login for HTTP 200 OK.
func (cs *CallbackServer) finalDocument(success bool) (body []byte, status int) {
	if success {
		if len(cs.pages.SuccessHTML) > 0 {
			return cs.pages.SuccessHTML, http.StatusOK
		}
		return []byte(defaultSuccessHTML), http.StatusOK
	}
	if len(cs.pages.FailureHTML) > 0 {
		return cs.pages.FailureHTML, http.StatusServiceUnavailable
	}
	return []byte(defaultFailureHTML), http.StatusServiceUnavailable
}

func setSafePageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", finalPageCSP)
}

// writeErrorPage serves a callback error response with strict security headers.
// Legacy callers (neither WithDeferredCompletion nor WithCallbackPages set)
// receive authErrorHTML with the escaped error summary for backward
// compatibility. Enhanced callers receive the configured FailureHTML (or
// defaultFailureHTML) with zero provider error text in the browser DOM.
func (cs *CallbackServer) writeErrorPage(w http.ResponseWriter, status int, escapedErrMsg string) {
	setSafePageHeaders(w)
	if !cs.enhancedMode() {
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, authErrorHTML(escapedErrMsg))
		return
	}
	body := []byte(defaultFailureHTML)
	if len(cs.pages.FailureHTML) > 0 {
		body = cs.pages.FailureHTML
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// completeSuccess coordinates ResultChan delivery and final HTTP page writing.
// In deferred mode, ResultChan is notified first so token exchange can proceed
// while writeFinalPage holds the browser response until Complete is called.
// In non-deferred mode, the final HTML response is written and flushed before
// notifying ResultChan so an immediate caller defer cs.Close() cannot reset the
// socket mid-write.
func (cs *CallbackServer) completeSuccess(w http.ResponseWriter, r *http.Request, result CallbackResult) {
	if cs.deferred {
		cs.sendResult(result)
		cs.writeFinalPage(w, r)
		return
	}
	cs.writeFinalPage(w, r)
	cs.sendResult(result)
}

// writeFinalPage writes the callback response after a valid code/token arrives.
// Non-deferred callers receive SuccessHTML (or defaultSuccessHTML) immediately
// with strict security headers. WithDeferredCompletion holds the response until
// Complete or context cancellation settles the outcome.
func (cs *CallbackServer) writeFinalPage(w http.ResponseWriter, r *http.Request) {
	settled := true
	rc := http.NewResponseController(w)
	if cs.deferred {
		if rc != nil {
			// Clear both http.Server ReadTimeout and WriteTimeout (30s) while
			// parked waiting for MFA, token exchange, and credential storage.
			// Go's net/http runs a background socket read during GET handlers
			// to detect disconnects; leaving ReadTimeout armed would cancel
			// r.Context() at 30s and emit an empty 200 OK. resolveDeferred
			// bounds the wait via cs.ctx and deferredWriteWindow.
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
		}
		var clientGone bool
		settled, clientGone = cs.resolveDeferred(r.Context())
		if clientGone {
			return
		}
		if rc != nil {
			// Apply a fresh socket write deadline so a 503 failure page still
			// flushes cleanly even when cs.ctx timed out.
			_ = rc.SetWriteDeadline(time.Now().Add(defaultShutdownTimeout))
		}
	}

	body, status := cs.finalDocument(settled)
	setSafePageHeaders(w)
	w.WriteHeader(status)
	_, _ = w.Write(body)
	if rc != nil {
		_ = rc.Flush()
	}
}

func implicitBridgeCSP() string {
	sum := sha256.Sum256([]byte(implicitBridgeScript))
	hash := base64.StdEncoding.EncodeToString(sum[:])
	return fmt.Sprintf(
		"default-src 'none'; script-src 'sha256-%s'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; frame-src 'self' about: data: blob:; child-src 'self' about: data: blob:; base-uri 'none'; form-action 'none'",
		hash,
	)
}

// fallbackCardBaseCSS defines the shared brand-neutral dark card layout used by
// all built-in fallback HTML responses (matching implicitCallbackHTML so
// callbacks render offline without a white flash).
const fallbackCardBaseCSS = `
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; min-height: 100svh; display: grid; place-items: center; padding: 24px; background: #05152a; color: #eff7ff; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .card { width: min(28rem, 100%); padding: 32px 36px; border-radius: 12px; background: #071e3d; border: 1px solid rgba(120, 148, 175, 0.28); box-shadow: 0 20px 48px rgba(0, 0, 0, 0.4); }
  .row { display: flex; align-items: center; gap: 14px; }
  .badge { width: 28px; height: 28px; flex-shrink: 0; display: grid; place-items: center; border-radius: 50%; }
  .icon { width: 16px; height: 16px; }
  h1 { margin: 0; font-size: 1.15rem; font-weight: 600; letter-spacing: -0.015em; line-height: 1.3; }
  p { margin: 12px 0 0; font-size: 0.925rem; line-height: 1.55; color: #9bafc4; }`

// defaultSuccessHTML is the generic brand-neutral dark-card success page served
// when authentication succeeds and no custom SuccessHTML was supplied. It is
// self-contained offline HTML/CSS with zero scripts or external URLs, compliant
// with finalPageCSP.
const defaultSuccessHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication Successful</title>
<style>` + fallbackCardBaseCSS + `
  .card { border-color: rgba(164, 246, 197, 0.4); }
  .badge { background: rgba(164, 246, 197, 0.14); color: #a4f6c5; }
</style>
</head>
<body>
<main class="card" role="status" aria-live="polite">
  <div class="row"><span class="badge" aria-hidden="true"><svg class="icon" viewBox="0 0 16 16" fill="none" focusable="false"><path d="M3.5 8.5L6.5 11.5L12.5 4.5" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg></span><h1>Authentication Successful</h1></div>
  <p>You can close this window and return to the terminal.</p>
</main>
</body></html>`

// defaultFailureHTML is the generic brand-neutral dark-card failure page served
// when a deferred or custom-page flow fails and no custom FailureHTML was
// supplied. It carries no provider, token, or error details and complies with
// finalPageCSP.
const defaultFailureHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authentication Failed</title>
<style>` + fallbackCardBaseCSS + `
  .card { border-color: rgba(255, 194, 142, 0.45); }
  .badge { background: rgba(255, 194, 142, 0.14); color: #ffc28e; }
  .footer { margin-top: 16px; font-size: 0.85rem; color: #8da4bd; }
</style>
</head>
<body>
<main class="card" role="alert">
  <div class="row"><span class="badge" aria-hidden="true"><svg class="icon" viewBox="0 0 16 16" fill="none" focusable="false"><path d="M8 5V8.5M8 11H8.01" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/></svg></span><h1>Authentication Failed</h1></div>
  <p>We couldn't finish connecting you. Check the terminal for details and run the login command again.</p>
  <p class="footer">You can close this window.</p>
</main>
</body></html>`
