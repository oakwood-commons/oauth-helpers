---
description: "OAuth 2.0 flow patterns for oauth-helpers: PKCE, RFC 8628 device authorization polling, authorization code, implicit grant, callback servers, custom pages, deferred completion, and browser launching."
---

# OAuth Flow Patterns

## PKCE (RFC 7636)

Generate a code verifier and challenge for PKCE-enabled authorization code flows:

~~~go
verifier, err := oauth.GenerateCodeVerifier()
if err != nil {
    return fmt.Errorf("generating PKCE verifier: %w", err)
}
challenge := oauth.GenerateCodeChallenge(verifier)
~~~

- Verifier: 43-character base64url-encoded random string (32 bytes)
- Challenge: S256 (SHA-256 hash of verifier, base64url-encoded)

## Device Authorization Flow (RFC 8628)

Poll a device-authorization token endpoint with post-response spacing and
`slow_down` backoff:

~~~go
tok, err := oauth.PollDeviceToken(ctx, oauth.DevicePollConfig{
    Interval:             time.Duration(deviceCode.Interval) * time.Second,
    RetryTransientErrors: true,
    OnSlowDown: func(newInterval time.Duration) {
        logger.Info("slow_down received, increasing poll interval", "newInterval", newInterval)
    },
}, func(ctx context.Context) (*TokenResponse, *oauth.DevicePollError, error) {
    resp, err := postDeviceToken(ctx)
    if err != nil {
        return nil, nil, err // retried after Interval + SafetyMargin when RetryTransientErrors is true
    }
    if resp.Error != "" {
        return nil, &oauth.DevicePollError{
            Code:        resp.Error,
            Description: resp.ErrorDescription,
            Interval:    resp.Interval,
        }, nil
    }
    return resp, nil, nil
})
if errors.Is(err, oauth.ErrDeviceCodeExpired) {
    return fmt.Errorf("device code expired: %w", err)
}
if errors.Is(err, oauth.ErrDeviceAccessDenied) {
    return fmt.Errorf("user denied authorization: %w", err)
}
~~~

- Waits `Interval + SafetyMargin` (default `5s` + `1s`) before the first poll
  and after each completed `authorization_pending`, `slow_down`, or retried
  transient-error response rather than using a fixed-rate ticker; when
  `RetryTransientErrors` is enabled, timeout errors double the base interval
  (clamped on overflow) before retrying per RFC 8628 Section 3.5 while
  non-timeout transient errors leave the interval unchanged
- Increases the base interval to `max(serverInterval, interval + SlowDownIncrement)`
  (with `SlowDownIncrement` clamped to at least `5s`) on `slow_down`
- Wraps `ErrDeviceCodeExpired` on `expired_token` and `ErrDeviceAccessDenied`
  on `access_denied` or `authorization_declined`, while keeping `*DevicePollError`
  and `Cause` inspectable via `errors.As` / `errors.Is`

## Authorization Code Flow

Start a local callback server to receive the authorization code:

~~~go
cs, err := oauth.StartCallbackServer(ctx, 0, expectedState)
if err != nil {
    return fmt.Errorf("starting callback server: %w", err)
}
defer cs.Close()

// cs.RedirectURI contains the callback URL (e.g., http://localhost:12345)
// Build the authorization URL and open it (optionally targeting a preferred browser)
_ = oauth.OpenBrowserWithPreference(ctx, authURL, browserPref,
    oauth.WithWarningHandler(func(msg string) {
        logger.Warn(msg)
    }),
)

// Wait for the callback
result := <-cs.ResultChan()
if result.Err != nil {
    return fmt.Errorf("OAuth callback error: %w", result.Err)
}
// Use result.Code
~~~

## Custom Callback Pages and Deferred Completion

Hold the browser HTTP response open while exchanging the code/token and storing
credentials so the browser reflects the true end-to-end login outcome:

~~~go
cs, err := oauth.StartCallbackServer(ctx, 0, expectedState,
    oauth.WithCallbackPages(oauth.CallbackPages{
        SuccessHTML: successHTML,
        FailureHTML: failureHTML,
    }),
    oauth.WithDeferredCompletion(),
)
if err != nil {
    return fmt.Errorf("starting callback server: %w", err)
}
defer func() {
    _ = cs.Shutdown(context.Background())
}()

oauth.OpenBrowser(ctx, authURL)

result := <-cs.ResultChan()
if result.Err != nil {
    cs.Complete(false)
    return fmt.Errorf("OAuth callback error: %w", result.Err)
}

if err := exchangeAndStore(ctx, result.Code); err != nil {
    cs.Complete(false)
    return fmt.Errorf("exchanging authorization code: %w", err)
}
cs.Complete(true)
~~~

- Omitting `WithCallbackPages` (or leaving either `SuccessHTML` / `FailureHTML`
  empty) falls back to the built-in self-contained dark-card HTML pages.
- `cs.Shutdown(ctx)` settles any unsettled deferred callback as `503` failure
  and drains the final HTTP response within a bounded timeout.

## Implicit Grant Flow

Start an implicit callback server for token-in-fragment flows (also supports
`WithCallbackHost`, `WithCallbackPath`, `WithCallbackPages`, and
`WithDeferredCompletion`):

~~~go
cs, err := oauth.StartImplicitCallbackServer(ctx, 0, expectedState)
if err != nil {
    return fmt.Errorf("starting implicit callback server: %w", err)
}
defer cs.Close()

oauth.OpenBrowser(ctx, authURL)

result := <-cs.ResultChan()
if result.Err != nil {
    return fmt.Errorf("OAuth callback error: %w", result.Err)
}
// Use result.AccessToken, result.TokenType, result.ExpiresIn
~~~

## Security Constraints

- Callback servers bind **only** to loopback addresses (`localhost`, `127.0.0.1`, `::1`)
- `OpenBrowser` and `OpenBrowserWithPreference` only accept `http://` and `https://`
  URLs with a non-empty host and no control characters or whitespace, never invoke
  `sh -c` or `cmd.exe /c`, and launch browser binaries detached from `ctx` so
  canceling the login context does not kill the user's browser session
- State parameter comparison runs **first** (before `error` or `code` handling) using
  **constant-time** comparison (`crypto/subtle`); missing or mismatched `state`
  and disallowed HTTP methods return `403`/`405` without delivering a `CallbackResult`
  so stray local requests cannot abort an active login
- Untrusted `error` and `error_description` parameters strip C0, DEL, C1, and
  bidirectional control characters and cap length before building `CallbackResult.Err`
- Final and error HTML responses carry strict security headers (`Content-Security-Policy`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`)
- Implicit bridge pages enforce a SHA-256 script-hash CSP and render final HTML
  inside a script-disabled `<iframe sandbox="">` (`srcdoc`)
- Custom `CallbackPages` slices are cloned defensively and served byte-for-byte;
  provider `error_description` strings are never interpolated into enhanced/custom
  failure pages, and legacy troubleshooting pages single-escape all untrusted input
- `PollDeviceToken` schedules waits after each poll response completes (never on a
  fixed-rate ticker), clamps untrusted `slow_down` intervals against duration
  overflow, and sanitizes C0, DEL, C1, and bidirectional control characters with
  rune-length caps in `DevicePollError` and sentinel-wrapped error strings
