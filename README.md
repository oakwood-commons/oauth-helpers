# oauth-helpers

Shared OAuth 2.0 utilities for [scafctl](https://github.com/oakwood-commons/scafctl)
auth handler plugins.

## Features

- **PKCE** -- RFC 7636 code verifier/challenge generation (S256)
- **Device authorization polling** -- Generic RFC 8628 token poller
  (`PollDeviceToken`) with post-response wait spacing, configurable safety
  margin, `slow_down` interval backoff, sentinel error wrapping
  (`ErrDeviceCodeExpired`, `ErrDeviceAccessDenied`), and optional transient
  error retry
- **Browser launch** -- Configurable browser selection (`OpenBrowserWithPreference`,
  `$BROWSER`, `WithWarningHandler`) with cross-platform discovery, graceful
  system-default fallback (`open`/`xdg-open`/`rundll32`), URL hardening, and
  detached process lifecycle
- **Callback server** -- Local HTTP server for OAuth authorization code and
  implicit grant flows with CSRF state validation, IPv6 support, configurable
  host/path, and CORS origin checks
- **Styled offline callback pages** -- Built-in dark-card HTML responses
  (`color-scheme: dark`, inline CSS, zero external requests) for success,
  implicit token bridging, generic failure, and troubleshooting error states
- **Custom pages & deferred completion** -- `WithCallbackPages` and
  `WithDeferredCompletion` hold the browser response until token exchange
  settles via `Complete(bool)` and drain cleanly via `Shutdown(ctx)`

## Install

~~~bash
go get github.com/oakwood-commons/oauth-helpers
~~~

## Usage

~~~go
import "github.com/oakwood-commons/oauth-helpers"

// PKCE
verifier, _ := oauth.GenerateCodeVerifier()
challenge := oauth.GenerateCodeChallenge(verifier)

// Device authorization polling (RFC 8628)
type TokenResponse struct {
    AccessToken string `json:"access_token"`
}
tok, err := oauth.PollDeviceToken(ctx, oauth.DevicePollConfig{
    Interval:             5 * time.Second,
    RetryTransientErrors: true,
}, func(ctx context.Context) (*TokenResponse, *oauth.DevicePollError, error) {
    // Perform a single HTTP POST to the provider's token endpoint and map
    // RFC 8628 error responses to *oauth.DevicePollError.
    return exchangeOnce(ctx)
})
if errors.Is(err, oauth.ErrDeviceCodeExpired) || errors.Is(err, oauth.ErrDeviceAccessDenied) {
    // Handle expired code or user denial
}
_ = tok

// Browser (system default or $BROWSER)
_ = oauth.OpenBrowser(ctx, authURL)

// Browser with explicit preference and graceful fallback warning
_ = oauth.OpenBrowserWithPreference(ctx, authURL, "msedge",
    oauth.WithWarningHandler(func(msg string) {
        log.Printf("warning: %s", msg)
    }),
)

// Callback server (authorization code flow)
cs, _ := oauth.StartCallbackServer(ctx, 0, state,
    oauth.WithCallbackHost("127.0.0.1"),
    oauth.WithCallbackPath("/auth/callback"),
    oauth.WithCallbackPages(oauth.CallbackPages{
        SuccessHTML: successHTML,
        FailureHTML: failureHTML,
    }),
    oauth.WithDeferredCompletion(),
)
defer cs.Close()
// Use cs.RedirectURI in the authorization request
result := <-cs.ResultChan()
// Exchange code / store credentials before settling the browser page:
cs.Complete(true)
_ = cs.Shutdown(context.Background())
~~~

### Device Authorization Polling

- **Post-response spacing (`PollDeviceToken`)**: Waits `Interval + SafetyMargin`
  before the first poll attempt and after each completed `authorization_pending`,
  `slow_down`, or retried transient-error response rather than using a fixed-rate
  ticker, preventing HTTP round-trip latency from shortening the server's
  rate-limit window. When `RetryTransientErrors` is enabled, timeout errors
  double the base polling interval (clamped on overflow) before retrying per
  RFC 8628 Section 3.5 while non-timeout transient errors retain the current
  interval.
- **Defaults & safety margin (`DevicePollConfig`)**: Enforces a configurable
  minimum interval (`MinInterval`, default `DefaultDevicePollInterval` = `5s`)
  and post-response safety margin (`SafetyMargin`, default
  `DefaultDevicePollSafetyMargin` = `1s`; set `DisableSafetyMargin: true` for an
  exact `0s` margin).
- **`slow_down` & error semantics (`DevicePollError`)**: Increases the base
  interval to `max(serverInterval, interval + SlowDownIncrement)` (with
  `SlowDownIncrement` clamped to at least `DefaultDeviceSlowDownIncrement` = `5s`
  per RFC 8628 Section 3.5), wraps `ErrDeviceCodeExpired` on `expired_token` and
  `ErrDeviceAccessDenied` on `access_denied` or `authorization_declined`, returns
  `DevicePollError.Cause` directly on other error codes when set, sanitizes and
  length-caps `Code`, `Description`, and formatted `Cause` text while preserving
  the original `Cause` via `Unwrap`, and accepts an optional `Sleep` hook for
  deterministic unit tests.

### Browser Selection and Fallback

- **Priority chain (`OpenBrowserWithPreference`)**:
  1. Explicit `preference` (`"msedge"`/`"edge"`, `"chrome"`/`"google-chrome"`,
     `"chromium"`, `"firefox"`, `"brave"`, `"safari"`, `"default"`/`"system"`,
     or an executable name/path). `"default"` and `"system"` bypass `$BROWSER`
     and open the OS default browser directly.
  2. `$BROWSER` environment variable when `preference` is empty (`""`),
     supporting colon-separated fallback lists on Unix (`firefox:chromium`) and
     semicolon-separated entries or executable paths on Windows without ever
     invoking a shell (`sh -c` or `cmd.exe /c`).
  3. OS default browser (`open` on macOS, `xdg-open` on Linux,
     `rundll32 url.dll,FileProtocolHandler` on Windows).
- **Graceful fallback (`WithWarningHandler`)**: If the configured `preference`
  or `$BROWSER` cannot be found or fails to start, `WithWarningHandler` receives
  a human-readable warning and execution falls back to the OS default browser,
  returning an error only when the fallback also fails (or if `ctx.Err()` / URL
  validation fails up front).
- **Security & detached lifecycle**: Validates `http://` / `https://` scheme
  (case-insensitive), non-empty host, and absence of control characters or
  whitespace before launch, and detaches spawned browser processes from `ctx` so
  completing `Login(ctx)` does not terminate the user's browser session.

### Callback Pages and Deferred Completion

- **Built-in dark fallback cards**: Callers that omit `WithCallbackPages`
  automatically serve self-contained brand-neutral dark cards (`#05152a` canvas,
  `#071e3d` card, `system-ui` typography, zero JavaScript on final pages, zero
  external URLs) with strict security headers across authorization-code success,
  implicit fragment bridging, deferred failure, and legacy OAuth troubleshooting
  responses.
- **Custom HTML (`WithCallbackPages`)**: Supplies opaque `SuccessHTML` and
  `FailureHTML` byte slices served with `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and a strict
  `Content-Security-Policy` (`default-src 'none'; style-src 'unsafe-inline';
  img-src data:; base-uri 'none'; form-action 'none'`). Empty fields fall back
  to the built-in dark cards, failure responses return non-2xx HTTP status
  codes, and provider error strings are never interpolated into custom or
  enhanced failure pages.
- **Deferred completion (`WithDeferredCompletion`)**: Delivers `CallbackResult`
  on `ResultChan()` as soon as the redirect arrives while holding the browser
  HTTP response open until `cs.Complete(true)` or `cs.Complete(false)` settles
  token exchange (or the server context cancels/times out as a `503` failure).
  Call `cs.Shutdown(ctx)` with a fresh cleanup context to drain the final
  response cleanly.

## Design Principles

- **Zero dependencies** beyond the Go standard library (test-only: testify)
- **Security first** -- loopback-only binding, state-first constant-time CSRF
  validation (forged requests return 403/405 without aborting active logins),
  CORS checks, strict CSP headers, HTML escaping, terminal control-character
  sanitization, and path traversal prevention
- **Minimal API** -- just what auth handler plugins need, nothing more

## License

Apache-2.0
