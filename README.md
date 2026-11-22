# oauth-helpers

Shared OAuth 2.0 utilities for [scafctl](https://github.com/oakwood-commons/scafctl)
auth handler plugins.

## Features

- **PKCE** -- RFC 7636 code verifier/challenge generation (S256)
- **Browser launch** -- Cross-platform `open`/`xdg-open`/`rundll32` wrapper
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

// Browser
oauth.OpenBrowser(ctx, authURL)

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
- **Security first** -- loopback-only binding, state validation, CORS checks,
  strict CSP headers, HTML escaping, and path traversal prevention
- **Minimal API** -- just what auth handler plugins need, nothing more

## License

Apache-2.0
