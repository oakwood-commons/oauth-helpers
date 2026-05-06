# oauth-helpers

Shared OAuth 2.0 utilities for [scafctl](https://github.com/oakwood-commons/scafctl)
auth handler plugins.

## Features

- **PKCE** -- RFC 7636 code verifier/challenge generation (S256)
- **Browser launch** -- Cross-platform `open`/`xdg-open`/`rundll32` wrapper
- **Callback server** -- Local HTTP server for OAuth authorization code and
  implicit grant flows with CSRF state validation, IPv6 support, configurable
  host/path, and CORS origin checks

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
)
defer cs.Close()
// Use cs.RedirectURI in the authorization request
result := <-cs.ResultChan()
~~~

## Design Principles

- **Zero dependencies** beyond the Go standard library (test-only: testify)
- **Security first** -- loopback-only binding, state validation, CORS checks,
  path traversal prevention
- **Minimal API** -- just what auth handler plugins need, nothing more

## License

Apache-2.0
