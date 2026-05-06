---
description: "OAuth 2.0 flow patterns for oauth-helpers: PKCE, authorization code, implicit grant, callback servers, and browser launching."
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

## Authorization Code Flow

Start a local callback server to receive the authorization code:

~~~go
cs, err := oauth.StartCallbackServer(ctx, 0, expectedState)
if err != nil {
    return fmt.Errorf("starting callback server: %w", err)
}
defer cs.Close()

// cs.RedirectURI contains the callback URL (e.g., http://localhost:12345)
// Build the authorization URL and open it
oauth.OpenBrowser(ctx, authURL)

// Wait for the callback
result := <-cs.ResultChan()
if result.Err != nil {
    return fmt.Errorf("OAuth callback error: %w", result.Err)
}
// Use result.Code
~~~

## Implicit Grant Flow

Start an implicit callback server for token-in-fragment flows:

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

- Callback servers bind **only** to loopback addresses (localhost, 127.0.0.1, ::1)
- OpenBrowser only accepts **http://** and **https://** URLs
- State parameter comparison uses **constant-time** comparison (`crypto/subtle`)
- All HTML output is **escaped** to prevent XSS
