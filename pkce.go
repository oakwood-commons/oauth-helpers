// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateCodeVerifier generates a PKCE code verifier (43-128 character random string).
// See RFC 7636 section 4.1.
func GenerateCodeVerifier() (string, error) {
	buf := make([]byte, 32) // 32 bytes -> 43 base64url chars
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateCodeChallenge creates a PKCE S256 code challenge from a code verifier.
// See RFC 7636 section 4.2.
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
