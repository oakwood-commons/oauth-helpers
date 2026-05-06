// Copyright 2025-2026 Oakwood Commons
// SPDX-License-Identifier: Apache-2.0

// Package oauth provides shared OAuth 2.0 utilities used by multiple auth
// handler plugins and the scafctl host, including PKCE code generation,
// browser launching, and local callback servers.
//
// This module is intentionally dependency-free (stdlib only) to minimize
// transitive dependency overhead for plugin binaries.
package oauth
