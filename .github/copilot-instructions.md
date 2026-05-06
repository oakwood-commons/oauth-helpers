# oauth-helpers - AI Agent Instructions

## Overview
Go library providing shared OAuth 2.0 utilities: PKCE code generation, browser launching, and local callback servers for authorization code and implicit grant flows.

## Key Patterns

- **PKCE**: Use `GenerateCodeVerifier()` and `GenerateCodeChallenge(verifier)` for RFC 7636 compliance
- **Callback servers**: `StartCallbackServer()` for authorization code flow, `StartImplicitCallbackServer()` for implicit grant flow
- **Browser**: `OpenBrowser()` launches URLs in the default browser (http/https only)
- **Stdlib only**: This module has zero non-test dependencies to minimize transitive overhead

## Conventions

- **Commits**: Use [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/#specification)
- **Signing**: All commits must include DCO sign-off (`-s`)
- **Errors**: Return errors with `fmt.Errorf("context: %w", err)`, don't panic
- **Testing**: Use `testify/assert` and `testify/require` for assertions, table-driven tests where appropriate

## Build & Test Commands

~~~bash
# Test
go test ./...              # Run all tests
go test -race ./...        # Run with race detector

# Linting
task lint                  # Run golangci-lint (uses pinned version)
task lint:fix              # Run linter and auto-fix issues

# Coverage
task coverage:html         # Generate and open HTML coverage report
~~~

The project uses `task` (go-task/task) for builds and linting. **Always use `task lint` instead of running `golangci-lint` directly** to ensure the correct pinned version is used.

## Critical Rules

- **Stdlib only**: This is a dependency-free library (test deps excluded). Never add runtime dependencies
- **Security**: All callback servers bind only to loopback addresses. OpenBrowser only accepts http/https URLs
- **After any change**: Run `go test -race ./...` to ensure everything passes
- **Test coverage**: Every new or changed file must have tests. Target 70%+ patch coverage
- **Git safety**: Never run `git commit`, `git push`, or `git commit --amend` unless the user explicitly asks

## Security Scanning

~~~bash
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
~~~

## Additional Conventions

Go coding conventions (error handling, testing patterns) are in `.github/instructions/*.instructions.md` files -- they load automatically when editing relevant files.
