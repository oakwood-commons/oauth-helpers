---
description: "Go coding conventions for oauth-helpers: error handling, design principles, and formatting. Use when writing or editing Go code."
applyTo: "**/*.go"
---

# Go Conventions

## Error Handling

Always wrap errors with context:

~~~go
if err != nil {
    return fmt.Errorf("failed to start listener: %w", err)
}
~~~

## Design Principles

- Accept interfaces, return structs
- Keep interfaces small (1-3 methods)
- Use constructor functions for dependency injection
- Always pass `context.Context` as first parameter
- No package-level mutable state (except `allowedCallbackHosts` which is read-only)

## Secret Management

Read secrets from environment variables -- never hardcode.

## Formatting

- **gofmt** and **goimports** are mandatory
- Never use magic strings or numbers; always define constants

## Stdlib Only

This library has zero runtime dependencies. Never add non-test dependencies.
Test dependencies (`testify`) are acceptable.
