---
description: "Go module rules for oauth-helpers. Run go mod tidy after dependency changes. Never edit go.sum manually."
applyTo: "**/go.mod"
---

# Go Modules

- Run `go mod tidy -v` after adding or removing dependencies
- Never edit `go.sum` manually -- it is auto-generated
- Pin dependencies to specific versions, not branches
- Use `go mod verify` to check module integrity
- **Never add runtime dependencies** -- this library must remain stdlib-only
