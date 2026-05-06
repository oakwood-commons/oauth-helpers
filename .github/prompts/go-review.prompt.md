---
description: "Run Go code review on recent changes. Checks for idiomatic Go, security, error handling, and project conventions."
agent: "go-reviewer"
---
Review the current Go code changes thoroughly. You MUST complete ALL phases below.

## Phase 1: Automated checks

1. Run `go vet ./...` and `task lint`
2. Run `git diff --stat HEAD -- '*.go'` and `git status --short`
3. Read the full diff for all changed files
4. Read the full contents of all new (untracked) files
5. Run `go test -coverprofile` on every changed package
6. Run `go test -race` on changed packages

## Phase 2: Systematic review

### Security
- [ ] Command injection (user input passed to exec without sanitization)
- [ ] Hardcoded secrets, tokens, or credentials
- [ ] URL scheme validation (only http/https allowed for browser)
- [ ] Network binding (only loopback addresses for callback servers)
- [ ] Timing attacks (state comparisons must use constant-time)

### Error handling
- [ ] Ignored errors (unchecked error returns)
- [ ] Missing error wrapping (`fmt.Errorf("context: %w", err)`)
- [ ] Panics used for recoverable errors

### Concurrency
- [ ] Goroutine leaks
- [ ] Race conditions (shared state without synchronization)

### Code quality
- [ ] Functions over 60 lines
- [ ] Non-idiomatic Go patterns
- [ ] Runtime dependency additions (not allowed)

## Phase 3: Coverage analysis

Run coverage and flag any changed function below 90%.

## Phase 4: Self-review

Re-read the full diff and ask "what did I miss?"
