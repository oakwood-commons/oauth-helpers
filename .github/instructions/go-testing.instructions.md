---
description: "Go testing conventions for oauth-helpers: table-driven tests, testify/assert, race detection, and coverage."
applyTo: "**/*_test.go"
---

# Go Testing Conventions

## Framework

- Use standard `go test` with **table-driven tests**
- Use `testify/assert` for assertions and `testify/require` for fatal checks
- Place test helpers in the same file as the tests they support

## Race Detection

Always run with the `-race` flag:

~~~bash
go test -race ./...
~~~

## Coverage

~~~bash
go test -cover ./...
~~~

### Coverage Targets

| Code Type | Target |
|-----------|--------|
| Core logic (PKCE, callback, browser) | 80%+ |
| New files | 90%+ |
| Changed files | 70%+ |

### Patch Coverage

Every PR must have **70%+ patch coverage**. Never submit a new file with 0% coverage.

## Test Patterns

Use table-driven tests for functions with multiple input/output combinations:

~~~go
tests := []struct {
    name     string
    input    string
    expected string
    wantErr  bool
}{
    {"valid input", "test", "result", false},
    {"empty input", "", "", true},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        result, err := MyFunction(tt.input)
        if tt.wantErr {
            assert.Error(t, err)
            return
        }
        require.NoError(t, err)
        assert.Equal(t, tt.expected, result)
    })
}
~~~

## Integration Tests

Integration tests live in `tests/integration/` and test the full OAuth flow lifecycle. They use real HTTP servers on loopback addresses.
