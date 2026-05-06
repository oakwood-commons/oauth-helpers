# Contributing to oauth-helpers

Thank you for your interest in contributing to oauth-helpers! This document provides guidelines and best practices for contributing.

## Code of Conduct

See our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Developer Certificate of Origin (DCO) & Commit Signing

All commits must be **DCO signed-off** (`-s`) -- this certifies you have the right to submit the contribution under the project's license per the [Developer Certificate of Origin](https://developercertificate.org/).

Sign commits with `-s`:

```bash
git commit -s -m "feat: add new feature"
```

If you forget, amend the last commit:

```bash
git commit --amend -s --no-edit
```

### Prerequisites

- Go 1.23.0+
- [Task](https://taskfile.dev/) (optional, for running project tasks)
- golangci-lint
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/oakwood-commons/oauth-helpers.git
cd oauth-helpers

# Install dependencies
go mod download

# Run tests
go test ./...

# Run linter
golangci-lint run
```

Or using Task:

```bash
task test
task lint
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feat/my-feature
# or
git checkout -b fix/my-bugfix
```

### 2. Make Changes

Follow the coding standards below.

### 3. Test Your Changes

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Or using Task:

```bash
task test
task test-cover
task coverage:html
```

### 4. Lint Your Code

```bash
golangci-lint run --fix
```

Or:

```bash
task lint:fix
```

### 5. Commit with Conventional Commits

```bash
# Format: <type>(<scope>): <description>

git commit -s -m "feat(callback): add timeout configuration"
git commit -s -m "fix(pkce): handle edge case in verifier generation"
git commit -s -m "docs: update README with usage examples"
git commit -s -m "test(browser): add URL validation tests"
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `test`: Tests
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `chore`: Maintenance tasks

### 6. Push and Create PR

```bash
git push origin feat/my-feature
```

Then create a Pull Request on GitHub.

## Coding Standards

### Error Handling

```go
// Good: Wrap errors with context
if err != nil {
    return fmt.Errorf("failed to start callback server: %w", err)
}

// Good: Use sentinel errors
var ErrNotFound = errors.New("resource not found")
```

### Testing

Use testify for assertions:

```go
func TestMyFunction(t *testing.T) {
    // Arrange
    input := "test"

    // Act
    result, err := MyFunction(input)

    // Assert
    require.NoError(t, err)
    assert.Equal(t, "expected", result)
}
```

Use table-driven tests where appropriate:

```go
func TestMyFunction_Cases(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {"empty input", "", "", true},
        {"valid input", "test", "result", false},
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
}
```

## Breaking Changes

This project is pre-1.0, so breaking changes are allowed. When making them:

1. Document in commit message: `feat!: remove deprecated API`
2. Update migration notes if needed
3. Ensure tests are updated

## Release Process

Releases are automated via GitHub Actions on tag push:

```bash
git tag v0.2.0
git push origin v0.2.0
```

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues and discussions

## Recognition

Contributors are recognized in release notes and the GitHub contributors page.

Thank you for contributing!
