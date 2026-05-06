---
description: "Create an implementation plan for a feature. Produces a structured blueprint."
agent: "planner"
argument-hint: "Describe the feature to plan"
---
Create a structured implementation blueprint for the described feature:

1. **Summary** -- What and why
2. **Architecture decisions** -- Files affected, new types, interface changes
3. **Task breakdown** -- Ordered steps with files, complexity, dependencies
4. **Error handling** -- Sentinel errors, wrapping strategy
5. **Testing strategy** -- Unit tests, integration tests
6. **Risks & edge cases** -- What could go wrong

Follow oauth-helpers conventions: stdlib only, loopback-only servers, error wrapping.
