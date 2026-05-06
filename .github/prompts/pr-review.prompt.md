---
description: "Fetch and triage PR review comments and CI failures for the current branch."
agent: "pr-reviewer"
argument-hint: "Optional: PR number or leave blank to use current branch"
---
Triage unresolved PR review comments and CI failures.

Follow these phases **in order**:

1. **Fetch**: Fetch all review threads via GraphQL; skip comments that are already resolved
2. **Pipeline check**: Run `gh pr checks <PR_NUMBER>` to see CI status
3. **Coverage check**: Check the PR comments for a Codecov report
4. **Early exit**: If there are zero unresolved threads, all checks passing, and patch coverage >= 70%, report that and stop
5. **Triage**: For each unresolved comment, assess whether it's a legit problem. Present the triage summary and **stop here** -- the user will click "Apply fixes" to hand off to the fixer agent

Include thread IDs in the triage output so the fixer agent can respond to and resolve them.

The "Apply fixes" handoff MUST instruct the fixer to reply to each thread and resolve it via `resolveReviewThread` after verification passes.
