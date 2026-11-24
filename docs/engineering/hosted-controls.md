# Hosted checks and workflow trust

The `main` ruleset in each repository requires one status check, and a pull request must contain the current `main` before it can merge. The check result therefore describes the commit that lands. No actor can bypass the ruleset, the owner included.

| Repository | Workflow | Required context | Reported by |
| --- | --- | --- | --- |
| Core | `Public source` | `Core source and contracts` | GitHub Actions, integration 15368 |
| Complete Collection | `Public catalog` | `Collection catalog and hygiene` | GitHub Actions, integration 15368 |

A missing check, a failing check, and a status of the same name from any other source all leave the pull request blocked. [Core #173](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/173) records how each case was qualified.

## What the verifier asserts

`scripts/verify-workflows.py` reads [the workflow policy](../../.github/workflow-policy.json) and every file under `.github/workflows`. It runs in `scripts/check static`, so the required check fails when a workflow leaves the reviewed boundary.

- Events are exactly `pull_request` with no filter and `push` to `main`. A path filter would let a pull request skip the required check, and `pull_request_target` or `workflow_run` would run with a privileged token.
- The workflow token is read-only and no job changes it.
- No workflow reads a secret or the workflow token.
- Every job runs on a named GitHub-hosted runner with a time limit. Conditions, matrices, tolerated failures, containers, services and deployment environments are not reviewed keys and are rejected.
- Every action is a reviewed full commit. Every checkout drops its credential, and a checkout of another repository names a reviewed full commit.
- No script interpolates an expression. Untrusted values reach a script through `env`.
- Exactly one job of the named workflow produces the required context.

The verifier also mutates the real workflow twenty ways and fails unless each mutation is rejected for its own reason. `scripts/check lint` runs `actionlint` for workflow syntax.

## Changing a workflow

A new action, commit pin, event, permission or runner needs the matching edit to the workflow policy in the same pull request. Review the action's own source and its dependencies at the new commit before pinning it.

Renaming the workflow or the job changes the reported context. The rename pull request cannot satisfy the old context, so the owner changes the ruleset context to the new name immediately before merging that pull request. Every other open pull request stays blocked until it contains the renamed `main`. The ruleset is restored with a `PUT` of the previous rules to its ruleset endpoint. The owner keeps that payload with the private settings evidence.

## Review limits

`CODEOWNERS` names the owner. The ruleset requires a pull request and resolved review threads. It requires zero approvals and no code-owner approval, because the only maintainer cannot approve their own pull request. Raising either number blocks every owner change until a second maintainer exists, so that is a separate governing decision. Until then the required check is the merge gate for owner changes. The owner reviews dependency updates and outside contributions before merging them.

## Untrusted pull requests

A pull request from a fork or from Dependabot runs the same `pull_request` workflow with a read-only token. Neither repository has a secret, variable, deployment environment, self-hosted runner, deploy key or webhook, and no workflow writes a cache or an artifact. A first-time contributor's workflow run waits for owner approval. A change to the workflow file inside a pull request runs under the same limits. It cannot gain a credential, and it cannot satisfy the required context under another name.

## Write-capable workflows

Release, cache, artifact-promotion and other write-capable workflows are not admitted today. Each needs its own Issue and governing decision, and these conditions before its first run:

- It lives in a separate workflow file that no pull request event can trigger.
- Each job declares the least permission it needs.
- A credential is reachable only through a protected environment that the owner approves per run.
- A privileged job never restores a cache or downloads an artifact that a pull request job wrote.
- A promoted artifact comes from a protected ref and carries a recorded digest.
- The workflow policy and this page change in the same reviewed pull request.

## Dependency review and scanning

Dependabot alerts and security updates, secret scanning with push protection, and private vulnerability reporting are enabled in both repositories. No code scanning, dependency-review step or advisory scan runs in a workflow. This change adds none. A required check already stops a dependency update that breaks the build or the tests. [Core #174](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/174) owns the choice of an advisory gate, which needs exact component identities and someone to triage its findings.
