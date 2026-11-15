# Contributing to SecretMesh

Thanks for your interest in SecretMesh. It is a personal project that I build and maintain on my own, so I review issues and pull requests as time allows. For anything larger than a small fix, please open an issue first so we can agree on the approach.

Read this before opening a pull request.

## Ground rules

1. **No secret values at rest.** Code must never write secret values to PostgreSQL, logs, traces, metrics, job payloads, error messages or API responses (other than the explicit reveal endpoint). Wrap secret material in `sensitive.Value` as soon as it enters the process.
2. **Fail closed.** If an identity, authorization, approval or policy check cannot be completed, deny the operation.
3. **Contract first.** API changes start in `contracts/openapi/secretmesh.yaml`; run `make generate` and commit the generated code.
4. **Significant design changes need an ADR** in `docs/adr/`.
5. Security issues go through [SECURITY.md](SECURITY.md), not public issues or pull requests.

## Workflow

Install the git hooks once after cloning (needs Go, Node.js and Docker):

```sh
make hooks
```

| Hook | When | What it checks |
|------|------|----------------|
| `pre-commit` | every commit, about 20 s | secrets and credential files, `gofmt`, `go mod tidy`, generated code, `go vet`, golangci-lint, unit tests with the race detector, and for web changes eslint and `tsc` |
| `commit-msg` | every commit | first line of 72 characters or fewer, and a `Signed-off-by` line matching the author (`git commit -s`) |
| `pre-push` | every push, about 40 s | the entire Go suite on **LocalStack and Moto** with the race detector, no skipped tests and a coverage floor; plus a web production build when web files changed |

Useful commands:

```sh
make dev                # run locally
make lint test          # fast checks
make test-integration   # full suite on LocalStack and Moto (starts a throwaway stack in Docker)
make test-localstack    # one emulator, with the stack already up (make test-stack-up)
make security           # gitleaks + govulncheck
make verify             # everything CI checks
```

The test stack (`deployments/docker/compose.test.yaml`) keeps all data in memory and uses its own ports, so it never touches your development stack. AWS behaviour is tested against LocalStack and Moto because they differ in places, as AWS differs from both; a test that only passes on one emulator is testing the emulator. LocalStack is pinned to 4.14.0, the newest release that runs without an account or auth token.

Hooks are a convenience: they run on your machine and can be skipped. **CI runs the same checks and more, cannot be skipped, and must pass before merge.** It additionally runs semgrep, CodeQL, dependency review, workflow linting, container image builds and the DCO check.

## Commits and pull requests

- Sign off every commit with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/). The sign-off must match the commit author.
- Keep pull requests under 1,500 changed lines (generated code and lockfiles excluded); describe the security impact of the change if there is one.
- Add tests for new behaviour. Security-relevant changes (authentication, authorization, tenancy, audit) need negative tests showing the attack fails.
- By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
