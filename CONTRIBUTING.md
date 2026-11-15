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

```sh
make dev                # run locally
make lint test          # before pushing
make test-integration   # with a database (see README)
make security           # gitleaks + govulncheck
```

CI runs the same checks, plus integration tests against PostgreSQL, semgrep and CodeQL. All must pass before I merge.

## Commits and pull requests

- Sign off every commit with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/). The sign-off must match the commit author.
- Keep pull requests under 1,500 changed lines (generated code and lockfiles excluded); describe the security impact of the change if there is one.
- Add tests for new behaviour. Security-relevant changes (authentication, authorization, tenancy, audit) need negative tests showing the attack fails.
- By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
