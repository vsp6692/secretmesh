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
- Contributions are subject to the licensing rules below. Read them before you submit code.

## Licensing and your contributions

> The licence documents are **drafts** pending legal review (see [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md)). Until the owner adopts them, today's published code is under Apache-2.0. If you submit work now, you are asked to accept the new terms for it so the project can move to them.

SecretMesh is source-available software, free for personal and internal organizational use, including production deployments. Commercial redistribution, resale, white-labeling, and third-party SaaS or managed hosting require a separate commercial license. It is not OSI-approved open source.

**What you agree to when you contribute.**

1. **You keep ownership** of what you write. You license it to the project owner under the [CLA](CLA.md), which includes the right to offer SecretMesh, with your contribution, under the public licence ([LICENSE.md](LICENSE.md)) **and under separate commercial licences**, and to change the licence of future versions.
2. **Everyone else** receives your contribution under [LICENSE.md](LICENSE.md): free for internal use, restricted for commercial redistribution and hosting.
3. **You can still use your own work however you like**, including elsewhere.
4. **Sign off every commit** (`git commit -s`, the Developer Certificate of Origin) *and* state in your first pull request that you have read and accept [CLA.md](CLA.md). Maintainers record acceptance in `.github/cla-signatories.txt`. CLA enforcement is off until the CLA is approved; the CI job reports and does not block.
5. **Employers.** If your employer has rights in your work, get written permission or have the company sign the corporate CLA first.
6. **Only submit what you have the right to submit.** Do not paste code from other projects unless its licence is on the allowed list ([license-policy.json](docs/legal/license-policy.json)) and you state the source in the pull request. Do not submit code under GPL, AGPL, LGPL, SSPL, BUSL or similar licences.
7. **AI-assisted work.** You may use AI tools. You are responsible for what you submit: review it, make sure you have the right to submit it, and **say so in the pull request if a substantial part is AI-generated**. Copyright in AI-generated material is unsettled in many places, and the project owner may ask you to rewrite it.

**Source file headers.** Every source file starts with an SPDX identifier line, which `make license-headers` adds. CI and the pre-commit hook check it.

**Dependencies.** A new dependency must use an allowed licence (`make license-check`) and the notice file must be regenerated (`make license-report`). Copyleft and "unknown" licences are rejected without maintainer approval. Never remove a third-party notice.

**Connectors, plugins, SDKs and extensions.**

| What you build | Licence |
|----------------|---------|
| A provider connector or plugin that you **contribute to this repository** | Part of SecretMesh: [LICENSE.md](LICENSE.md) and the CLA apply |
| An **independent** connector, plugin, script or SDK client that you publish yourself and that talks to SecretMesh only through its documented interfaces and contains none of its source | Yours. License it as you like, including commercially or as open source; see [LICENSE.md](LICENSE.md) section 5.3 |
| A connector or plugin that **copies or edits SecretMesh source files** | A modification of SecretMesh: the SecretMesh licence applies to it |
| A new connector for another cloud | Follow `internal/connectors/contract` and `docs/adr/0012-azure-and-gcp-connectors.md`; contributions follow the same rules as the connectors in this repository |

**Forks and redistribution.** You may publish a free fork to prepare contributions, keeping the licence and notices and not presenting it as the official SecretMesh or using the name as your product name ([TRADEMARK_POLICY.md](TRADEMARK_POLICY.md)). Selling, bundling, hosting for others, or rebranding a fork needs a commercial licence ([COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)). Your own modifications that you keep internal are free.

Questions? [LICENSE_FAQ.md](LICENSE_FAQ.md).
