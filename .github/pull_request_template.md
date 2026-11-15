## What and why

<!-- What does this change do, and why is it needed? Link the issue: "Closes #123". -->

## Security impact

<!-- Does this touch authentication, authorization, tenancy, approvals, audit,
     cloud connectors or anything that handles secret values? If so, explain
     the impact and which negative tests show an attack fails. Write "None" otherwise. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`), see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] `make lint test` passes locally
- [ ] Tests cover the new behaviour (negative tests for security-relevant changes)
- [ ] No secret values are written to the database, logs, traces, job payloads or errors
- [ ] API changes start in `contracts/openapi/secretmesh.yaml` and `make generate` was run
- [ ] Significant design changes include an ADR in `docs/adr/`
