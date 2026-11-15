## What and why

<!-- What does this change do, and why is it needed? Link the issue: "Closes #123". -->

## Security impact

<!-- Does this touch authentication, authorization, tenancy, approvals, audit,
     cloud connectors or anything that handles secret values? If so, explain
     the impact and which negative tests show an attack fails. Write "None" otherwise. -->

## Checklist

- [ ] I have read [CLA.md](../CLA.md) and agree to it for this contribution (draft; not yet enforced), and I understand the contribution is licensed under [LICENSE.md](../LICENSE.md) and may also be offered under commercial licences
- [ ] New source files carry the SPDX header (`make license-headers`); new dependencies pass `make license-check` and `docs/legal/THIRD_PARTY_LICENSES.md` was regenerated (`make license-report`)
- [ ] I wrote this myself or have the right to submit it; any substantial AI-generated part is disclosed above
- [ ] Commits are signed off (`git commit -s`), see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] `make lint test` passes locally
- [ ] Tests cover the new behaviour (negative tests for security-relevant changes)
- [ ] No secret values are written to the database, logs, traces, job payloads or errors
- [ ] API changes start in `contracts/openapi/secretmesh.yaml` and `make generate` was run
- [ ] Significant design changes include an ADR in `docs/adr/`
