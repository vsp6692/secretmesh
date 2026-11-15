# Security Policy

SecretMesh governs access to production credentials, so I treat security reports as my highest priority. It is a personal project maintained by one person.

## Supported versions

SecretMesh is pre-release. Until v1.0, only the latest release and `main` receive security fixes.

## Reporting a vulnerability

**Do not open a public issue.**

Report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting).

Please include:

- affected version or commit;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept;
- any suggested mitigation.

I aim to acknowledge reports within 3 business days and to agree on a disclosure timeline with you. As a solo maintainer I may need longer to ship a fix; I will keep you updated. I credit reporters in release notes unless you prefer otherwise.

## Scope

Of particular interest:

- any path by which a secret value is persisted by SecretMesh (database, logs, traces, job payloads, error messages) or exposed to an unauthorized party;
- cross-tenant access;
- bypass of authentication, authorization, approval or execution-policy checks;
- tampering with or suppression of audit records;
- misuse of SecretMesh's cloud identities.

The development credentials in `deployments/docker` and `.env.example` are intentionally public and are not vulnerabilities.
