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

## Licensing and security reports

- Security fixes are published for every supported version regardless of how it is licensed: internal users, community users and commercial licensees receive the same fixes. A commercial licence does not buy earlier access to vulnerability details in public releases. [DECISION: whether commercial licensees get a private pre-notification channel; if so, it is named in their agreement.]
- Reports about code you received under the Apache License 2.0 (versions before the licence change) are handled the same way.
- Good-faith security research on **your own** SecretMesh deployment, or on the source code, is welcome and is not restricted by the licence ([LICENSE.md](LICENSE.md) section 5.6).
- This policy does not authorise testing **someone else's** SecretMesh deployment, including hosted instances that a third party operates under a commercial licence. You need that operator's permission.
- If you believe someone is running SecretMesh in breach of its licence (for example, a hosted service without a commercial licence), report it to [LICENSING_CONTACT_EMAIL] (placeholder), not through the vulnerability channel.
- Our own supply chain: dependency licences and software bills of materials are checked in CI ([docs/legal/THIRD_PARTY_LICENSES.md](docs/legal/THIRD_PARTY_LICENSES.md)). A vulnerability in a third-party component should be reported to that component's maintainers and, if SecretMesh is affected, to us.

The development credentials in `deployments/docker` and `.env.example` are intentionally public and are not vulnerabilities.
