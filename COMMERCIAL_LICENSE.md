# SecretMesh Commercial Licensing Framework (DRAFT)

> **DRAFT: pending qualified legal review and owner approval.** This describes how commercial licences are intended to work. No commercial licence is on offer yet, no prices are set, and no agreement exists until the Licensor signs one with you. Placeholders in square brackets are for the owner to fill in.

SecretMesh is source-available and **free for personal and internal organisational use, including production** (see [LICENSE.md](LICENSE.md)). A commercial licence is for people who want to do something the public licence does not allow: put SecretMesh in front of **other people's** hands, or into **their** products.

**You do not need a commercial licence to run SecretMesh for your own organisation**, at any size, in production.

## 1. Who needs one

| Programme | Who | What it would allow | Typical examples |
|-----------|-----|---------------------|------------------|
| **SaaS / hosted** | Companies running SecretMesh as a service for customers | Operating SecretMesh (paid or free) for Third Parties, with their own tenants and billing | A "secrets governance as a service" product built on SecretMesh |
| **Managed hosting** | Cloud, platform and managed-service providers | Running dedicated or shared SecretMesh instances for customers from the provider's infrastructure | An MSP that hosts one instance per customer and operates it for a fee |
| **Reseller / distributor** | Companies selling or distributing SecretMesh | Selling copies, subscriptions, support bundles or marketplace listings of SecretMesh | A software reseller, a cloud marketplace listing |
| **White-label partner** | Companies shipping SecretMesh under their own brand | Rebranding the console and artefacts, using their own name | A security vendor adding "its own" secrets governance module |
| **OEM / embedded** | Vendors embedding SecretMesh in products, appliances or images | Embedding source or binaries in a product distributed to customers | A hardware or software appliance that includes SecretMesh |
| **Commercial derivative** | Companies building commercial products on SecretMesh's source | Selling or distributing products substantially based on the source code | A fork sold as a different product |

A single agreement may cover more than one programme.

## 2. What does not need a commercial licence

- Running SecretMesh internally for your own organisation, including its affiliates, in production, at any scale.
- Consultants, system integrators and managed service providers installing and operating **your own** deployment, in your environment, on your behalf and under your licence, as long as they do not host it for you and others from shared infrastructure of their own (see LICENSE.md section 5.2).
- Writing, selling or open-sourcing independent connectors, plugins, scripts or SDK clients that talk to SecretMesh through its documented interfaces and contain none of its source code (LICENSE.md section 5.3).
- Training, writing, speaking and consulting about SecretMesh.
- Contributing to SecretMesh.

If you are unsure, read [LICENSE_FAQ.md](LICENSE_FAQ.md) and then ask; we would rather answer a question than lose a customer or a community member to uncertainty.

## 3. What a commercial licence is intended to contain

The final agreement is for qualified counsel to draft. The outline below is the proposal:

| Term | Proposal |
|------|----------|
| Grant | Non-exclusive, non-transferable right to do the specific restricted activity in scope, for named products or services |
| Scope | Programme(s), territory, products or services, deployment model, branding rights if any |
| Term and renewal | [TERM, e.g. annual, renewable] |
| Fees | [PRICING_MODEL_TO_BE_DECIDED]. No price list exists. Options considered: fixed fee, revenue share, per-tenant or per-instance fee, or a flat OEM fee |
| Source and updates | Right to build from source; access to releases and security fixes during the term |
| Branding | Whether the SecretMesh name and marks may be used, under [TRADEMARK_POLICY.md](TRADEMARK_POLICY.md); white-label rights are priced and granted separately |
| Third-party components | The licensee remains bound by third-party licences (for example attribution, LGPL and MPL conditions) |
| Contributions | Licensee modifications are the licensee's; sending them upstream is optional and goes through [CLA.md](CLA.md) |
| Security | Both sides follow [SECURITY.md](SECURITY.md); a private security contact is part of the agreement |
| Audit | Reasonable, confidentiality-protected verification that use stays within scope; no telemetry or remote checks are built into the Software |
| Support | None implied. Optional support terms [TO_BE_DEFINED] |
| Warranty and liability | Negotiated; the public licence's disclaimer is the starting point |
| Termination | For breach with cure period; a wind-down period for the licensee's existing customers [DECISION: length] |
| Governing law | [GOVERNING_LAW_AND_FORUM] |

## 4. How to apply

1. Describe what you intend to build or offer, who the end customers are, and which programme applies.
2. Send it to **[COMMERCIAL_CONTACT_EMAIL]** (placeholder: no commercial contact exists yet).
3. The Licensor replies with the applicable terms or a signed agreement. Until you hold a signed agreement, the restricted activities remain off limits.

Do not start restricted activities while a request is pending.

## 5. Who may grant a commercial licence

Only the Licensor, [LICENSOR_LEGAL_NAME], and only for rights it holds. The Licensor can license contributors' work commercially only to the extent the contributors granted those rights through [CLA.md](CLA.md) (or in another written way). Contributions received before the CLA took effect are a limitation: see [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md), section "Contributor rights".

## 6. Commitments (project policy; see LICENSE_FAQ.md)

- Internal use stays free. No licence keys, activation, telemetry or feature limits for permitted uses.
- The commercial licence never takes away rights already granted under the Apache License 2.0 for earlier versions.
- The Licensor will not use a commercial agreement to cancel a community member's internal-use rights.

[OWNER DECISION: whether these commitments are binding terms or non-binding policy.]
