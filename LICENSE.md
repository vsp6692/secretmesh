# SecretMesh Source-Available License, Version 1.0 (DRAFT)

SPDX identifier: `LicenseRef-SecretMesh-SAL-1.0-DRAFT`

> **DRAFT: NOT YET IN EFFECT. PENDING QUALIFIED LEGAL REVIEW AND OWNER APPROVAL.**
> This text is a proposal. It has not been reviewed by a lawyer, it has not been adopted, and no release has been made under it. Until the owner adopts it, SecretMesh remains available under the Apache License 2.0 (see [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt) and [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md)). Items in square brackets are placeholders that the owner must fill in; nothing in them has been invented.

SecretMesh is **source-available software, not open source software** as defined by the Open Source Initiative. You can read, run, modify and use the source code, but the licence restricts commercial redistribution and third-party hosting. This licence is not approved by the OSI.

In plain words (the numbered terms below control if there is any difference):

- Free for personal use, education, research and testing.
- Free for internal use by any organisation, including production use by companies, with no limits on users, servers, accounts or size.
- You may modify it for your own internal use.
- You need a **separate commercial licence** to resell it, redistribute it commercially, white-label it, embed it in a product you ship, or offer it (paid or free) to other people as SaaS, hosted or managed software.

Copyright (c) [COPYRIGHT_YEARS] [LICENSOR_LEGAL_NAME]. All rights reserved except as granted below.

---

## 1. Definitions

- **"Software"** means the SecretMesh source code, documentation, build files, database migrations, policies, contracts, deployment templates and other materials in this repository or distributed with it by the Licensor, and any Modification of them.
- **"Licensor"** means [LICENSOR_LEGAL_NAME], the owner of the copyright in the Software, together with anyone it has authorised to grant this licence.
- **"You"** means the individual or the legal entity exercising rights under this licence.
- **"Affiliate"** means an entity that controls You, is controlled by You, or is under common control with You, where control means owning more than 50% of the voting interests or the power to direct management.
- **"Organization"** means You and Your Affiliates.
- **"Modification"** means any change to, or work that is a derivative work of, the Software under applicable copyright law.
- **"Internal Use"** means using, running, copying and modifying the Software to operate the business, activities and systems of Your Organization, including production use and commercial business operations, where the Software is operated by or for Your Organization on infrastructure that Your Organization controls or has contracted for its own account, and where the only people who use the Software's functionality are Your Organization's own personnel (employees, officers, contractors and agents acting on Your Organization's behalf).
- **"Third Party"** means any person or entity that is not part of Your Organization. Your customers, end users, tenants, partners and members of the public are Third Parties.
- **"Core Functionality"** means the governance functions of the Software as a whole or in substantial part: discovering, approving, rotating, auditing and revealing secrets in cloud secret stores, the approval and execution gate chain, the audit ledger, and the web console and API that expose them.
- **"Independent Integration"** means software that you write yourself, that communicates with the Software only through its documented public interfaces (the HTTP API described in `contracts/`, the connector, plugin and notification interfaces documented in `docs/`, configuration, or standard network protocols), and that does not copy or incorporate source code of the Software beyond what those interfaces' documentation and generated clients permit.
- **"Contribution"** means anything You intentionally submit to the Licensor for inclusion in the Software, as governed by [CLA.md](CLA.md).

## 2. Licence grant: free uses

Subject to this licence, the Licensor grants You a worldwide, non-exclusive, royalty-free, non-sublicensable, non-transferable (except under section 10) licence to do the following, without fee:

1. **Inspect and learn.** Download, read, study and test the Software.
2. **Personal and non-commercial use.** Use the Software for personal, educational, academic, research and other non-commercial purposes.
3. **Internal Use.** Use the Software for Internal Use, including production deployments by commercial businesses, without any limit on the number of users, resources, infrastructure, accounts, secrets, connections, organisations configured in the Software, or the size of the deployment.
4. **Internal Modification.** Modify the Software and use the Modified version for Internal Use.
5. **Contribute.** Prepare and submit Contributions under section 9, including bug fixes, features, provider connectors, plugins and integrations.
6. **Permitted Sharing.** Share the Software, or a Modified version, with others only as described in section 3.

## 3. Permitted sharing (not a commercial redistribution)

You may make copies of the Software, including Modified versions, available to others if **all** of the following are true:

1. it is free of charge, and is not part of, bundled with, or a condition of a paid or otherwise commercial product, service, subscription, support contract or consulting deliverable;
2. the recipient receives this licence with the Software and is bound by it;
3. all copyright, licence, attribution and trademark notices are kept, and Modified files carry a prominent notice that they were changed;
4. it is not offered as a hosted or managed service (section 4.2);
5. a Modified version that is made public is not presented as the official SecretMesh and does not use the SecretMesh name or marks except as the [Trademark Policy](TRADEMARK_POLICY.md) allows.

Examples that this section is meant to allow: a public fork on a code-hosting platform to prepare a Contribution; giving a colleague at another company a copy of the source to evaluate; publishing a tutorial that includes short excerpts.

## 4. Restricted uses: a commercial licence is required

You must have a separate written commercial licence from the Licensor ([COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)) before You do any of the following, with or without charge, except where section 3 or section 5 applies:

1. **Resale and commercial redistribution.** Sell, resell, rent, lease, license, sublicense or otherwise commercially distribute the Software or a Modified version, alone or bundled with other things.
2. **Hosted and managed services.** Offer the Software, or its Core Functionality, to Third Parties as software-as-a-service, hosted software, a managed service, a platform, an API or any other service where Third Parties access or benefit from the Software's functionality as operated by You, whether the service is paid or free.
3. **White-labelling.** Distribute or provide the Software under a name, brand, logo or interface other than SecretMesh's, or otherwise rebrand it, for commercial purposes.
4. **Embedding.** Incorporate the Software or any substantial portion of its source code into a product, appliance, image or package that You distribute or make available commercially to Third Parties.
5. **Derivative products.** Sell or commercially distribute a product that is substantially based on the Software's source code.
6. **Commercially modified versions.** Distribute commercially Modified versions of the Software.
7. **Core Functionality as a commercial service.** Provide the Software's Core Functionality to Third Parties as a commercial service, however delivered.

These restrictions apply to commercialisation by and for Third Parties. They do not restrict Your Organization's own internal operations (section 2.3).

## 5. Clarifications

1. **Internal business operations are permitted.** A company that deploys SecretMesh in its own cloud accounts to govern its own secrets, for its own staff, may do so freely, in production, at any scale.
2. **Contractors and service providers.** Your contractors, consultants and managed service providers may install, configure, operate and support the Software **on Your Organization's behalf and for Your Organization's own Internal Use**, in an environment that Your Organization controls or pays for, without a commercial licence from the Licensor, provided that the Software remains Your Organization's deployment under this licence and they do not run it as a service that they offer to You and other customers from shared infrastructure of their own. Ordinary consulting, training, integration and deployment assistance are not restricted by this licence.
3. **Independent Integrations.** An Independent Integration (for example a connector, plugin, script, SDK client or dashboard written by You) is Your own work. You may license and distribute it, including commercially, on any terms You choose, **provided that** it contains no source code of the Software beyond what section 1 allows, and **provided that** distributing it does not involve distributing the Software itself. A connector or plugin that copies or modifies the Software's source files is a Modification, not an Independent Integration. See section 11 for connectors, plugins and SDKs that the Licensor publishes.
4. **Your own data and configuration.** Secrets, policies, configuration, audit records and other content You create or manage with the Software belong to You. This licence grants the Licensor no rights in them.
5. **No artificial limits.** The Licensor does not intend to, and the Software distributed under this licence will not, require licence keys or activation, send telemetry, or limit features, users, resources or deployment size for uses permitted by sections 2 and 3. [OWNER DECISION: keep this clause as a binding term, or move it to a non-binding project commitment in LICENSE_FAQ.md.]
6. **Public disclosure of the Software's weaknesses.** Nothing in this licence restricts good-faith security research or the publication of vulnerability reports in line with [SECURITY.md](SECURITY.md).

## 6. Conditions

1. Keep all copyright, licence and attribution notices, and include a copy of this licence, when You share the Software under section 3.
2. Do not remove or obscure the Licensor's notices, or any notice of a third party, from the Software.
3. Do not use the Licensor's names, logos or marks except as the [Trademark Policy](TRADEMARK_POLICY.md) permits. This licence does not grant any trademark rights.

## 7. Third-party components

The Software includes or depends on components owned by others, licensed under their own terms (for example Apache-2.0, MIT, BSD, ISC, MPL-2.0, LGPL-3.0-or-later and CC-BY-4.0 components). This licence does not change those terms and does not restrict Your rights under them. Their notices are listed in [docs/legal/THIRD_PARTY_LICENSES.md](docs/legal/THIRD_PARTY_LICENSES.md). If a component's licence conflicts with this licence for a particular use, the component's licence controls for that component.

## 8. No warranty and limitation of liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. SECRETMESH GOVERNS ACCESS TO CREDENTIALS; YOU ARE RESPONSIBLE FOR TESTING IT, CONFIGURING IT SECURELY AND DECIDING WHETHER IT IS SUITABLE FOR YOUR USE.

TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE LICENSOR WILL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL OR PUNITIVE DAMAGES, OR FOR LOSS OF PROFITS, DATA, SECRETS OR GOODWILL, ARISING FROM THE SOFTWARE OR THIS LICENCE, UNDER ANY THEORY OF LIABILITY, EVEN IF ADVISED OF THEIR POSSIBILITY. [LEGAL REVIEW: liability caps and exclusions vary by jurisdiction and cannot exclude liability that the law does not allow to be excluded.]

## 9. Contributions

By submitting a Contribution You agree to [CLA.md](CLA.md). Under it You keep ownership of Your Contribution and grant the Licensor the rights it needs to include the Contribution in the Software and to license the Software, including Your Contribution, under this licence and under separate commercial licences. Contributions are then licensed to everyone else under this licence.

## 10. Transfer and Affiliates

You may not transfer this licence, except to a successor of Your Organization's business as a whole (by merger, acquisition or sale of substantially all relevant assets) that is bound by this licence. Your Affiliates may exercise Your rights under section 2 as part of Your Organization.

## 11. Connectors, plugins, SDKs and extensions

1. **Published by the Licensor in this repository.** Provider connectors, plugins, SDKs, deployment templates and extensions that are in this repository are part of the Software and are covered by this licence, unless a file or directory states a different licence in its own `LICENSE` file or SPDX header.
2. **Written by You.** An Independent Integration is Yours (section 5.3).
3. **Contributed to this repository.** A connector or plugin that You contribute is a Contribution (section 9) and becomes part of the Software.
4. **Separate licences.** The Licensor may, in its discretion, publish particular SDKs or interface definitions under a more permissive licence to encourage independent integrations. Any such licence applies only to the files that say so. [OWNER DECISION: whether to publish a permissively licensed SDK or connector interface package.]

## 12. Earlier versions

This licence applies to the Software from [EFFECTIVE_DATE] ("Effective Date") and to commits and releases made on or after it. The Licensor proposes the repository state at commit `82f1e0e` (the head of the `main` branch when this draft was written) as the last Apache-2.0 version; the final boundary is [LAST_APACHE_2_0_COMMIT_OR_TAG]. Copies of the Software that anyone received under the Apache License 2.0 before the Effective Date remain licensed to those recipients under the Apache License 2.0, which is irrevocable as to those copies, and nothing in this licence takes those rights away. The Licensor does not offer later versions under Apache-2.0.

## 13. Termination

1. If You breach this licence, Your rights under it end automatically for the breaching use.
2. The Licensor will reinstate Your rights if You stop the breach and, for a first breach, within 30 days of notice from the Licensor, cure it. A second breach within 12 months ends Your rights until the Licensor reinstates them in writing.
3. Ending Your rights does not affect anyone who received the Software from You under section 3 and who complies with this licence.
4. Sections 7, 8, 13 and 14 survive termination.

## 14. General

1. **Governing law and courts.** [GOVERNING_LAW_AND_FORUM: to be chosen by the owner with legal advice.]
2. **Severability.** If a part of this licence is unenforceable, the rest remains in effect and the part is enforced to the maximum extent permitted.
3. **No waiver.** Failure to enforce a term is not a waiver of it.
4. **Entire agreement.** This licence, [CLA.md](CLA.md) where it applies and any signed commercial licence are the whole agreement about the Software; a signed commercial licence controls where it conflicts with this text.
5. **Interpretation.** Headings are for convenience. The plain-words summary near the top is not a term.
6. **Commercial licensing.** To ask for a commercial licence, contact [COMMERCIAL_CONTACT_EMAIL].

---

*Reminder: this is a draft that no lawyer has reviewed. Do not rely on it as legal advice, and do not publish a release under it until it has been reviewed and approved. See [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md) for open legal questions.*
