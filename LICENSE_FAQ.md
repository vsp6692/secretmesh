# Licensing FAQ (DRAFT)

> **DRAFT: pending qualified legal review and owner approval.** This FAQ explains the proposed licence in [LICENSE.md](LICENSE.md). It is not legal advice, and where it differs from LICENSE.md, LICENSE.md controls. Nothing here is in effect until the owner adopts the licence; today, SecretMesh as published is under the Apache License 2.0.

SecretMesh is source-available software, free for personal and internal organizational use, including production deployments. Commercial redistribution, resale, white-labeling, and third-party SaaS or managed hosting require a separate commercial license.

## The basics

**Is SecretMesh open source?**
No. It is **source-available**. You can read, run and change the code, but the licence is not approved by the Open Source Initiative (OSI) because it restricts commercial redistribution and third-party hosting. Please do not describe it as "open source".

**Why not open source?**
SecretMesh is a personal project. The owner wants it to be usable by everyone for their own needs while keeping the right to build a commercial business (for example a hosted version) on it. See [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md).

**Does it convert to open source later?**
No. BUSL 1.1 and FSL convert to an open-source licence after a set time. This licence does not, because the owner wants the commercial restrictions to remain. That is a deliberate choice you can ask the owner to revisit.

**What did I already receive under Apache-2.0?**
Versions published under the Apache License 2.0 stay yours under that licence. If you obtained SecretMesh before the effective date, nothing changes for those copies. See LICENSE.md section 12.

## What is free

**Can my company run SecretMesh in production?**
Yes. Internal production use by any organisation, including commercial businesses, is free, with no limit on users, servers, accounts, secrets, environments or deployment size. There are no licence keys, no activation and no telemetry.

**Can I modify it for my own company?**
Yes. Internal modifications and customisations are free.

**Can my subsidiaries use it?**
Yes. Your "Organization" includes affiliates you control (more than 50%).

**Can our contractors use it?**
Yes, when they act for your organisation. They are part of your personnel for this purpose.

**Can I use it for research, teaching or learning?**
Yes.

**Can I contribute?**
Yes, under the [CLA](CLA.md) and the rules in [CONTRIBUTING.md](CONTRIBUTING.md).

## What needs a commercial licence

**Can I offer SecretMesh as a hosted service to my customers?**
Not without a commercial licence, even if it is free. That includes giving customers logins to a SecretMesh instance that you operate for them.

**What if my customers only use it to manage secrets in their own cloud accounts?**
If they access a SecretMesh that **you** run, you are offering the service to third parties. That needs a commercial licence. If they run SecretMesh **themselves**, in their own environment, under the public licence, you do not.

**Can I resell it, bundle it or put it in a marketplace?**
Not without a commercial licence.

**Can I rebrand it?**
Not for commercial distribution without a commercial licence. Internal rebranding for your own staff is part of internal modification and is fine, but do not use the SecretMesh trademark in a misleading way ([TRADEMARK_POLICY.md](TRADEMARK_POLICY.md)).

**Can I embed it in a product I sell?**
Not without a commercial licence.

## The grey areas, answered

**I am a consultant. Can I install SecretMesh for clients?**
Yes. Installing, configuring, tuning, training and supporting a client's own deployment, in the client's environment and under the client's licence, is fine. You must not host it for several clients from your own shared infrastructure as a service.

**I am an MSP. Can I operate a client's SecretMesh in the client's cloud account?**
Operating it **for** the client, **in** the client's environment, with the client as the licensee, is intended to be allowed (LICENSE.md section 5.2). Running it on your infrastructure as a service you offer to clients is not. This is one of the areas where the owner and counsel should confirm the line; see the decisions list in the licensing strategy.

**Can I write and sell a connector or plugin?**
Yes, if it is an *Independent Integration*: you write it, it talks to SecretMesh through its documented interfaces, and it contains none of SecretMesh's source code. You can license it however you like, including commercially or as open source. A connector that copies or edits SecretMesh source files is a modification, not an independent integration. Connectors you contribute to this repository become part of SecretMesh under the licence.

**Can I publish a public fork?**
Yes, to prepare contributions or to share improvements for free, under LICENSE.md section 3: free of charge, with the licence and notices intact, not hosted as a service, and not presented as the official SecretMesh. Forks that are public must not use the SecretMesh name as their own product name.

**Can I fork it and build a competing commercial product?**
Not from SecretMesh's source: a product substantially based on the source needs a commercial licence. You are free to build an independent product that does not use the source. The licence cannot stop someone from independently developing a competing product, and nothing here claims otherwise.

**Is a company's internal platform team offering SecretMesh to its other business units "third party" use?**
No, if the business units are part of your organisation (the same company or its controlled affiliates). Giving it to separate companies is third-party use.

**Our customers will approve secret changes in our product's UI that talks to SecretMesh's API.**
If the SecretMesh instance is run by you for those customers, that is a hosted service and needs a commercial licence. Talk to us before you design around it.

## Contributions and rights

**Who owns what I contribute?**
You do. By signing the [CLA](CLA.md) you give the owner a broad licence (including the right to relicense it, for instance under commercial terms). The CLA is a draft; see the strategy document for the "licence versus assignment" decision.

**Can the owner change the licence again?**
The owner can license **new** versions under different terms and can grant commercial licences, within the rights contributors granted. Versions you already received stay under the licence they came with.

**What about code written with AI tools?**
You must have the right to contribute what you submit and must disclose AI assistance you are not confident about; copyright in AI-generated material is unsettled in many places. See CONTRIBUTING.md and the strategy's legal-risk list.

## Practical

**Is there telemetry or a licence check in the software?**
No, and none is planned for permitted uses.

**Where are third-party licences?**
[docs/legal/THIRD_PARTY_LICENSES.md](docs/legal/THIRD_PARTY_LICENSES.md) and the `LICENSES/` directory.

**How do I ask for a commercial licence?**
See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). The contact is a placeholder until the owner sets one up: [COMMERCIAL_CONTACT_EMAIL].

**Who do I ask a licensing question?**
[LICENSING_CONTACT_EMAIL] (placeholder). Do not open a public issue for a question about your private commercial plans.
