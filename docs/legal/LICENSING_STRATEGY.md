# SecretMesh licensing strategy (DRAFT)

Date: 2026-11-15
Status: **Draft proposal. Not legal advice. No qualified lawyer has reviewed it. Nothing here is in effect.** It becomes effective only if the owner adopts it after legal review (see the [adoption checklist](#adoption-checklist)). Nothing has been published, tagged or released under it.

SecretMesh is source-available software, free for personal and internal organizational use, including production deployments. Commercial redistribution, resale, white-labeling, and third-party SaaS or managed hosting require a separate commercial license.

## 1. What this document does

It records the current licensing position of the project, the effect of moving from Apache-2.0 to a source-available model, the options compared, the recommendation, the legal risks, and the decisions that only the owner can make. It accompanies these drafts: [LICENSE.md](../../LICENSE.md), [COMMERCIAL_LICENSE.md](../../COMMERCIAL_LICENSE.md), [LICENSE_FAQ.md](../../LICENSE_FAQ.md), [CLA.md](../../CLA.md), [TRADEMARK_POLICY.md](../../TRADEMARK_POLICY.md), and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

The change is **licensing and documentation only**. The architecture, plan, stack, APIs, schemas and behaviour are unchanged, and no licence keys, activation, telemetry or feature limits are added.

## 2. The project today (from the repository)

| Fact | Finding | Source |
|------|---------|--------|
| Product | SecretMesh: multi-cloud secrets governance (AWS Secrets Manager, Azure Key Vault, Google Cloud Secret Manager). Go API, Next.js console, PostgreSQL. "A personal project" of [@vsp6692](https://github.com/vsp6692) | README, PLAN.md |
| Roadmap | M0 to M5 built (M5 verified against in-process fakes only); M6 (posture, CLI, Helm, SBOM and signing, release) not started; self-hosted first, SaaS after v0.1 | PLAN.md |
| Current licence | **Apache License 2.0**, in the file `LICENSE`, with the template appendix unfilled: `Copyright [yyyy] [name of copyright owner]`. No copyright notice naming a holder appears anywhere in the repository | LICENSE, README, `contracts/openapi` |
| Source headers | None before this change | |
| Contribution model | Pull requests; DCO sign-off (`Signed-off-by`) required by the commit hook and CI; `CONTRIBUTING.md` said contributions are licensed under Apache-2.0. No CLA | CONTRIBUTING.md, `.github/workflows/pr.yml` |
| Publication | Public repository `vsp6692/secretmesh` on GitHub, pushed from 2026-11-15; history rewritten once on the same day to remove an AI co-author trailer from two commits | git history |
| Releases and tags | **No git tags exist.** GitHub Releases and forks could not be checked from the working environment (API rate limit): [VERIFY] | git |
| Commit identities seen | `Satheesh <vsp6692@gmail.com>` (owner), `Satheesh <admin@concocterz.in>` (one commit), `T3 Code` (commits made through a coding-agent tool), `dependabot[bot]` (dependency PRs on branches, not merged). **No commit from an external human contributor exists in the history.** | `git shortlog` |
| Third-party code | No third-party source is vendored. Dependencies are consumed as modules: 76 Go modules and 25 production npm packages (see THIRD_PARTY_LICENSES.md) | go.mod, package.json |
| Existing licensing checks | GitHub dependency review denies GPL, AGPL, SSPL and BUSL in pull requests | `.github/workflows/pr.yml` |

## 3. Rights already granted, and what cannot be undone

Apache-2.0 gives every recipient of a copy a worldwide, perpetual, irrevocable (except for patent litigation) licence to use, modify, redistribute, sublicense and **host as a service, commercially**, plus a patent licence. SecretMesh has been public under Apache-2.0 since at least commit `c0538a9` (`f81c439` after the history rewrite; the same tree).

Consequences:

1. **Copies that anyone has already obtained stay Apache-2.0 for good.** The owner cannot revoke that, and this strategy does not try to. The draft licence says so (LICENSE.md section 12).
2. **A third party can fork the last Apache-2.0 version and run it as a competing service, indefinitely.** The new restrictions protect only **future** code. The last Apache-2.0 version contains the whole M1 to M5 feature set (identity, tenancy, approvals, audit, AWS/Azure/GCP connectors, rotation, console). That is a real limit on the strategy and it grows with every day the Apache-2.0 version stays public. Adopting the new licence **soon, before outside adoption**, minimises it.
3. **Proposed boundary:** the last Apache-2.0 state is the head of `main` when this draft was written, commit **`82f1e0e`** (the head after the 2026-11-15 history rewrite). The licence change sits on the local branch `licensing/source-available-draft`, which remains a draft. Decision 4 below fixes the boundary.
4. **Relicensing does not need anyone's permission only for code the owner owns** (section 5).

## 4. The model

| | Free | Commercial licence needed |
|---|------|--------------------------|
| People | Individuals, students, researchers; any organisation and its controlled affiliates | Anyone offering SecretMesh to **third parties** |
| Use | Read, test, learn; personal, educational, research and non-commercial use; internal production use by any organisation, including businesses; internal modification; contributions and independent integrations | Resale and commercial redistribution; SaaS, hosted or managed service for third parties (paid or free); white-labelling; embedding in a distributed product; commercial derivatives; sublicensing; providing the core functionality to third parties as a commercial service |
| Size | No limit on users, resources, infrastructure, accounts or deployment size | |
| Product behaviour | No licence key, no activation, no telemetry, no feature or usage limits for permitted use | |

Consulting, training, integration and deployment assistance are **not** restricted, nor are independent integrations written through the documented interfaces. The drafts mark the one boundary that counsel and owner should confirm: a service provider operating a client's deployment, in the client's environment, under the client's licence (LICENSE.md section 5.2), as opposed to running SecretMesh for several clients on its own infrastructure (restricted).

Commercial licence programmes: SaaS, managed hosting, resellers and distributors, white-label, OEM and embedded, commercial derivatives (COMMERCIAL_LICENSE.md). Prices and terms are not defined; they are placeholders.

## 5. Contributor rights

The owner can relicense code **only if the owner holds the rights to do so.** Findings:

1. **The owner's own code.** The `LICENSE` file names no copyright holder, and no notice does. Copyright initially belongs to the author, or to an employer or client if the work was done under an employment or contractor agreement or with their resources. The repository shows two author identities for the owner (`vsp6692@gmail.com` and `admin@concocterz.in`) and a README that calls it a personal project. **Decision 1 (owner):** state which legal person owns the copyright and confirm no employer or client has a claim.
2. **Agent- and AI-assisted code.** Most of the code was produced with the help of AI coding tools (the history shows commits made through such a tool, and earlier commits carried an AI co-author trailer, since removed). Whether AI-generated material is copyrightable depends on human authorship and differs by country; tool terms say who owns output as between the user and the tool vendor, and should be re-read against the versions used. A licence can only restrict what is protected. **Risk:** parts of the code may be unprotected, or protected only to the extent of human creative direction and editing. Counsel should advise on this and on what record of human authorship to keep.
3. **External human contributors.** **None found** in the Git history; the only non-owner commits are dependency-bot version bumps, which carry no creative expression of consequence. The open Dependabot pull requests are unmerged. Before any external contribution is accepted, the CLA process must be live.
4. **DCO versus CLA.** The DCO sign-off certifies the right to submit under the project's licence **at the time**. It does not give the owner the right to relicense or to sell commercial licences. `CONTRIBUTING.md` previously said contributions were licensed under Apache-2.0; had any outside contribution been accepted under that statement, the owner could not take it into the new licence without that contributor's consent. There is none today, which is why timing matters.
5. **CLA design.** [CLA.md](../../CLA.md) is a **licence-back** CLA: contributors keep copyright and grant a broad licence including the right to relicense, plus a patent licence. The alternative is a copyright **assignment**. Licence-back is more acceptable to contributors; assignment is cleaner for the owner. **Decision 5.**
6. **Enforcement.** The `cla` CI job reports missing acceptance without failing (`CLA_ENFORCE: "false"`), because the CLA is a draft. It switches to blocking once the owner approves the text.

## 6. Options compared

| | BUSL 1.1 | FSL (Functional Source License) | Custom source-available (**recommended draft**) |
|---|----------|----------------------------------|-------------------------------------------------|
| Free internal production use | Yes, if the Additional Use Grant says so | Yes (internal use is a permitted purpose) | Yes, by design |
| Restriction on hosting for third parties | Expressible through the Additional Use Grant, any scope | Limited to "competing use" (a product or service substantially similar or with overlapping functionality); other commercial hosting is allowed | Any third-party hosting, paid or free |
| Restriction on resale, white-label, OEM, embedding | Expressible, any scope | Only where it is a competing use | Yes, explicit |
| **Converts to open source later** | **Yes, always:** to the Change License at the Change Date, which may not be later than 4 years after each version's first public release | **Yes, always:** each version becomes Apache-2.0 or MIT two years after release | **No**, unless the owner chooses to add a conversion |
| Legal maturity | Widely used (HashiCorp, MariaDB, others), text known to counsel; the BUSL name may only be used if the text is unmodified except the parameters | Newer, published with a model text and a FAQ; used by several vendors | None: a bespoke text needs fresh drafting and review, and its terms are untested in court |
| Community and procurement friction | Moderate; known pattern | Lower; a short, known conversion promise reassures users | Higher: unfamiliar licences trigger legal reviews and some organisations will refuse them |
| Not OSI | Not OSI-approved | Not OSI-approved | Not OSI-approved |
| Cost to adopt | Low | Low | Highest: legal drafting and review |
| Fit with the stated requirements | Partial: permanent restriction is impossible (4-year cap) | Partial: restriction limited to competing use, two-year conversion | **Full**, at the cost of legal work and adoption friction |

Other common models, considered and not recommended for this requirement set: **AGPL-3.0 with a commercial licence** (open source, strong network-use copyleft; it permits free hosting by anyone who shares their source, so it does not "restrict third-party hosting"); **Elastic License 2.0** (permanent, prohibits offering as a managed service, but does not restrict redistribution or embedding and its terms are Elastic's); **PolyForm Internal Use** (internal use only; no external use at all); **SSPL** (broad service source-sharing condition, not OSI-approved and rejected by many distributors).

**Recommendation.** Because the owner requires *permanent* restrictions on hosting and redistribution, a **custom source-available licence reviewed by counsel** is the only option that expresses them without a conversion date, as the task requires; that is what is drafted. If the cost or friction proves too high, the lowest-effort fallback is **BUSL 1.1 with a custom Additional Use Grant** (permanent-looking in practice because each release restarts a four-year clock, but converting each version in the end), or **FSL** if a narrower "competing use" restriction is acceptable. Both convert; neither is permanent. That is a trade-off the owner must accept knowingly.

## 7. Plugins, connectors, SDKs and extensions

| Case | Treatment (see LICENSE.md section 11, CONTRIBUTING.md) |
|------|------------------------------------------------------|
| Connectors, plugins, SDKs, templates in this repository | Core licence, unless a directory states otherwise |
| Independent connector, plugin, script or client written by someone else, via the documented interfaces, with no SecretMesh source | Theirs; any licence, commercial or open source |
| A work that copies or edits SecretMesh source | A modification: core licence applies |
| A contribution to the repository | Under the CLA; becomes part of SecretMesh |
| Published SDK or interface definitions under a more permissive licence | **Option**, to encourage an ecosystem. Not drafted. **Decision 7.** |

"Documented interfaces" means the HTTP API in `contracts/`, and the connector, plugin and notification interfaces described in `docs/`. In this codebase the connector interface (`internal/connectors`) is a Go package inside the module, so a third-party Go connector would import SecretMesh packages and may be a derivative work. Whether such a connector is an "independent integration" depends on how it is built; a stable external plugin protocol (for example process or HTTP based) would make the answer clearer. **Decision 7.**

## 8. Legal risks

1. **Existing open-source obligations.** Apache-2.0 sections 4(a) to 4(d) bind anyone who redistributes the Apache-licensed versions, not the owner. The owner's own continuing obligations are limited to copies already granted (section 3). Third-party Apache NOTICE files must be preserved.
2. **Previously granted rights.** Irrevocable for existing copies; competitors may fork the last Apache version (section 3). The new licence cannot change this and the drafts do not pretend otherwise.
3. **Contributor and author copyright.** Open items in section 5: owner identity and any employer claim, AI-assisted authorship, and the absence (so far) of external contributors.
4. **Enforceability across jurisdictions.** Source-available licences are enforced as copyright licences with conditions and as contracts. Restrictions on *hosting* are not copyright-law restrictions in most jurisdictions (running software is not distributing it), so they must work as licence conditions or contract terms, and contract formation (assent by conduct) and unfair-terms rules differ across the EU, UK, US states and elsewhere. Clauses such as the liability exclusion, the termination and cure terms and the governing-law choice need local advice. Expect uncertainty and cost when enforcing against a violator in another country.
5. **Derivative-work interpretation.** The draft relies on "Modification", "substantially based" and "Independent Integration". Boundaries (API clients, plugins that link against Go packages, generated clients, configuration-only extensions) are fact-specific and may be read differently by different courts. Ambiguity cuts against the drafter.
6. **Third-party dependency restrictions.** An LGPL-3.0 component (libvips via `sharp`, in the web image) and MPL-2.0 components (River) are present. LGPL conditions (replaceability, no terms that forbid it) must not be defeated by SecretMesh's licence; counsel should confirm for the web image and decide whether to drop `sharp`. CC-BY-4.0 data (`caniuse-lite`) needs attribution. CI enforces the policy and blocks other copyleft licences.
7. **Trademark and branding.** SecretMesh has no registered trademark and no clearance search is known. The name could conflict with an existing mark; the licence grants no trademark rights; white-label use needs a separate grant. See TRADEMARK_POLICY.md.
8. **Calling it "open source".** The licence is not OSI-approved and the drafts say so. Describing it as open source would be inaccurate.
9. **No prevention guarantee.** Source-available licensing does not prevent copying, and it cannot stop independently written competing products. It gives the owner a legal basis to object to specific uses.
10. **Community and adoption cost.** Some users and distributors avoid non-OSI licences; the permanent restrictions may reduce contributions.
11. **Liability and security product.** SecretMesh governs credentials. The warranty disclaimer and liability limitation are important and jurisdiction-sensitive, and commercial licensees may expect more.

## 9. Decisions for the project owner

| # | Decision | Recommendation |
|---|----------|----------------|
| 1 | Who is the Licensor (legal person), and does any employer or client hold rights? | Name the person or entity; confirm in writing; fill `[LICENSOR_LEGAL_NAME]` |
| 2 | Adopt a custom licence, BUSL 1.1 or FSL (section 6)? | Custom, after legal review, if permanent restriction matters; otherwise BUSL or FSL |
| 3 | Effective date | After legal review, before external contributions or wide adoption |
| 4 | The last Apache-2.0 commit or tag | `82f1e0e` (head of `main` before the licence change); create a tag such as `last-apache-2.0` there, only after approval |
| 5 | CLA: licence-back or assignment; "any terms" or limited relicensing grant; Licensor's undertakings (CLA.md section 4) | Licence-back with the relicensing grant, plus a non-binding undertaking that internal use stays free |
| 6 | Whether "no licence keys, activation, telemetry or limits" is a binding licence term (LICENSE.md section 5.5) or a policy commitment | Policy commitment in the FAQ, to avoid binding future product decisions; or binding, if trust matters more |
| 7 | Plugin ecosystem: publish a permissive SDK or a process-based plugin protocol? | Yes, later, before inviting third-party connectors |
| 8 | The service-provider boundary (LICENSE.md section 5.2) and whether a public free fork is allowed (section 3) | Keep both as drafted; ask counsel |
| 9 | Governing law and forum; liability terms | Counsel |
| 10 | Commercial pricing and programmes; contact details | Not defined; decide when a first customer asks |
| 11 | Trademark registration, clearance and the owning entity | Clearance search first |
| 12 | `sharp` and the LGPL library in the web image: keep and comply, or remove | Counsel; removing image optimisation avoids the issue |
| 13 | Handling of the Claude trailer history | Already removed by the 2026-11-15 history rewrite; record what AI tools were used (section 5.2) |

## 10. Adoption checklist

Do not publish, tag or release until every step is done.

1. Qualified counsel reviews LICENSE.md, COMMERCIAL_LICENSE.md, CLA.md, TRADEMARK_POLICY.md and this strategy, in the owner's jurisdiction(s).
2. Resolve every decision in section 9; fill every placeholder in square brackets in the legal documents.
3. Verify what has been published: GitHub Releases, forks, clones and stars, any contributor who is not the owner (section 3, section 5).
4. Create the boundary tag at the last Apache-2.0 commit (decision 4).
5. Change the SPDX identifier from the draft one: edit `spdxID` in `scripts/licenses/headers.go` and the identifier line in LICENSE.md and `contracts/openapi/secretmesh.yaml`, then run `make license-headers`, `make generate` and the container image labels.
6. Remove the draft banners and the "pending legal review" text; set `CLA_ENFORCE: "true"` once CLA.md is approved and add the `CLA` check to `.github/rulesets/main.json`.
7. Run `scripts/check-legal-files.sh --release`. The release gate workflow (`.github/workflows/release-gate.yml`) runs the same check on every `v*` tag and **fails while any draft marker or placeholder remains**.
8. Update the GitHub repository's licence field, README badge, and npm/Docker metadata.
9. Announce the change, state clearly that earlier versions stay Apache-2.0, and keep the Apache-2.0 text in `LICENSES/`.

## 11. What was added to the repository (licensing only)

| Area | Files |
|------|-------|
| Licence and policy documents | `LICENSE.md` (draft licence; the Apache-2.0 text moved to `LICENSES/Apache-2.0.txt`), `COMMERCIAL_LICENSE.md`, `LICENSE_FAQ.md`, `CLA.md`, `TRADEMARK_POLICY.md`, `docs/legal/*`, `docs/adr/0013-source-available-licensing.md` |
| Updated documents | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `PLAN.md`, PR template, `CODEOWNERS`, OpenAPI `info.license`, `apps/web/package.json` licence field |
| Compliance tooling | `scripts/licenses` (policy check, notice generation, header check and apply), `scripts/check-legal-files.sh`, `scripts/check-cla.sh`, `scripts/sbom.sh`, `scripts/license-texts.sh`, Makefile targets, pre-commit and pre-push steps |
| CI | `licenses` job (documents, headers, dependency policy, notice drift, CycloneDX SBOMs as an artefact); `CLA` job (reporting only); wider dependency-review deny list; `release-gate.yml` (fails on draft markers) |
| Distribution | Container images carry the licence texts under `/licenses`, an SPDX licence label, and the notice file |
| Source | SPDX identifier line at the top of every hand-written source file |

Not changed: architecture, code behaviour, APIs, schemas, the implementation plan, the technology stack and the integrations. No licence-key, activation, telemetry or limit code exists, and `scripts/check-legal-files.sh` fails if code like that is added.
