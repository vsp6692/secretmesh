# SecretMesh Contributor License Agreement (DRAFT PROPOSAL)

> **DRAFT: pending qualified legal review and owner approval. Not yet in force and not yet requested from contributors.** This proposal is written so that the Licensor can include contributions in SecretMesh, release SecretMesh under the source-available licence in [LICENSE.md](LICENSE.md), and grant separate commercial licences ([COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)). It is a **licence** agreement: you keep ownership of what you write. See [docs/legal/LICENSING_STRATEGY.md](docs/legal/LICENSING_STRATEGY.md) for the licence-versus-assignment decision and for what the CLA cannot fix (contributions already made).

**Why a CLA?** A contributor who submits code under only the project's public licence gives the Licensor the right to distribute it under that licence and no more. To offer commercial licences, or to change the licence of future versions, the Licensor needs a broader grant. The CLA is that grant, stated plainly so you can see what you agree to before you submit anything.

**What it means for you, in short.**
- You keep the copyright in your contribution.
- You give the Licensor a wide licence to use it, including relicensing it and selling commercial licences to the whole of SecretMesh.
- You still may use your own contribution however you like.
- Your contribution is available to everybody under the public licence ([LICENSE.md](LICENSE.md)).
- If you contribute for an employer, your employer must allow it (section 3).

Please read it before you open a pull request.

---

## Agreement

This agreement is between **[LICENSOR_LEGAL_NAME]** ("Licensor") and the person or entity that submits a Contribution ("You"). It applies to every Contribution You submit, from the first time You submit one after this agreement takes effect.

### 1. Definitions

- **"Contribution"** means any original work of authorship, including code, tests, documentation, connectors, plugins, configuration and translations, and any modification of existing work, that You intentionally submit to the Licensor for inclusion in SecretMesh, by pull request, patch, issue attachment, email or any other means, and that is not conspicuously marked "Not a Contribution".
- **"Software"** means SecretMesh and its repository materials, as defined in [LICENSE.md](LICENSE.md).
- **"Submit"** means send in any form to the Licensor or its representatives, including by posting to the project's repository, mailing lists or issue tracker. Communications that are conspicuously marked "Not a Contribution" are not Contributions.

### 2. Grant of rights

1. **Copyright licence.** You grant the Licensor and recipients of the Software a perpetual, worldwide, non-exclusive, royalty-free, irrevocable copyright licence to reproduce, prepare derivative works of, publicly display, publicly perform, **sublicense** and distribute Your Contribution and derivative works of it, **in source or object form, under any terms the Licensor chooses**, including the terms of [LICENSE.md](LICENSE.md), any later version of it, commercial and proprietary licences, and any other licence. [OWNER DECISION: keep "any terms", or restrict to "this licence, later source-available versions of it, and commercial licences".]
2. **Patent licence.** You grant the Licensor and recipients of the Software a perpetual, worldwide, non-exclusive, royalty-free, irrevocable (except as stated here) patent licence to make, have made, use, offer to sell, sell, import and otherwise transfer the Contribution, alone or combined with the Software, where the patents are licensable by You and necessarily infringed by Your Contribution alone or in combination with the Software. If anyone sues You alleging that the Contribution or the Software infringes a patent, the patent licences You granted for that Contribution end on the date the suit starts.
3. **Moral rights.** To the extent the law allows, You waive, or agree not to assert, moral rights in the Contribution against the Licensor and its licensees. Where this cannot be waived, You consent to the uses described here.
4. **Attribution.** The Licensor will keep a record of Contributors (for example the Git history and a contributors file), but is not obliged to put Your name in a particular place.
5. **You keep your rights.** Except for the licences above, You keep ownership of Your Contribution and may use it in any way You wish, including contributing it elsewhere.

### 3. Your representations

You confirm that:

1. each Contribution is Your original creation, or You have the right to submit it under this agreement;
2. You are legally entitled to grant these rights; if Your employer or another party has rights in Your work (including under an employment, contractor or school agreement), You have obtained written permission, or that party has signed a corporate version of this agreement for You;
3. Your Contribution does not knowingly violate anyone else's rights;
4. if Your Contribution includes third-party material, it is marked with its source and licence, that licence allows its use in this project and permits the Licensor to distribute it under the terms in section 2 without violating that licence, and You have not included anything under a licence that conflicts with this project's policy ([docs/legal/THIRD_PARTY_LICENSES.md](docs/legal/THIRD_PARTY_LICENSES.md));
5. You have disclosed in the pull request any substantial part of the Contribution that was **generated with the assistance of an AI tool**, and You are satisfied that You have the right to submit it. [LEGAL REVIEW: ownership and enforceability of AI-assisted material.]

You are not expected to provide support for Your Contribution, and You may provide it "AS IS", without warranties, except as stated in this section.

### 4. Licensor's undertakings

[OWNER DECISION: choose whether to include any of the following, which are non-binding in this draft.]

1. The Licensor will keep the source code of every released version, including Your Contribution, publicly available under at least the source-available licence ([LICENSE.md](LICENSE.md)) for personal and internal use.
2. The Licensor will not use this agreement to restrict Your own use of Your Contribution.
3. The Licensor will not make You or Your organisation pay a fee for the internal use that [LICENSE.md](LICENSE.md) allows.

### 5. Employers and organisations

If You contribute on behalf of a company, the company must sign a **Corporate CLA** (same text, with the company as "You" and a list of authorised employees). [PROCESS: how corporate CLAs are signed and recorded.]

### 6. How You sign

1. Add **Signed-off-by** to every commit with `git commit -s`. This certifies the [Developer Certificate of Origin](https://developercertificate.org/) for the commit. It is **in addition to** the CLA, not a replacement.
2. State in Your first pull request: "I have read CLA.md and I agree to it for my contributions to SecretMesh." [PROCESS PLACEHOLDER: replace with the final mechanism: a signed form, a bot such as CLA Assistant, or an entry in `.github/cla-signatories.txt`.]
3. A maintainer records Your acceptance in `.github/cla-signatories.txt`. Until the CLA is approved and the process is live, CI only reports missing CLA acceptance; it does not block merging (see `scripts/check-cla.sh`).

### 7. General

1. **Term.** This agreement lasts as long as the Licensor or any of its licensees uses any Contribution. You may stop submitting at any time; the licences for Contributions already submitted remain.
2. **Governing law and courts.** [GOVERNING_LAW_AND_FORUM]
3. **Changes.** The Licensor may publish a new version of this agreement. It applies to Contributions You submit after You accept it; it does not reduce rights You kept in earlier Contributions.
4. **Entire agreement.** This is the whole agreement about Contributions. If any part is unenforceable, the rest stands.

---

*Not legal advice. Have a qualified lawyer review this before using it, particularly the relicensing grant in section 2.1, the patent clause, the AI-assistance representation and the governing-law clause.*
