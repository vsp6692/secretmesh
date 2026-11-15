# Identity provider setup

SecretMesh signs users in with any OpenID Connect provider using the authorization code flow with PKCE. Configure exactly one issuer:

| Setting | Value |
|---------|-------|
| `SECRETMESH_OIDC_ISSUER` | Issuer URL; discovery must be served at `<issuer>/.well-known/openid-configuration` |
| `SECRETMESH_OIDC_CLIENT_ID` / `_CLIENT_SECRET` | Confidential client credentials |
| Redirect URI to register | `<SECRETMESH_PUBLIC_URL>/auth/callback` |
| Scopes requested | `openid email profile` |

## What SecretMesh reads from the ID token

| Claim | Use |
|-------|-----|
| `sub` (with `iss`) | Stable user identity |
| `email` | Required. Matched against invitations and the bootstrap admin |
| `email_verified` | Invitations and bootstrap admin are honoured only for verified emails. If the claim is absent, the email counts as unverified unless `SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED=true` |
| `auth_time` | When the user last authenticated. Required for step-up; without it, sensitive operations are refused (fail closed) |
| `amr`, `acr` | MFA detection. The session counts as MFA if `amr` contains a value from `SECRETMESH_OIDC_MFA_AMR` (default `mfa,otp,hwk`) or `acr` equals a value from `SECRETMESH_OIDC_MFA_ACR` (default none) |

Step-up re-authentication sends `prompt=login` and `max_age=0`. SecretMesh accepts the result only if `auth_time` is no earlier than the start of that login (with one minute of clock skew).

Organizations can require MFA. Only enable this if your provider reports MFA in `amr` or `acr`, or nobody (including you) will be able to use the organization. SecretMesh refuses to enable it from a session without MFA.

## Keycloak

Used by the development stack (`deployments/docker/keycloak/secretmesh-realm.json`). Verified end to end, including step-up.

- Issuer: `https://<host>/realms/<realm>`.
- Keycloak sends `email_verified` and `auth_time`, and honours `max_age`.
- MFA: require OTP or WebAuthn in the browser flow, then make it visible in tokens. One option is an *Authentication Method Reference (AMR)* protocol mapper on the client, with reference values (for example `otp`) set on the authenticators. The other is mapping an authentication level to `acr` and listing it in `SECRETMESH_OIDC_MFA_ACR`. Check a real ID token to confirm the claim appears.

## Google

Not yet verified against a live Google client.

- Issuer: `https://accounts.google.com`. Create an OAuth client of type *Web application*.
- Google sends `email_verified`.
- To restrict sign-in to a Workspace domain, do it with invitations: only invited (or bootstrap) emails get any organization access. Any other Google account can sign in, but sees no organizations.
- Google ID tokens do not report MFA in `amr`, so leave *Require MFA* off and enforce 2-Step Verification in Google Workspace instead.
- Confirm that step-up works (the ID token must carry `auth_time` after `max_age=0`). If it does not, token creation and security settings will be refused.

## Microsoft Entra ID

Not yet verified against a live tenant.

- Use a **single-tenant** app registration and the tenant-specific issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`. Multi-tenant issuers (`/common`, `/organizations`, `/consumers`) are rejected when `SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED=true`, because users outside your tenant could present an email they do not own.
- Add the optional `email` claim to the ID token (*Token configuration → Add optional claim*).
- Entra does not send `email_verified`. Within a single tenant, administrators control the email attribute, so set `SECRETMESH_OIDC_ASSUME_EMAIL_VERIFIED=true`.
- MFA: Entra reports authentication methods in `amr` (for example `mfa`) when MFA was performed. Enforce MFA with Conditional Access and inspect a real ID token before enabling *Require MFA*.
