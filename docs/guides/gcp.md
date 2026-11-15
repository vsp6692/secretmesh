# Google Cloud setup

SecretMesh manages Google Cloud Secret Manager by impersonating a service account that you own in each project (ADR-0012). The deployment never holds customer credentials, and never accepts a key file.

> **Status:** verified against an in-process fake of the Secret Manager and IAM Credentials REST APIs only. It has not been run against live Google Cloud, so IAM evaluation, IAM Conditions, VPC Service Controls and organization policies are unconfirmed. Treat the first real connection as a test, in a non-production project.

## What SecretMesh stores in your project, and what it never stores

SecretMesh keeps no secret values (ADR-0003). Inside your project it creates only:

| Object | Purpose | Lifetime |
|--------|---------|----------|
| Secret `secretmesh-external-id` | Proves the project belongs to the connection. You create it | Permanent |
| Secret `smstaging-<request id>` | Holds a proposed value until approval (creates and updates) | Deleted when the request finishes |
| Annotations `secretmesh-*` on managed secrets | Idempotency records (see below) | Permanent |
| Label `secretmesh-managed=true` | On secrets SecretMesh created | Permanent |

## 1. SecretMesh's own identity

SecretMesh authenticates with Application Default Credentials and must be keyless:

- **GKE Workload Identity** (preferred on GKE), or
- **Workload Identity Federation** from another cloud, Kubernetes or an OIDC provider, or
- a service account **attached** to the compute resource that runs SecretMesh.

If `GOOGLE_APPLICATION_CREDENTIALS` points at a service account **key file**, SecretMesh refuses to start the GCP connector. Keys are long-lived credentials that can be copied. (A development-only override exists in code for local testing; there is no setting for it in production.)

| Setting | Default | Meaning |
|---------|---------|---------|
| `SECRETMESH_ENABLE_GCP_CONNECTOR` | `false` | Register the GCP provider |
| `SECRETMESH_GCP_ENDPOINT_URL` | unset | Emulators only. Never set in production |

SecretMesh's identity needs exactly one permission on each customer service account: `iam.serviceAccounts.getAccessToken`, granted through `roles/iam.serviceAccountTokenCreator` on that service account only (never on the project).

## 2. Connect a project

1. In SecretMesh, a `cloud_admin` creates the connection with `project_id` and `service_account`. SecretMesh generates the `external_id` and rejects one you supply.

   | Setting | Example |
   |---------|---------|
   | `project_id` | `my-project-123` |
   | `service_account` | `secretmesh-connector@my-project-123.iam.gserviceaccount.com` |
   | `external_id` | generated: `secretmesh-<32 hex>` |

   No other settings are accepted: no key files, tokens or endpoints.

2. Apply `deployments/gcp/connector-role.tf` in the project:

   ```sh
   terraform apply -var project_id=my-project-123 \
     -var 'secretmesh_principal=serviceAccount:secretmesh@host-project.iam.gserviceaccount.com' \
     -var external_id=<external_id from the connection> \
     -var secret_name_prefix=app-
   ```

   It creates the service account (without keys), two custom roles, the bindings, the token-creator grant and the marker secret. The file has not been applied against a live project; run `terraform plan` first.

   Without Terraform, create the marker by hand. The value must be exactly the external ID:

   ```sh
   printf '%s' "$EXTERNAL_ID" | gcloud secrets create secretmesh-external-id \
     --project my-project-123 --replication-policy automatic --data-file=-
   ```

3. Click **Sync** on the connection, or wait up to 15 minutes. An access-denied error appears on the connection as "check the service account binding, external ID and permissions".

### Why the marker secret exists

Google has no equivalent of the AWS `ExternalId`. In a shared SecretMesh deployment, one SecretMesh identity may be trusted by many customers, so a user of one organization could name another customer's service account and project in a connection. Before every first use, and again every 15 minutes, SecretMesh reads `secretmesh-external-id` and compares it, in constant time, to the connection's generated `external_id`. A missing or different value means the connection does not own the project, and every call fails with access denied. Delete the marker, or change its value, to cut off SecretMesh immediately, even before you remove the token-creator grant.

## 3. Permissions

The custom roles contain only what the connector calls:

| Permission | Used for |
|------------|----------|
| `secretmanager.secrets.create` | Staging secrets, new managed secrets |
| `secretmanager.secrets.get`, `.update` | Reading and writing labels and annotations |
| `secretmanager.secrets.list` | Discovery (names and labels only) |
| `secretmanager.secrets.delete` | Deleting SecretMesh's own staging secrets. Never used on managed secrets |
| `secretmanager.versions.add` | Writing values |
| `secretmanager.versions.access` | Reading staged values and revealing (with step-up) |
| `secretmanager.versions.get`, `.list` | Version history and discovery |
| `secretmanager.versions.disable` | Soft delete |

Not granted: `secretmanager.versions.destroy`, `.enable`, `secretmanager.secrets.setIamPolicy`, and anything outside Secret Manager. SecretMesh cannot change IAM, destroy a version or read other services.

**Limiting names.** `secret_name_prefix` adds an IAM Condition to the management role: SecretMesh can then only touch secrets whose name starts with the prefix, plus `smstaging-*` and the marker. Listing is evaluated against the project, so IAM conditions cannot hide secret names from discovery. SecretMesh can always see the names and labels of every secret in the project, but never their values. For a hard boundary, put the managed secrets in a dedicated project.

## 4. Placing discovered secrets

Label secrets in Google Cloud. Label values may only contain lowercase letters, digits, `_` and `-`, so use lowercase environment names:

| Label | Value |
|-------|-------|
| `secretmesh-environment` | Name of a SecretMesh environment, such as `prod` |
| `secretmesh-classification` | `internal`, `confidential` (default) or `restricted` |

They are read as SecretMesh's `secretmesh:environment` and `secretmesh:classification` tags. Other labels are kept as tags unchanged. Untagged secrets go to the connection's default environment; without one they are skipped and counted as unassigned. Moving a secret afterwards does not change its environment in SecretMesh.

## 5. What you will see in Google Cloud

- **Pending changes:** a secret `smstaging-<request id>` with labels `secretmesh-staging=true` and `secretmesh-request=<id>`. The target secret is untouched until approval; consumers reading `latest` see no change.
- **After approval:** a new version of the target secret, and annotations on the target:
  - `secretmesh-intent-op=<journal id>` written before the version is added,
  - `secretmesh-applied-op=<journal id>` and `secretmesh-applied-version=<n>` after.
  A retry of the same operation returns the recorded version, or recognises a version whose recording was interrupted by comparing the latest value with the staged one, so one approval never creates two versions.
- **Orphans:** if a crash leaves a staging secret behind, the periodic sync deletes it an hour after creation, provided no pending, approved or executing request owns it. Only secrets that carry the staging label, the `smstaging-` prefix and a request ID are ever deleted this way.
- **Audit logs:** enable Data Access audit logs for Secret Manager. Entries show the impersonated service account, with SecretMesh's identity in `serviceAccountDelegationInfo`. Token creation appears in the IAM Credentials audit log. Secret versions have a 64 KiB limit; larger values are rejected before any write.

## 6. Deletes are soft

Secret Manager deletes are permanent and destroy every version. A SecretMesh delete therefore does not call the API's delete: it labels the secret `secretmesh-deleted=true`, records `secretmesh-deleted-at`, and **disables** every version. Consumers then fail to read it, SecretMesh hides it, and nothing is destroyed.

A deleted secret keeps its name. Creating a secret with the same name through SecretMesh fails with a conflict until an administrator purges it:

```sh
# Undo: re-enable the versions and remove the label.
gcloud secrets versions enable <n> --secret NAME
gcloud secrets update NAME --remove-labels secretmesh-deleted

# Purge for good, only once you are sure:
gcloud secrets delete NAME
```

## 7. Limitations

- Verified against an in-process fake only (see the status note).
- Organization policies can block staging secrets. `constraints/gcp.restrictNonCmekServices` forbids secrets without a customer-managed key, and `constraints/gcp.resourceLocations` can forbid automatic replication. SecretMesh creates secrets with automatic replication and does not yet support CMEK or user-managed replication.
- VPC Service Controls: if Secret Manager is inside a perimeter, add an ingress rule that allows SecretMesh's identity or network, and an egress rule if SecretMesh runs inside another perimeter.
- Native rotation (Secret Manager rotation schedules publish to Pub/Sub) is not supported. Use manual rotation policies in SecretMesh.
- Google annotations are limited to 16 KiB per secret and labels to 64 per secret. SecretMesh uses fewer than ten of each.
- `latest` is the newest version. If someone disables the newest version, SecretMesh treats the secret as having no readable value.
