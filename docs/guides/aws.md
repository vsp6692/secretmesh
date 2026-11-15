# AWS setup

SecretMesh manages AWS Secrets Manager by assuming an IAM role in each account (ADR-0010). The deployment never holds customer credentials.

## 1. SecretMesh's own identity

SecretMesh uses the default AWS credential chain: an EKS service account (IRSA or Pod Identity), an ECS task role or an EC2 instance profile. It needs only `sts:AssumeRole` on the connector roles, plus the KMS and S3 permissions below if you enable them. Never use long-lived access keys outside local development.

| Setting | Default | Meaning |
|---------|---------|---------|
| `SECRETMESH_ENABLE_AWS_CONNECTOR` | `true` | Register the AWS provider |
| `SECRETMESH_AWS_ENDPOINT_URL` | unset | Emulators only (Moto, LocalStack). Never set in production |

## 2. Connector role (per account)

1. In SecretMesh, a `cloud_admin` creates the connection. Provide `role_arn` and `region`, plus optionally a default environment for discovered secrets that have no environment tag. SecretMesh generates the `external_id` and rejects one you supply.
2. Deploy `deployments/aws/connector-role.yaml` in the target account:

   ```sh
   aws cloudformation deploy --stack-name secretmesh-connector \
     --template-file deployments/aws/connector-role.yaml --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides SecretMeshPrincipalArn=arn:aws:iam::111111111111:role/secretmesh \
       ExternalId=<external_id from the connection> SecretNamePrefix='app/*'
   ```

   The template has three parameters:
   - `SecretNamePrefix` limits which secrets SecretMesh can manage. `secretmesh-staging/*` is always included because creates are staged there.
   - `KmsKeyArns` grants decrypt and encrypt (through Secrets Manager only) on customer-managed keys.
   - Customize the role name with `RoleName`, and keep `role_arn` in the connection matching it.
3. Click **Sync** on the connection, or wait up to 15 minutes. An access-denied error appears on the connection as "check the connection's identity, trust setup, ExternalId and permissions".

## 3. Placing discovered secrets

Tag secrets in AWS:

| Tag | Value |
|-----|-------|
| `secretmesh:environment` | Name of a SecretMesh environment, such as `prod` |
| `secretmesh:classification` | `internal`, `confidential` (default) or `restricted` |

Untagged secrets go to the connection's default environment. Without a default they are skipped and counted as unassigned. Moving a secret afterwards does not change its environment in SecretMesh, which avoids silent privilege changes.

## 4. What you will see in AWS

- **Pending updates:** a version labelled `SECRETMESH_PENDING`. Consumers keep reading `AWSCURRENT` until approval.
- **Pending creates:** a secret `secretmesh-staging/<request id>`, deleted once the request completes. If a crash leaves one behind, the periodic sync deletes it an hour after creation, provided no pending, approved or executing request owns it. Only secrets with the `secretmesh:staging` tag are ever deleted this way.
- **Deletes:** scheduled with a 7-day recovery window.
- **CloudTrail:** session name `secretmesh-<connection id prefix>`.

## 5. KMS keyring (recommended for production)

Create two keys and set `SECRETMESH_KEYRING=aws-kms`:

| Setting | Key |
|---------|-----|
| `SECRETMESH_KMS_MAC_KEY_ID` | `HMAC_256`, usage `GENERATE_VERIFY_MAC`; SecretMesh needs `kms:GenerateMac` |
| `SECRETMESH_KMS_SIGNING_KEY_ID` | `ECC_NIST_P256`, usage `SIGN_VERIFY`; SecretMesh needs `kms:Sign`, `kms:GetPublicKey` |

SecretMesh also needs `kms:DescribeKey` on both. Keep `SECRETMESH_MASTER_KEY` set when switching from the local keyring: it is then used only to verify old checkpoints. Requests still pending at the switch must be resubmitted, because their MACs were made with the old key.

## 6. Audit export (S3 Object Lock)

Deploy `deployments/aws/audit-bucket.yaml`. It creates a versioned, encrypted, private bucket with Object Lock, TLS-only access and a write-only export role. Then set:

| Setting | Default |
|---------|---------|
| `SECRETMESH_AUDIT_EXPORT_BUCKET` | unset (export disabled) |
| `SECRETMESH_AUDIT_EXPORT_REGION` | required with a bucket |
| `SECRETMESH_AUDIT_EXPORT_PREFIX` | `secretmesh-audit` |
| `SECRETMESH_AUDIT_EXPORT_MODE` | `COMPLIANCE` |
| `SECRETMESH_AUDIT_EXPORT_RETENTION_DAYS` | `365` |
| `SECRETMESH_AUDIT_EXPORT_ROLE_ARN` | unset; the `ExportRoleArn` output |

Each object is `<prefix>/<org>/<from>-<to>.jsonl`: one event per line, then the signed checkpoint. COMPLIANCE retention cannot be shortened by anyone, including the account root.

## Local development

`make deps-up` starts Moto on `127.0.0.1:5050`, and `.env` points SecretMesh at it with dummy credentials. Moto accepts any role and ExternalId, so it does not exercise IAM.
