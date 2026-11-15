# SecretMesh connector for Google Cloud Secret Manager (ADR-0012).
#
# Creates, in the customer project:
#   - a service account that SecretMesh impersonates (no keys are ever created),
#   - two custom roles with only the permissions the connector uses,
#   - bindings of those roles to the service account (optionally limited to a
#     secret name prefix with an IAM Condition),
#   - roles/iam.serviceAccountTokenCreator on that service account for the
#     SecretMesh principal,
#   - the marker secret "secretmesh-external-id" that proves this project
#     belongs to the SecretMesh connection (confused-deputy protection).
#
# This file has been written against the documented provider schema but has
# not been applied against a live project. Run `terraform plan` and review it
# before applying.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project_id" {
  type        = string
  description = "Project that holds the secrets SecretMesh manages. Use as project_id in the connection."
}

variable "secretmesh_principal" {
  type        = string
  description = <<-EOT
    The identity SecretMesh runs as, in IAM member format. Examples:
      serviceAccount:secretmesh@secretmesh-host.iam.gserviceaccount.com
      principal://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/subject/ns/secretmesh/sa/secretmesh
  EOT
}

variable "external_id" {
  type        = string
  description = "The external_id SecretMesh generated for the connection (secretmesh-...)."

  validation {
    condition     = startswith(var.external_id, "secretmesh-")
    error_message = "Use the external_id shown on the SecretMesh connection."
  }
}

variable "service_account_id" {
  type        = string
  default     = "secretmesh-connector"
  description = "Account ID of the service account SecretMesh impersonates. Use <id>@<project>.iam.gserviceaccount.com as service_account in the connection."
}

variable "secret_name_prefix" {
  type        = string
  default     = ""
  description = <<-EOT
    Limit SecretMesh to secrets whose name starts with this prefix (plus its own
    staging secrets and the marker). Empty means every secret in the project.
    Listing secrets cannot be limited by name: SecretMesh can always see names
    and labels of all secrets in the project, never their values.
  EOT
}

variable "create_marker" {
  type        = bool
  default     = true
  description = "Create the marker secret. Set to false to create it yourself (see the guide)."
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  secrets_root = "projects/${data.google_project.this.number}/secrets/"

  # Everything except listing, which IAM only evaluates against the project.
  manage_permissions = [
    "secretmanager.secrets.create",
    "secretmanager.secrets.get",
    "secretmanager.secrets.update",
    "secretmanager.secrets.delete", # staging secrets only; SecretMesh never deletes managed secrets
    "secretmanager.versions.add",
    "secretmanager.versions.access",
    "secretmanager.versions.get",
    "secretmanager.versions.list",
    "secretmanager.versions.disable", # soft delete
  ]

  condition_expression = join(" || ", [
    "resource.name.startsWith(\"${local.secrets_root}${var.secret_name_prefix}\")",
    "resource.name.startsWith(\"${local.secrets_root}smstaging-\")",
    "resource.name.startsWith(\"${local.secrets_root}secretmesh-external-id\")",
  ])
}

resource "google_service_account" "connector" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "SecretMesh connector"
  description  = "Impersonated by SecretMesh to govern Secret Manager. Never has keys."
}

resource "google_project_iam_custom_role" "manage" {
  project     = var.project_id
  role_id     = "secretmeshConnector"
  title       = "SecretMesh connector"
  description = "Manage secrets and versions on behalf of SecretMesh. No IAM, no destroy."
  permissions = local.manage_permissions
}

resource "google_project_iam_custom_role" "list" {
  project     = var.project_id
  role_id     = "secretmeshDiscovery"
  title       = "SecretMesh discovery"
  description = "List secrets (metadata) for SecretMesh discovery."
  permissions = ["secretmanager.secrets.list"]
}

resource "google_project_iam_member" "manage" {
  project = var.project_id
  role    = google_project_iam_custom_role.manage.id
  member  = "serviceAccount:${google_service_account.connector.email}"

  dynamic "condition" {
    for_each = var.secret_name_prefix == "" ? [] : [1]
    content {
      title       = "secretmesh-name-prefix"
      description = "Only secrets under the configured prefix, SecretMesh staging secrets and the marker."
      expression  = local.condition_expression
    }
  }
}

resource "google_project_iam_member" "list" {
  project = var.project_id
  role    = google_project_iam_custom_role.list.id
  member  = "serviceAccount:${google_service_account.connector.email}"
}

# Lets SecretMesh mint short-lived tokens for the service account. No key file
# is involved, and nobody else can impersonate it.
resource "google_service_account_iam_member" "secretmesh_impersonates" {
  service_account_id = google_service_account.connector.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = var.secretmesh_principal
}

resource "google_secret_manager_secret" "marker" {
  count     = var.create_marker ? 1 : 0
  project   = var.project_id
  secret_id = "secretmesh-external-id"

  labels = {
    "secretmesh-managed" = "marker"
  }

  replication {
    auto {}
  }
}

# The external ID is not a credential, but it does end up in Terraform state.
resource "google_secret_manager_secret_version" "marker" {
  count       = var.create_marker ? 1 : 0
  secret      = google_secret_manager_secret.marker[0].id
  secret_data = var.external_id
}

output "service_account" {
  value       = google_service_account.connector.email
  description = "Use as service_account in the SecretMesh connection."
}
