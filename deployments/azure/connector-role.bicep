// Custom role and assignment that let SecretMesh manage secrets in ONE Azure
// Key Vault (ADR-0012, docs/guides/azure.md).
//
// Deploy into the resource group that contains the vault:
//   az deployment group create -g <resource group> -f connector-role.bicep \
//     -p vaultName=<vault> secretMeshPrincipalId=<object id of SecretMesh's service principal>
//
// The vault must use the Azure RBAC permission model (not access policies).
// This template has not been deployed against a live subscription; review the
// role before using it.
targetScope = 'resourceGroup'

@description('Name of the existing Key Vault. It must use Azure RBAC authorization.')
param vaultName string

@description('Object ID of SecretMesh\'s service principal in this tenant (the enterprise application created when consent was granted, or the managed identity).')
param secretMeshPrincipalId string

@description('Name of the custom role. Keep it unique in the subscription.')
param roleName string = 'SecretMesh Key Vault connector'

@description('Allow purging only for secrets named smstaging-*, using an ABAC condition. Purging is how SecretMesh removes staged values; targets are never purged. Leave off if your tenant does not support role assignment conditions on Key Vault.')
param restrictPurgeToStaging bool = false

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: vaultName
}

// Everything SecretMesh does through the data plane: read and write secret
// values, list names, tags and versions, soft-delete, and purge staged values.
// It gets no key, certificate or vault-management permissions.
var dataActions = [
  'Microsoft.KeyVault/vaults/secrets/getSecret/action'
  'Microsoft.KeyVault/vaults/secrets/setSecret/action'
  'Microsoft.KeyVault/vaults/secrets/readMetadata/action'
  'Microsoft.KeyVault/vaults/secrets/delete'
  'Microsoft.KeyVault/vaults/secrets/purge/action'
]

resource role 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, roleName)
  properties: {
    roleName: roleName
    description: 'Lets SecretMesh stage, promote, read and soft-delete secrets in a Key Vault. No key or certificate access.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        notActions: []
        dataActions: dataActions
        notDataActions: []
      }
    ]
    assignableScopes: [
      resourceGroup().id
    ]
  }
}

var purgeCondition = '(!(ActionMatches{\'Microsoft.KeyVault/vaults/secrets/purge/action\'}) OR @Resource[Microsoft.KeyVault/vaults/secrets:name] StringStartsWith \'smstaging-\')'

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, secretMeshPrincipalId, role.id)
  properties: {
    roleDefinitionId: role.id
    principalId: secretMeshPrincipalId
    principalType: 'ServicePrincipal'
    condition: restrictPurgeToStaging ? purgeCondition : null
    conditionVersion: restrictPurgeToStaging ? '2.0' : null
  }
}

output roleDefinitionId string = role.id
output vaultUrl string = vault.properties.vaultUri
