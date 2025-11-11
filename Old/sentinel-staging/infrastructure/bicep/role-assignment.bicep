// =============================================================================
// Role Assignment Module
// Assigns a role to a principal on a target resource
// =============================================================================

@description('Principal ID (object ID) to assign the role to')
param principalId string

@description('Role Definition ID (GUID)')
param roleDefinitionId string

@description('Target resource ID to assign the role on')
param targetResourceId string

@description('Principal type')
@allowed([
  'ServicePrincipal'
  'User'
  'Group'
])
param principalType string = 'ServicePrincipal'

// Parse the target resource ID to get the resource type and name
var resourceIdParts = split(targetResourceId, '/')
var resourceType = '${resourceIdParts[6]}/${resourceIdParts[7]}'
var resourceName = resourceIdParts[8]

// Reference the target resource
resource targetResource 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' existing = {
  name: resourceName
}

// Create role assignment
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(targetResourceId, principalId, roleDefinitionId)
  scope: targetResource
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
    principalId: principalId
    principalType: principalType
  }
}

output roleAssignmentId string = roleAssignment.id
output roleAssignmentName string = roleAssignment.name
