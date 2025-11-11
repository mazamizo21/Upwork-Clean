// Assign Monitoring Metrics Publisher role to connector's managed identity
@description('Connector resource ID')
param connectorResourceId string

@description('DCR resource ID')
param dcrResourceId string

@description('DCE resource ID')
param dceResourceId string

// Parse connector resource ID
var connectorIdParts = split(connectorResourceId, '/')
var connectorSubscriptionId = connectorIdParts[2]
var connectorResourceGroup = connectorIdParts[4]
var connectorWorkspace = connectorIdParts[8]
var connectorName = connectorIdParts[12]

// Get connector to access its managed identity
resource connector 'Microsoft.OperationalInsights/workspaces/providers/dataConnectors@2023-02-01-preview' existing = {
  name: '${connectorWorkspace}/Microsoft.SecurityInsights/${connectorName}'
  scope: resourceGroup(connectorSubscriptionId, connectorResourceGroup)
}

// Get DCR
resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' existing = {
  name: last(split(dcrResourceId, '/'))
  scope: resourceGroup(split(dcrResourceId, '/')[4])
}

// Get DCE
resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' existing = {
  name: last(split(dceResourceId, '/'))
  scope: resourceGroup(split(dceResourceId, '/')[4])
}

// Monitoring Metrics Publisher role definition ID
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

// Assign role to DCR (deployed as extension resource)
resource dcrRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcrResourceId, connectorResourceId, 'MonitoringMetricsPublisher-DCR')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: connector.identity.principalId
    principalType: 'ServicePrincipal'
    scope: dcrResourceId
  }
}

// Assign role to DCE (deployed as extension resource)
resource dceRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dceResourceId, connectorResourceId, 'MonitoringMetricsPublisher-DCE')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalId: connector.identity.principalId
    principalType: 'ServicePrincipal'
    scope: dceResourceId
  }
}

output dcrRoleAssignmentId string = dcrRoleAssignment.id
output dceRoleAssignmentId string = dceRoleAssignment.id
