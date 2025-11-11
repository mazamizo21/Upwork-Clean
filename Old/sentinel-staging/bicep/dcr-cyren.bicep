// =============================================================================
// Data Collection Rule for Cyren Indicators
// Direct ingestion endpoint (no DCE required unless Private Link needed)
// =============================================================================

@description('DCR name')
param dcrName string = 'dcr-cyren-indicators'

@description('DCR location')
param location string = resourceGroup().location

@description('Target Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Optional Data Collection Endpoint resource ID to bind this DCR to')
param dceResourceId string = ''

@description('Stream name for custom table')
param streamName string = 'Custom-Cyren_Indicators_CL'

@description('Tags for the resource')
param tags object = {}

// Parse workspace name from resource ID
var workspaceName = last(split(workspaceResourceId, '/'))
var workspaceSubscriptionId = split(workspaceResourceId, '/')[2]
var workspaceResourceGroup = split(workspaceResourceId, '/')[4]

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  tags: tags
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: empty(dceResourceId) ? null : dceResourceId
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'url_s', type: 'string' }
          { name: 'ip_s', type: 'string' }
          { name: 'fileHash_s', type: 'string' }
          { name: 'domain_s', type: 'string' }
          { name: 'protocol_s', type: 'string' }
          { name: 'port_d', type: 'int' }
          { name: 'category_s', type: 'string' }
          { name: 'risk_d', type: 'int' }
          { name: 'firstSeen_t', type: 'datetime' }
          { name: 'lastSeen_t', type: 'datetime' }
          { name: 'source_s', type: 'string' }
          { name: 'relationships_s', type: 'string' }
          { name: 'detection_methods_s', type: 'string' }
          { name: 'action_s', type: 'string' }
          { name: 'type_s', type: 'string' }
          { name: 'identifier_s', type: 'string' }
          { name: 'detection_ts_t', type: 'datetime' }
          { name: 'object_type_s', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'clv2ws1'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'clv2ws1'
        ]
        transformKql: loadTextContent('../dcr/cyren-dcr-transformation.kql')
        outputStream: streamName
      }
    ]
  }
}

// Grant permissions to the workspace
resource workspacePermission 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dataCollectionRule.id, workspaceResourceId, 'MonitoringMetricsPublisher')
  scope: dataCollectionRule
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb') // Monitoring Metrics Publisher
    principalId: reference(workspaceResourceId, '2022-10-01', 'Full').identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output dcrId string = dataCollectionRule.id
output dcrImmutableId string = dataCollectionRule.properties.immutableId
output dcrName string = dataCollectionRule.name
output streamName string = streamName
