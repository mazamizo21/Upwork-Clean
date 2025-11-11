// =============================================================================
// Data Collection Rule for TacitRed Findings
// Direct ingestion endpoint (no DCE required unless Private Link needed)
// =============================================================================

@description('DCR name')
param dcrName string = 'dcr-tacitred-findings'

@description('DCR location')
param location string = resourceGroup().location

@description('Target Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Optional Data Collection Endpoint resource ID to bind this DCR to')
param dceResourceId string = ''

@description('Stream name for custom table')
param streamName string = 'Custom-TacitRed_Findings_CL'

@description('Tags for the resource')
param tags object = {}

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  kind: 'Direct'
  properties: {
    dataCollectionEndpointId: empty(dceResourceId) ? null : dceResourceId
    streamDeclarations: {
      '${streamName}': {
        columns: [
          { name: 'activity_id', type: 'int' }
          { name: 'category_uid', type: 'int' }
          { name: 'class_id', type: 'int' }
          { name: 'finding', type: 'dynamic' }
          { name: 'severity', type: 'string' }
          { name: 'severity_id', type: 'int' }
          { name: 'state_id', type: 'int' }
          { name: 'time', type: 'datetime' }
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
        transformKql: loadTextContent('../dcr/tacitred-dcr-transformation.kql')
        outputStream: streamName
      }
    ]
  }
}

output dcrId string = dataCollectionRule.id
output dcrImmutableId string = dataCollectionRule.properties.immutableId
output dcrName string = dataCollectionRule.name
output streamName string = streamName
