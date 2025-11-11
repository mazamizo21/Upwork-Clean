// =============================================================================
// Logic App - TacitRed Data Ingestion to Sentinel
// Polls TacitRed API and sends data to DCE using Logs Ingestion API
// =============================================================================

@description('Logic App name')
param logicAppName string = 'logic-tacitred-ingestion'

@description('Location for resources')
param location string = resourceGroup().location

@description('TacitRed API key')
@secure()
param tacitRedApiKey string

@description('TacitRed API base URL')
param tacitRedApiUrl string = 'https://app.tacitred.com/api/v1'

@description('DCR Immutable ID')
param dcrImmutableId string

@description('DCE Ingestion Endpoint')
param dceEndpoint string

@description('Stream name for ingestion')
param streamName string = 'Custom-TacitRed_Findings_CL'

@description('Polling interval in minutes')
param pollingIntervalMinutes int = 15

@description('Tags for the resource')
param tags object = {
  Solution: 'TacitRed-Sentinel-Integration'
  ManagedBy: 'Bicep'
}

// Logic App with managed identity
resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        tacitRedApiKey: {
          type: 'securestring'
        }
        tacitRedApiUrl: {
          type: 'string'
        }
        dcrImmutableId: {
          type: 'string'
        }
        dceEndpoint: {
          type: 'string'
        }
        streamName: {
          type: 'string'
        }
      }
      triggers: {
        Recurrence: {
          type: 'Recurrence'
          recurrence: {
            frequency: 'Minute'
            interval: pollingIntervalMinutes
          }
        }
      }
      actions: {
        Initialize_Query_Window: {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'queryWindowMinutes'
                type: 'integer'
                value: 302
              }
            ]
          }
          runAfter: {}
        }
        Calculate_From_Time: {
          type: 'Compose'
          inputs: '2025-10-26T14:00:00Z'
          runAfter: {
            Initialize_Query_Window: [
              'Succeeded'
            ]
          }
        }
        Calculate_Until_Time: {
          type: 'Compose'
          inputs: '2025-10-26T20:00:00Z'
          runAfter: {
            Calculate_From_Time: [
              'Succeeded'
            ]
          }
        }
        Call_TacitRed_API: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '@{parameters(\'tacitRedApiUrl\')}/findings?from=@{outputs(\'Calculate_From_Time\')}&until=@{outputs(\'Calculate_Until_Time\')}&page_size=100'
            headers: {
              Authorization: '@parameters(\'tacitRedApiKey\')'
              Accept: 'application/json'
              'User-Agent': 'LogicApp-Sentinel-TacitRed-Ingestion/1.0'
            }
          }
          runAfter: {
            Calculate_Until_Time: [
              'Succeeded'
            ]
          }
        }
        Send_to_DCE: {
          type: 'Http'
          inputs: {
            method: 'POST'
            uri: '@{parameters(\'dceEndpoint\')}/dataCollectionRules/@{parameters(\'dcrImmutableId\')}/streams/@{parameters(\'streamName\')}?api-version=2023-01-01'
            headers: {
              'Content-Type': 'application/json'
            }
            body: '@body(\'Call_TacitRed_API\')?[\'results\']'
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://monitor.azure.com/'
            }
          }
          runAfter: {
            Call_TacitRed_API: [
              'Succeeded'
            ]
          }
        }
        Log_Result: {
          type: 'Compose'
          inputs: {
            status: 'completed'
            timestamp: '@utcNow()'
            recordCount: '@length(body(\'Call_TacitRed_API\')?[\'results\'])'
            message: 'TacitRed ingestion completed'
          }
          runAfter: {
            Send_to_DCE: [
              'Succeeded'
            ]
          }
        }
      }
      outputs: {}
    }
    parameters: {
      tacitRedApiKey: {
        value: tacitRedApiKey
      }
      tacitRedApiUrl: {
        value: tacitRedApiUrl
      }
      dcrImmutableId: {
        value: dcrImmutableId
      }
      dceEndpoint: {
        value: dceEndpoint
      }
      streamName: {
        value: streamName
      }
    }
  }
}

output logicAppId string = logicApp.id
output logicAppName string = logicApp.name
output principalId string = logicApp.identity.principalId
output identityType string = logicApp.identity.type
