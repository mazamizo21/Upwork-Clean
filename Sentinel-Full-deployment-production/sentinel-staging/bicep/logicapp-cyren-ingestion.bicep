// =============================================================================
// Logic App - Cyren Indicators Ingestion to Sentinel
// Polls Cyren API and sends data to DCE using Logs Ingestion API (MSI auth)
// =============================================================================

@description('Logic App name')
param logicAppName string = 'logic-cyren-ingestion'

@description('Location for resources')
param location string = resourceGroup().location

@description('Cyren API Bearer token (JWT)')
@secure()
param cyrenApiToken string

@description('Cyren API base URL')
param cyrenApiUrl string = 'http://api-url.cyren.com'

@description('DCR Immutable ID')
param dcrImmutableId string

@description('DCE Ingestion Endpoint')
param dceEndpoint string

@description('Stream name for ingestion')
param streamName string = 'Custom-Cyren_Indicators_CL'

@description('Polling interval in minutes')
param pollingIntervalMinutes int = 15

@description('Tags for the resource')
param tags object = {
  Solution: 'Cyren-Sentinel-Integration'
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
        cyrenApiToken: {
          type: 'securestring'
        }
        cyrenApiUrl: {
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
        Calculate_From_Time: {
          type: 'Compose'
          inputs: '@{addMinutes(utcNow(), -360)}'
          runAfter: {}
        }
        Calculate_Until_Time: {
          type: 'Compose'
          inputs: '@utcNow()'
          runAfter: {
            Calculate_From_Time: [
              'Succeeded'
            ]
          }
        }
        Call_Cyren_API: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '@{parameters(''cyrenApiUrl'')}/indicators?since=@{outputs(''Calculate_From_Time'')}&until=@{outputs(''Calculate_Until_Time'')}'
            headers: {
              Authorization: 'Bearer @{parameters(''cyrenApiToken'')}'
              Accept: 'application/json'
              'User-Agent': 'LogicApp-Sentinel-Cyren-Ingestion/1.0'
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
            uri: '@{parameters(''dceEndpoint'')}/dataCollectionRules/@{parameters(''dcrImmutableId'')}/streams/@{parameters(''streamName'')}?api-version=2023-01-01'
            headers: {
              'Content-Type': 'application/json'
            }
            // Most Cyren responses return an array at root; if not, you may need to adjust to select the correct JSON path
            body: '@body(''Call_Cyren_API'')'
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://monitor.azure.com/'
            }
          }
          runAfter: {
            Call_Cyren_API: [
              'Succeeded'
            ]
          }
        }
        Log_Result: {
          type: 'Compose'
          inputs: {
            status: 'completed'
            timestamp: '@utcNow()'
            recordCount: '@length(body(''Call_Cyren_API''))'
            message: 'Cyren ingestion completed'
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
      cyrenApiToken: {
        value: cyrenApiToken
      }
      cyrenApiUrl: {
        value: cyrenApiUrl
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
