// =============================================================================
// Logic App - Cyren IP Reputation Feed Ingestion
// Polls Cyren IP Reputation API and sends data to DCE using Logs Ingestion API
// =============================================================================

@description('Logic App name')
param logicAppName string = 'logic-cyren-ip-reputation'

@description('Location for resources')
param location string = resourceGroup().location

@description('Cyren IP Reputation JWT token')
@secure()
param cyrenIpReputationToken string

@description('Cyren API base URL')
param cyrenApiBaseUrl string = 'https://api-feeds.cyren.com/v1/feed/data'

@description('Cyren IP Reputation feed ID')
param cyrenIpReputationFeedId string = 'ip_reputation'

@description('DCR Immutable ID')
param dcrImmutableId string

@description('DCE Ingestion Endpoint')
param dceEndpoint string

@description('Stream name for ingestion')
param streamName string = 'Custom-Cyren_IpReputation_CL'

@description('Fetch count per request')
param fetchCount int = 10000

@description('Polling interval in hours')
param pollingIntervalHours int = 6

// Logic App with managed identity
resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        cyrenToken: {
          type: 'securestring'
        }
        cyrenApiUrl: {
          type: 'string'
        }
        feedId: {
          type: 'string'
        }
        fetchCount: {
          type: 'int'
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
            frequency: 'Hour'
            interval: pollingIntervalHours
          }
        }
      }
      actions: {
        Initialize_Offset: {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'offset'
                type: 'integer'
                value: 0
              }
            ]
          }
          runAfter: {}
        }
        Initialize_Records: {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'records'
                type: 'array'
                value: []
              }
            ]
          }
          runAfter: {
            Initialize_Offset: [
              'Succeeded'
            ]
          }
        }
        Fetch_Feed_Data: {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '@{parameters(\'cyrenApiUrl\')}?feedId=@{parameters(\'feedId\')}&offset=@{variables(\'offset\')}&count=@{parameters(\'fetchCount\')}&format=jsonl'
            headers: {
              Authorization: 'Bearer @{parameters(\'cyrenToken\')}'
            }
          }
          runAfter: {
            Initialize_Records: [
              'Succeeded'
            ]
          }
        }
        Process_JSONL: {
          type: 'Compose'
          inputs: '@if(or(equals(body(\'Fetch_Feed_Data\'), null), equals(body(\'Fetch_Feed_Data\'), \'\')), json(\'[]\'), split(string(body(\'Fetch_Feed_Data\')), decodeUriComponent(\'%0A\')))'
          runAfter: {
            Fetch_Feed_Data: [
              'Succeeded'
            ]
          }
        }
        Filter_Empty_Lines: {
          type: 'Query'
          inputs: {
            from: '@outputs(\'Process_JSONL\')'
            where: '@not(equals(trim(item()), \'\'))'
          }
          runAfter: {
            Process_JSONL: [
              'Succeeded'
            ]
          }
        }
        For_Each_Line: {
          type: 'Foreach'
          foreach: '@body(\'Filter_Empty_Lines\')'
          actions: {
            Parse_JSON_Line: {
              type: 'ParseJson'
              inputs: {
                content: '@items(\'For_Each_Line\')'
                schema: {
                  type: 'object'
                  properties: {}
                }
              }
            }
            Append_Record: {
              type: 'AppendToArrayVariable'
              inputs: {
                name: 'records'
                value: '@body(\'Parse_JSON_Line\')'
              }
              runAfter: {
                'Parse_JSON_Line': [
                  'Succeeded'
                ]
              }
            }
          }
          runAfter: {
            Filter_Empty_Lines: [
              'Succeeded'
            ]
          }
          runtimeConfiguration: {
            concurrency: {
              repetitions: 1
            }
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
            body: '@variables(\'records\')'
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://monitor.azure.com/'
            }
          }
          runAfter: {
            For_Each_Line: [
              'Succeeded'
            ]
          }
        }
      }
      outputs: {}
    }
    parameters: {
      cyrenToken: {
        value: cyrenIpReputationToken
      }
      cyrenApiUrl: {
        value: cyrenApiBaseUrl
      }
      feedId: {
        value: cyrenIpReputationFeedId
      }
      fetchCount: {
        value: fetchCount
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

// Monitoring Metrics Publisher role ID
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

// Reference existing DCR and DCE for RBAC assignments
resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' existing = {
  name: last(split(dcrImmutableId, '-')[0])
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' existing = {
  name: last(split(dceEndpoint, '/')[2])
}

// Role assignment name includes deployment uniqueness to avoid update conflicts on recreate
resource roleAssignmentDcr 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, logicApp.name, monitoringMetricsPublisherRoleId, uniqueString(deployment().name))
  scope: dcr
  properties: {
    principalId: logicApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
  }
  dependsOn: [
    logicApp
  ]
}

resource roleAssignmentDce 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dce.id, logicApp.name, monitoringMetricsPublisherRoleId, uniqueString(deployment().name))
  scope: dce
  properties: {
    principalId: logicApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
  }
  dependsOn: [
    logicApp
  ]
}
