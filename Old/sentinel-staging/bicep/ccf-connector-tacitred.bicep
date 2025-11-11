// =============================================================================
// Codeless Connector Framework (CCF) - TacitRed
// RestApiPoller connector with API Key authentication
// =============================================================================

@description('Workspace name for Sentinel')
param workspaceName string

@description('Workspace resource group (if different from current RG)')
param workspaceResourceGroup string = resourceGroup().name

@description('Location for resources')
param location string = resourceGroup().location

@description('Connector name')
param connectorName string = 'ccf-tacitred'

@description('TacitRed API base URL')
param apiBaseUrl string

@secure()
@description('TacitRed API key')
param apiKey string

@description('Immutable ID of TacitRed DCR')
param dcrImmutableId string

@description('Stream name')
param streamName string = 'Custom-TacitRed_Findings_CL'

@description('DCE ingestion endpoint (e.g. https://dce-name.region.ingest.monitor.azure.com)')
param dceIngestionEndpoint string

@description('DCE resource ID for role assignment')
param dceResourceId string

@description('Polling window in minutes')
param queryWindowInMin int = 43200

@description('Maximum batch size for events')
param maximumBatchSize int = 1000

// Reference existing workspace (potentially in different RG)
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
  scope: resourceGroup(workspaceResourceGroup)
}

// Create the data connector definition
resource connectorDefinition 'Microsoft.OperationalInsights/workspaces/providers/dataConnectorDefinitions@2022-12-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/${connectorName}-definition'
  kind: 'Customizable'
  properties: {
    connectorUiConfig: {
      id: '${connectorName}-definition'
      title: 'TacitRed Compromised Credentials (CCF)'
      publisher: 'TacitRed'
      descriptionMarkdown: 'Ingest compromised email and domain findings including credential leaks, domain takeovers, and identity compromise indicators.'
      graphQueriesTableName: 'TacitRed_Findings_CL'
      graphQueries: [
        {
          metricName: 'Total TacitRed findings received'
          legend: 'TacitRed Findings'
          baseQuery: 'TacitRed_Findings_CL'
        }
      ]
      sampleQueries: [
        {
          description: 'All TacitRed findings from last 7 days'
          query: 'TacitRed_Findings_CL\\n| where TimeGenerated >= ago(7d)\\n| project TimeGenerated, email_s, domain_s, findingType_s, confidence_d'
        }
        {
          description: 'Compromised credentials by domain'
          query: 'TacitRed_Findings_CL\\n| where findingType_s == "compromised_credential"\\n| summarize CompromisedUsers = dcount(email_s) by domain_s\\n| order by CompromisedUsers desc'
        }
      ]
      dataTypes: [
        {
          name: 'TacitRed_Findings_CL'
          lastDataReceivedQuery: 'TacitRed_Findings_CL\n| summarize Time = max(TimeGenerated)\n| where isnotempty(Time)'
        }
      ]
      connectivityCriteria: [
        {
          type: 'HasDataConnectors'
          value: []
        }
      ]
      availability: {
        status: 'Available'
        isPreview: false
      }
      permissions: {
        resourceProvider: [
          {
            provider: 'Microsoft.OperationalInsights/workspaces'
            permissionsDisplayText: 'read and write permissions are required'
            providerDisplayName: 'Workspace'
            scope: 'Workspace'
            requiredPermissions: {
              write: true
              read: true
              delete: false
            }
          }
          {
            provider: 'Microsoft.OperationalInsights/workspaces/sharedKeys'
            permissionsDisplayText: 'read permissions to shared keys for the workspace are required'
            providerDisplayName: 'Keys'
            scope: 'Workspace'
            requiredPermissions: {
              action: true
            }
          }
        ]
        customs: [
          {
            name: 'TacitRed API credentials'
            description: 'TacitRed API key is required for authentication'
          }
        ]
      }
      instructionSteps: [
        {
          title: 'Connect TacitRed to Microsoft Sentinel'
          description: 'Configure the TacitRed API connection'
          instructions: [
            {
              parameters: {
                fillWith: ['WorkspaceId']
                label: 'Workspace ID'
              }
              type: 'CopyableLabel'
            }
            {
              parameters: {
                label: 'TacitRed API Key'
                placeholder: 'Enter your TacitRed API Key'
                type: 'password'
                name: 'apiKey'
              }
              type: 'Textbox'
            }
            {
              parameters: {
                name: 'connect'
                connectLabel: 'Connect'
                disconnectLabel: 'Disconnect'
                isPrimary: true
              }
              type: 'ConnectionToggleButton'
            }
          ]
        }
      ]
    }
  }
}

// Create the RestApiPoller connector instance
resource connector 'Microsoft.OperationalInsights/workspaces/providers/dataConnectors@2023-02-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/${connectorName}'
  kind: 'RestApiPoller'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    connectorDefinitionName: '${connectorName}-definition'
    dcrConfig: {
      dataCollectionEndpoint: dceIngestionEndpoint
      dataCollectionRuleImmutableId: dcrImmutableId
      streamName: streamName
    }
    dataType: 'TacitRed_Findings_CL'
    auth: {
      type: 'APIKey'
      ApiKeyName: 'Authorization'
      ApiKeyIdentifier: ''
      ApiKey: apiKey
    }
    request: {
      apiEndpoint: '${apiBaseUrl}/findings'
      httpMethod: 'GET'
      queryTimeFormat: 'yyyy-MM-ddTHH:mm:ssZ'
      queryWindowInMin: queryWindowInMin
      startTimeAttributeName: 'from'
      endTimeAttributeName: 'until'
      headers: {
        Accept: 'application/json'
        'User-Agent': 'Microsoft-Sentinel-TacitRed-Connector/1.0'
      }
      rateLimitQPS: 10
      retryCount: 3
      timeoutInSeconds: 60
    }
    paging: {
      pagingType: 'LinkHeader'
      linkHeaderTokenJsonPath: '$.next'
      pageSizeParameterName: 'page_size'
      pageSize: 100
    }
    response: {
      eventsJsonPaths: [
        '$.results'
      ]
      format: 'json'
    }
    isActive: true
  }
  dependsOn: [
    connectorDefinition
  ]
}

output connectorId string = connector.id
output connectorName string = connector.name
output dataType string = 'TacitRed_Findings_CL'
// Note: identity.principalId is not available in outputs for this resource type
// Will need to retrieve it separately after deployment
