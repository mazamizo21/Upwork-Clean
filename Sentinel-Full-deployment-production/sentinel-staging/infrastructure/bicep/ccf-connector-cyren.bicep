// =============================================================================
// Codeless Connector Framework (CCF) - Cyren Threat InDepth
// RestApiPoller connector with API Key (Bearer token) authentication
// =============================================================================

@description('Workspace name for Sentinel')
param workspaceName string

@description('Connector name')
param connectorName string = 'ccf-cyren'

@description('Cyren API base URL')
param apiBaseUrl string

@secure()
@description('Cyren API token (JWT)')
param apiToken string

@description('Immutable ID of Cyren DCR')
param dcrImmutableId string

@description('Stream name')
param streamName string = 'Custom-Cyren_Indicators_CL'

@description('Polling window in minutes')
param queryWindowInMin int = 360

@description('Maximum batch size for events')
param maximumBatchSize int = 1000

// Reference existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Create the data connector definition first
resource connectorDefinition 'Microsoft.SecurityInsights/dataConnectorDefinitions@2022-12-01-preview' = {
  name: '${connectorName}-definition'
  kind: 'Customizable'
  properties: {
    connectorUiConfig: {
      id: '${connectorName}-definition'
      title: 'Cyren Threat InDepth (CCF)'
      publisher: 'Cyren'
      descriptionMarkdown: 'Ingest phishing and malware infrastructure indicators including URLs, IPs, domains, and file hashes with relationship data.'
      graphQueriesTableName: 'Cyren_Indicators_CL'
      graphQueries: [
        {
          metricName: 'Total Cyren indicators received'
          legend: 'Cyren Indicators'
          baseQuery: 'Cyren_Indicators_CL'
        }
      ]
      sampleQueries: [
        {
          description: 'All Cyren malware indicators from last 24 hours'
          query: 'Cyren_Indicators_CL\\n| where TimeGenerated >= ago(24h)\\n| where category_s == "malware"\\n| project TimeGenerated, url_s, ip_s, domain_s, risk_d, lastSeen_t'
        }
        {
          description: 'High-risk indicators (risk >= 70)'
          query: 'Cyren_Indicators_CL\\n| where risk_d >= 70\\n| summarize count() by category_s\\n| render piechart'
        }
      ]
      dataTypes: [
        {
          name: 'Cyren_Indicators_CL'
          lastDataReceivedQuery: 'Cyren_Indicators_CL\\n| summarize Time = max(TimeGenerated)\\n| where isnotempty(Time)'
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
            name: 'Cyren API credentials'
            description: 'Cyren API JWT token is required for authentication'
          }
        ]
      }
      instructionSteps: [
        {
          title: 'Connect Cyren Threat InDepth to Microsoft Sentinel'
          description: 'Enter your Cyren API credentials to start ingesting threat indicators'
          instructions: [
            {
              parameters: {
                enable: 'true'
                userRequestPlaceHoldersInput: [
                  {
                    displayText: 'Cyren API Base URL'
                    requestObjectKey: 'apiEndpoint'
                    placeHolderName: '{{placeHolder1}}'
                  }
                ]
              }
              type: 'APIKey'
            }
          ]
        }
      ]
    }
  }
  scope: workspace
}

// Create the RestApiPoller connector instance
resource connector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  name: connectorName
  kind: 'RestApiPoller'
  scope: workspace
  properties: {
    connectorDefinitionName: connectorDefinition.name
    dcrConfig: {
      dataCollectionRuleImmutableId: dcrImmutableId
      streamName: streamName
    }
    dataType: 'Cyren_Indicators_CL'
    auth: {
      type: 'APIKey'
      apiKeyName: 'Authorization'
      apiKeyIdentifier: 'Bearer'
      apiKey: apiToken
    }
    request: {
      apiEndpoint: '${apiBaseUrl}/indicators'
      httpMethod: 'Get'
      queryTimeFormat: 'yyyy-MM-ddTHH:mm:ssZ'
      queryWindowInMin: queryWindowInMin
      queryParameters: {
        since: '{{queryWindowStartTime}}'
        until: '{{queryWindowEndTime}}'
      }
      headers: {
        Accept: 'application/json'
        'User-Agent': 'Microsoft-Sentinel-Cyren-Connector/1.0'
      }
      rateLimitQps: 10
      retryCount: 3
      timeoutInSeconds: 60
    }
    paging: {
      pagingType: 'LinkHeader'
    }
    response: {
      eventsJsonPaths: [
        '$'
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
output dataType string = 'Cyren_Indicators_CL'
