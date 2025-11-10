// ============================================================================
// Cyren Threat Intelligence Infrastructure
// Deploys DCR/DCE and Logic Apps for IP Reputation and Malware URLs feeds
// ============================================================================

@description('Azure subscription ID')
param subscriptionId string

@description('Resource group name')
param resourceGroupName string

@description('Log Analytics workspace name')
param workspaceName string

@description('Deployment location')
param location string = 'eastus'

@description('Cyren API base URL')
param cyrenApiBaseUrl string = 'https://api-feeds.cyren.com/v1/feed/data'

@description('Cyren IP Reputation feed ID')
param cyrenIpReputationFeedId string = 'ip_reputation'

@description('Cyren IP Reputation JWT token')
@secure()
param cyrenIpReputationToken string

@description('Cyren Malware URLs feed ID')
param cyrenMalwareUrlsFeedId string = 'malware_urls'

@description('Cyren Malware URLs JWT token')
@secure()
param cyrenMalwareUrlsToken string

@description('Number of records to fetch per request')
param cyrenFetchCount int = 10000

@description('Enable IP Reputation feed')
param enableCyrenIpReputation bool = true

@description('Enable Malware URLs feed')
param enableCyrenMalwareUrls bool = true

@description('Recurrence frequency for Logic Apps')
param recurrenceFrequency string = 'Hour'

@description('Recurrence interval for Logic Apps')
param recurrenceInterval int = 6

// Get existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// ============================================================================
// Data Collection Endpoint for Cyren
// ============================================================================
resource cyrenDCE 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: 'dce-cyren-threat-intel'
  location: location
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

// ============================================================================
// Data Collection Rule - IP Reputation
// ============================================================================
resource cyrenIpReputationDCR 'Microsoft.Insights/dataCollectionRules@2022-06-01' = if (enableCyrenIpReputation) {
  name: 'dcr-cyren-ip-reputation'
  location: location
  properties: {
    dataCollectionEndpointId: cyrenDCE.id
    streamDeclarations: {
      'Custom-Cyren_IpReputation_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'ip_address', type: 'string' }
          { name: 'threat_type', type: 'string' }
          { name: 'risk_score', type: 'int' }
          { name: 'confidence', type: 'int' }
          { name: 'first_seen', type: 'datetime' }
          { name: 'last_seen', type: 'datetime' }
          { name: 'country_code', type: 'string' }
          { name: 'asn', type: 'int' }
          { name: 'categories', type: 'string' }
          { name: 'tags', type: 'string' }
          { name: 'source', type: 'string' }
          { name: 'feed_offset', type: 'long' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-Cyren_IpReputation_CL'
        ]
        destinations: [
          'workspace'
        ]
        transformKql: 'source | extend TimeGenerated = now()'
        outputStream: 'Custom-Cyren_IpReputation_CL'
      }
    ]
  }
}

// ============================================================================
// Data Collection Rule - Malware URLs
// ============================================================================
resource cyrenMalwareUrlsDCR 'Microsoft.Insights/dataCollectionRules@2022-06-01' = if (enableCyrenMalwareUrls) {
  name: 'dcr-cyren-malware-urls'
  location: location
  properties: {
    dataCollectionEndpointId: cyrenDCE.id
    streamDeclarations: {
      'Custom-Cyren_MalwareUrls_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'url', type: 'string' }
          { name: 'domain', type: 'string' }
          { name: 'malware_family', type: 'string' }
          { name: 'threat_type', type: 'string' }
          { name: 'risk_score', type: 'int' }
          { name: 'confidence', type: 'int' }
          { name: 'first_seen', type: 'datetime' }
          { name: 'last_seen', type: 'datetime' }
          { name: 'categories', type: 'string' }
          { name: 'tags', type: 'string' }
          { name: 'status', type: 'string' }
          { name: 'source', type: 'string' }
          { name: 'feed_offset', type: 'long' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-Cyren_MalwareUrls_CL'
        ]
        destinations: [
          'workspace'
        ]
        transformKql: 'source | extend TimeGenerated = now()'
        outputStream: 'Custom-Cyren_MalwareUrls_CL'
      }
    ]
  }
}

// ============================================================================
// Logic App - IP Reputation Feed
// ============================================================================
resource logicAppIpReputation 'Microsoft.Logic/workflows@2019-05-01' = if (enableCyrenIpReputation) {
  name: 'logicapp-cyren-ip-reputation'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        Recurrence: {
          type: 'Recurrence'
          recurrence: {
            frequency: recurrenceFrequency
            interval: recurrenceInterval
          }
        }
      }
      actions: {
        'Initialize_Last_Offset': {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'lastOffset'
                type: 'integer'
                value: 0
              }
            ]
          }
          runAfter: {}
        }
        'Get_Feed_Info': {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://api-feeds.cyren.com/v1/feed/info?feedId=${cyrenIpReputationFeedId}'
            headers: {
              Authorization: 'Bearer ${cyrenIpReputationToken}'
              'Accept-Encoding': 'gzip'
            }
          }
          runAfter: {
            'Initialize_Last_Offset': [
              'Succeeded'
            ]
          }
        }
        'Parse_Feed_Info': {
          type: 'ParseJson'
          inputs: {
            content: '@body(\'Get_Feed_Info\')'
            schema: {
              type: 'object'
              properties: {
                feedId: { type: 'string' }
                currentOffset: { type: 'integer' }
                totalRecords: { type: 'integer' }
              }
            }
          }
          runAfter: {
            'Get_Feed_Info': [
              'Succeeded'
            ]
          }
        }
        'Fetch_Feed_Data': {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '@{cyrenApiBaseUrl}?feedId=${cyrenIpReputationFeedId}&offset=@{variables(\'lastOffset\')}&count=${cyrenFetchCount}&format=jsonl'
            headers: {
              Authorization: 'Bearer ${cyrenIpReputationToken}'
              'Accept-Encoding': 'gzip'
            }
          }
          runAfter: {
            'Parse_Feed_Info': [
              'Succeeded'
            ]
          }
        }
        'Split_JSONL_Records': {
          type: 'Compose'
          inputs: '@split(body(\'Fetch_Feed_Data\'), \'\\n\')'
          runAfter: {
            'Fetch_Feed_Data': [
              'Succeeded'
            ]
          }
        }
        'For_Each_Record': {
          type: 'Foreach'
          foreach: '@outputs(\'Split_JSONL_Records\')'
          actions: {
            'Parse_Record': {
              type: 'ParseJson'
              inputs: {
                content: '@items(\'For_Each_Record\')'
                schema: {
                  type: 'object'
                  properties: {
                    ip_address: { type: 'string' }
                    threat_type: { type: 'string' }
                    risk_score: { type: 'integer' }
                    confidence: { type: 'integer' }
                    first_seen: { type: 'string' }
                    last_seen: { type: 'string' }
                    country_code: { type: 'string' }
                    asn: { type: 'integer' }
                    categories: { type: 'array' }
                    tags: { type: 'array' }
                    offset: { type: 'integer' }
                  }
                }
              }
            }
            'Send_to_DCR': {
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@{cyrenDCE.properties.logsIngestion.endpoint}/dataCollectionRules/${cyrenIpReputationDCR.properties.immutableId}/streams/Custom-Cyren_IpReputation_CL?api-version=2023-01-01'
                headers: {
                  'Content-Type': 'application/json'
                  Authorization: 'Bearer @{listKeys(resourceId(\'Microsoft.Insights/dataCollectionRules\', \'${cyrenIpReputationDCR.name}\'), \'2022-06-01\').primaryKey}'
                }
                body: {
                  TimeGenerated: '@{utcNow()}'
                  ip_address: '@{body(\'Parse_Record\')?[\'ip_address\']}'
                  threat_type: '@{body(\'Parse_Record\')?[\'threat_type\']}'
                  risk_score: '@{body(\'Parse_Record\')?[\'risk_score\']}'
                  confidence: '@{body(\'Parse_Record\')?[\'confidence\']}'
                  first_seen: '@{body(\'Parse_Record\')?[\'first_seen\']}'
                  last_seen: '@{body(\'Parse_Record\')?[\'last_seen\']}'
                  country_code: '@{body(\'Parse_Record\')?[\'country_code\']}'
                  asn: '@{body(\'Parse_Record\')?[\'asn\']}'
                  categories: '@{join(body(\'Parse_Record\')?[\'categories\'], \',\')}'
                  tags: '@{join(body(\'Parse_Record\')?[\'tags\'], \',\')}'
                  source: 'Cyren-IpReputation'
                  feed_offset: '@{body(\'Parse_Record\')?[\'offset\']}'
                }
              }
              runAfter: {
                'Parse_Record': [
                  'Succeeded'
                ]
              }
            }
          }
          runAfter: {
            'Split_JSONL_Records': [
              'Succeeded'
            ]
          }
        }
      }
    }
  }
}

// ============================================================================
// Logic App - Malware URLs Feed
// ============================================================================
resource logicAppMalwareUrls 'Microsoft.Logic/workflows@2019-05-01' = if (enableCyrenMalwareUrls) {
  name: 'logicapp-cyren-malware-urls'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        Recurrence: {
          type: 'Recurrence'
          recurrence: {
            frequency: recurrenceFrequency
            interval: recurrenceInterval
          }
        }
      }
      actions: {
        'Initialize_Last_Offset': {
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'lastOffset'
                type: 'integer'
                value: 0
              }
            ]
          }
          runAfter: {}
        }
        'Get_Feed_Info': {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: 'https://api-feeds.cyren.com/v1/feed/info?feedId=${cyrenMalwareUrlsFeedId}'
            headers: {
              Authorization: 'Bearer ${cyrenMalwareUrlsToken}'
              'Accept-Encoding': 'gzip'
            }
          }
          runAfter: {
            'Initialize_Last_Offset': [
              'Succeeded'
            ]
          }
        }
        'Parse_Feed_Info': {
          type: 'ParseJson'
          inputs: {
            content: '@body(\'Get_Feed_Info\')'
            schema: {
              type: 'object'
              properties: {
                feedId: { type: 'string' }
                currentOffset: { type: 'integer' }
                totalRecords: { type: 'integer' }
              }
            }
          }
          runAfter: {
            'Get_Feed_Info': [
              'Succeeded'
            ]
          }
        }
        'Fetch_Feed_Data': {
          type: 'Http'
          inputs: {
            method: 'GET'
            uri: '@{cyrenApiBaseUrl}?feedId=${cyrenMalwareUrlsFeedId}&offset=@{variables(\'lastOffset\')}&count=${cyrenFetchCount}&format=jsonl'
            headers: {
              Authorization: 'Bearer ${cyrenMalwareUrlsToken}'
              'Accept-Encoding': 'gzip'
            }
          }
          runAfter: {
            'Parse_Feed_Info': [
              'Succeeded'
            ]
          }
        }
        'Split_JSONL_Records': {
          type: 'Compose'
          inputs: '@split(body(\'Fetch_Feed_Data\'), \'\\n\')'
          runAfter: {
            'Fetch_Feed_Data': [
              'Succeeded'
            ]
          }
        }
        'For_Each_Record': {
          type: 'Foreach'
          foreach: '@outputs(\'Split_JSONL_Records\')'
          actions: {
            'Parse_Record': {
              type: 'ParseJson'
              inputs: {
                content: '@items(\'For_Each_Record\')'
                schema: {
                  type: 'object'
                  properties: {
                    url: { type: 'string' }
                    domain: { type: 'string' }
                    malware_family: { type: 'string' }
                    threat_type: { type: 'string' }
                    risk_score: { type: 'integer' }
                    confidence: { type: 'integer' }
                    first_seen: { type: 'string' }
                    last_seen: { type: 'string' }
                    categories: { type: 'array' }
                    tags: { type: 'array' }
                    status: { type: 'string' }
                    offset: { type: 'integer' }
                  }
                }
              }
            }
            'Send_to_DCR': {
              type: 'Http'
              inputs: {
                method: 'POST'
                uri: '@{cyrenDCE.properties.logsIngestion.endpoint}/dataCollectionRules/${cyrenMalwareUrlsDCR.properties.immutableId}/streams/Custom-Cyren_MalwareUrls_CL?api-version=2023-01-01'
                headers: {
                  'Content-Type': 'application/json'
                  Authorization: 'Bearer @{listKeys(resourceId(\'Microsoft.Insights/dataCollectionRules\', \'${cyrenMalwareUrlsDCR.name}\'), \'2022-06-01\').primaryKey}'
                }
                body: {
                  TimeGenerated: '@{utcNow()}'
                  url: '@{body(\'Parse_Record\')?[\'url\']}'
                  domain: '@{body(\'Parse_Record\')?[\'domain\']}'
                  malware_family: '@{body(\'Parse_Record\')?[\'malware_family\']}'
                  threat_type: '@{body(\'Parse_Record\')?[\'threat_type\']}'
                  risk_score: '@{body(\'Parse_Record\')?[\'risk_score\']}'
                  confidence: '@{body(\'Parse_Record\')?[\'confidence\']}'
                  first_seen: '@{body(\'Parse_Record\')?[\'first_seen\']}'
                  last_seen: '@{body(\'Parse_Record\')?[\'last_seen\']}'
                  categories: '@{join(body(\'Parse_Record\')?[\'categories\'], \',\')}'
                  tags: '@{join(body(\'Parse_Record\')?[\'tags\'], \',\')}'
                  status: '@{body(\'Parse_Record\')?[\'status\']}'
                  source: 'Cyren-MalwareUrls'
                  feed_offset: '@{body(\'Parse_Record\')?[\'offset\']}'
                }
              }
              runAfter: {
                'Parse_Record': [
                  'Succeeded'
                ]
              }
            }
          }
          runAfter: {
            'Split_JSONL_Records': [
              'Succeeded'
            ]
          }
        }
      }
    }
  }
}

// ============================================================================
// Outputs
// ============================================================================
output dceId string = cyrenDCE.id
output dceEndpoint string = cyrenDCE.properties.logsIngestion.endpoint
output ipReputationDcrId string = enableCyrenIpReputation ? cyrenIpReputationDCR.id : ''
output malwareUrlsDcrId string = enableCyrenMalwareUrls ? cyrenMalwareUrlsDCR.id : ''
output ipReputationLogicAppId string = enableCyrenIpReputation ? logicAppIpReputation.id : ''
output malwareUrlsLogicAppId string = enableCyrenMalwareUrls ? logicAppMalwareUrls.id : ''
