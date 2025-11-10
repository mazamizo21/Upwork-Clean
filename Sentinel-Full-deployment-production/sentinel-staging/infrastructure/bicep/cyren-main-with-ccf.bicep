// =============================================================================
// Cyren Threat Intelligence Integration - Main Template (with CCF Option)
// Supports both Logic Apps (WORKING) and CCF (DISABLED - subscription issue)
// =============================================================================

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
param cyrenFetchCount int = 100

@description('Enable IP Reputation feed')
param enableCyrenIpReputation bool = true

@description('Enable Malware URLs feed')
param enableCyrenMalwareUrls bool = true

@description('Polling interval in hours')
param pollingIntervalHours int = 6

// =============================================================================
// CCF OPTIONS (DISABLED BY DEFAULT - Subscription/Backend Issue)
// =============================================================================

@description('Use CCF (Codeless Connector Framework) instead of Logic Apps')
param useCCF bool = false // DISABLED: Set to true when subscription/CCF backend is fixed

@description('CCF polling window in minutes (only used if useCCF = true)')
param ccfQueryWindowInMin int = 360

@description('CCF maximum batch size (only used if useCCF = true)')
param ccfMaximumBatchSize int = 1000

// Get existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// ============================================================================
// Data Collection Endpoint (used by both Logic Apps and CCF)
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
// LOGIC APPS (DEFAULT - WORKING SOLUTION)
// Only deployed if useCCF = false
// ============================================================================

// Logic App - IP Reputation
module ipReputationLogicApp './logicapp-cyren-ip-reputation.bicep' = if (enableCyrenIpReputation && !useCCF) {
  name: 'deploy-logicapp-ip-reputation'
  params: {
    location: location
    cyrenIpReputationToken: cyrenIpReputationToken
    cyrenApiBaseUrl: cyrenApiBaseUrl
    cyrenIpReputationFeedId: cyrenIpReputationFeedId
    dcrImmutableId: enableCyrenIpReputation ? cyrenIpReputationDCR.properties.immutableId : ''
    dceEndpoint: cyrenDCE.properties.logsIngestion.endpoint
    fetchCount: cyrenFetchCount
    pollingIntervalHours: pollingIntervalHours
  }
}

// Logic App - Malware URLs
module malwareUrlsLogicApp './logicapp-cyren-malware-urls.bicep' = if (enableCyrenMalwareUrls && !useCCF) {
  name: 'deploy-logicapp-malware-urls'
  params: {
    location: location
    cyrenMalwareUrlsToken: cyrenMalwareUrlsToken
    cyrenApiBaseUrl: cyrenApiBaseUrl
    cyrenMalwareUrlsFeedId: cyrenMalwareUrlsFeedId
    dcrImmutableId: enableCyrenMalwareUrls ? cyrenMalwareUrlsDCR.properties.immutableId : ''
    dceEndpoint: cyrenDCE.properties.logsIngestion.endpoint
    fetchCount: cyrenFetchCount
    pollingIntervalHours: pollingIntervalHours
  }
}

// ============================================================================
// CCF CONNECTORS (DISABLED - NOT WORKING YET)
// Only deployed if useCCF = true
// NOTE: Currently blocked by subscription state or CCF backend access issues
// ============================================================================

// CCF Connector - IP Reputation
module ccfIpReputationConnector './ccf-connector-cyren.bicep' = if (enableCyrenIpReputation && useCCF) {
  name: 'deploy-ccf-ip-reputation'
  params: {
    workspaceName: workspaceName
    connectorName: 'ccf-cyren-ip-reputation'
    apiBaseUrl: cyrenApiBaseUrl
    apiToken: cyrenIpReputationToken
    dcrImmutableId: enableCyrenIpReputation ? cyrenIpReputationDCR.properties.immutableId : ''
    streamName: 'Custom-Cyren_IpReputation_CL'
    queryWindowInMin: ccfQueryWindowInMin
    maximumBatchSize: ccfMaximumBatchSize
  }
}

// Note: CCF for Malware URLs would need a separate module call here if needed
// Currently using single CCF module for IP Reputation as example

// ============================================================================
// Outputs
// ============================================================================
output deploymentMethod string = useCCF ? 'CCF (Codeless Connector Framework)' : 'Logic Apps'
output dceId string = cyrenDCE.id
output dceEndpoint string = cyrenDCE.properties.logsIngestion.endpoint
output ipReputationDcrId string = enableCyrenIpReputation ? cyrenIpReputationDCR.id : ''
output ipReputationDcrImmutableId string = enableCyrenIpReputation ? cyrenIpReputationDCR.properties.immutableId : ''
output malwareUrlsDcrId string = enableCyrenMalwareUrls ? cyrenMalwareUrlsDCR.id : ''
output malwareUrlsDcrImmutableId string = enableCyrenMalwareUrls ? cyrenMalwareUrlsDCR.properties.immutableId : ''

// Logic App outputs (only populated if useCCF = false)
output ipReputationLogicAppId string = (enableCyrenIpReputation && !useCCF) ? ipReputationLogicApp.outputs.logicAppId : ''
output ipReputationLogicAppPrincipalId string = (enableCyrenIpReputation && !useCCF) ? ipReputationLogicApp.outputs.principalId : ''
output malwareUrlsLogicAppId string = (enableCyrenMalwareUrls && !useCCF) ? malwareUrlsLogicApp.outputs.logicAppId : ''
output malwareUrlsLogicAppPrincipalId string = (enableCyrenMalwareUrls && !useCCF) ? malwareUrlsLogicApp.outputs.principalId : ''

// CCF outputs (only populated if useCCF = true)
output ccfConnectorDeployed bool = useCCF
output ccfStatus string = useCCF ? 'Deployed (may not be functional - check subscription/CCF backend)' : 'Not deployed (using Logic Apps)'
