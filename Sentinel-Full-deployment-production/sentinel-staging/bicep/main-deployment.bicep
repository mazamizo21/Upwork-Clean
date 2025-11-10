// =============================================================================
// Main Deployment - Sentinel CCF ThreatIntel Solution
// Complete deployment including DCRs, connectors, analytics, playbooks
// =============================================================================

targetScope = 'resourceGroup'

// Import parameters
@description('Solution parameters file')
param parametersFile string = './parameters.bicep'

@description('Deployment timestamp')
param deploymentTimestamp string = utcNow()

// Core parameters
@description('Target Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Location')
param location string = resourceGroup().location

// Cyren parameters
@description('Cyren API base URL')
param cyrenApiBaseUrl string = ''

@secure()
@description('Cyren API token')
param cyrenApiToken string = ''

// TacitRed parameters
@description('TacitRed API base URL')
param tacitRedApiBaseUrl string

@secure()
@description('TacitRed API key')
param tacitRedApiKey string

// Configuration
@description('Enable Cyren connector deployment')
param enableCyren bool = true

@description('Enable analytics rules')
param enableAnalytics bool = true

@description('Enable playbooks')
param enablePlaybooks bool = true

@description('Enable IP enrichment')
param enableIpEnrichment bool = true

@description('IP enrichment provider')
@allowed(['DefenderTI', 'ip-api', 'ipinfo', 'MaxMind'])
param enrichmentProvider string = 'DefenderTI'

@description('Require approval for containment actions')
param requireApproval bool = true

@description('Tags for all resources')
param resourceTags object = {
  Solution: 'Sentinel-ThreatIntel-CCF'
  ManagedBy: 'Bicep'
}

// Extract workspace name from resource ID
var workspaceName = last(split(workspaceResourceId, '/'))
var workspaceSubscriptionId = split(workspaceResourceId, '/')[2]
var workspaceResourceGroup = split(workspaceResourceId, '/')[4]

// Reference existing workspace to access its CustomerId (Workspace ID GUID)
resource laWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  name: workspaceName
}

// =============================================================================
// 0. Deploy Data Collection Endpoint (used by CCF connectors)
// =============================================================================

module dce './data-collection-endpoint.bicep' = {
  name: 'deploy-dce'
  params: {
    location: location
    dceName: 'dce-sentinel-threatintel'
    tags: resourceTags
  }
}

// =============================================================================
// 1. Deploy DCRs
// =============================================================================

module cyrenDcr './dcr-cyren.bicep' = if (enableCyren) {
  name: 'deploy-dcr-cyren'
  params: {
    dcrName: 'dcr-cyren-indicators'
    location: location
    workspaceResourceId: workspaceResourceId
    streamName: 'Custom-Cyren_Indicators_CL'
    tags: resourceTags
  }
}

module tacitRedDcr './dcr-tacitred.bicep' = {
  name: 'deploy-dcr-tacitred'
  params: {
    dcrName: 'dcr-tacitred-findings'
    location: location
    workspaceResourceId: workspaceResourceId
    dceResourceId: dce.outputs.dceId
    streamName: 'Custom-TacitRed_Findings_CL'
    tags: resourceTags
  }
}

// Associate TacitRed DCR to the workspace (shows as endpoint configured in portal)
module tacitRedDcra './associate-dcr-to-workspace.bicep' = {
  name: 'associate-tacitred-dcr'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceResourceId: workspaceResourceId
    dcrResourceId: tacitRedDcr.outputs.dcrId
    associationName: 'assoc-dcr-tacitred-workspace'
  }
  dependsOn: [
    tacitRedDcr
    dce
  ]
}

// =============================================================================
// 2. Deploy CCF Connectors
// =============================================================================

module cyrenConnector './ccf-connector-cyren.bicep' = if (enableCyren) {
  name: 'deploy-connector-cyren'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: workspaceName
    connectorName: 'ccf-cyren'
    apiBaseUrl: cyrenApiBaseUrl
    apiToken: cyrenApiToken
    dcrImmutableId: cyrenDcr.outputs.dcrImmutableId
    streamName: 'Custom-Cyren_Indicators_CL'
  }
  dependsOn: [
    cyrenDcr
  ]
}

module tacitRedConnector './ccf-connector-tacitred.bicep' = {
  name: 'deploy-connector-tacitred'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: workspaceName
    workspaceResourceGroup: workspaceResourceGroup
    location: location
    connectorName: 'ccf-tacitred'
    apiBaseUrl: tacitRedApiBaseUrl
    apiKey: tacitRedApiKey
    dcrImmutableId: tacitRedDcr.outputs.dcrImmutableId
    streamName: 'Custom-TacitRed_Findings_CL'
    dceIngestionEndpoint: dce.outputs.dceEndpoint
    dceResourceId: dce.outputs.dceId
    queryWindowInMin: 360
  }
  dependsOn: [
    tacitRedDcr
    tacitRedDcra
  ]
}

// Note: Role assignment for connector identity must be done post-deployment
// because the connector resource doesn't expose identity.principalId in outputs
// Run assign-connector-permissions.ps1 after deployment

// =============================================================================
// 3. Deploy Analytics Rules
// =============================================================================

module analyticsRules './analytics-rules.bicep' = if (enableAnalytics) {
  name: 'deploy-analytics-rules'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    workspaceName: workspaceName
    enabled: true
    defaultSeverity: 'Medium'
  }
  dependsOn: [
    cyrenConnector
    tacitRedConnector
  ]
}

// =============================================================================
// 4. Deploy Playbooks
// =============================================================================

module playbookThreatHunt '../playbooks/PB-ThreatHunt-M365D.bicep' = if (enablePlaybooks) {
  name: 'deploy-playbook-threathunt'
  params: {
    playbookName: 'PB-ThreatHunt-M365D'
    location: location
  }
}

module playbookIpEnrichment '../playbooks/PB-IP-Enrichment.bicep' = if (enableIpEnrichment) {
  name: 'deploy-playbook-ipenrichment'
  params: {
    playbookName: 'PB-IP-Enrichment'
    location: location
    workspaceId: workspaceResourceId
    enrichmentProvider: enrichmentProvider
    batchSize: 100
    rateLimitPerMin: 40
    reEnrichDays: 7
  }
}

// =============================================================================
// Outputs
// =============================================================================

output deploymentStatus object = {
  dcrs: {
    cyren: enableCyren ? cyrenDcr.outputs.dcrImmutableId : 'Not deployed'
    tacitred: tacitRedDcr.outputs.dcrImmutableId
  }
  connectors: {
    cyren: enableCyren ? cyrenConnector.outputs.connectorName : 'Not deployed'
    tacitred: tacitRedConnector.outputs.connectorName
  }
  analytics: enableAnalytics ? {
    rulesDeployed: analyticsRules.outputs.analyticsRulesDeployed
  } : {}
  playbooks: {
    threatHunt: enablePlaybooks ? playbookThreatHunt.outputs.playbookName : 'Not deployed'
    ipEnrichment: enableIpEnrichment ? playbookIpEnrichment.outputs.playbookName : 'Not deployed'
  }
}

output dceId string = dce.outputs.dceId
output dceEndpoint string = dce.outputs.dceEndpoint

output workspaceId string = workspaceResourceId
output deploymentTimestamp string = deploymentTimestamp
