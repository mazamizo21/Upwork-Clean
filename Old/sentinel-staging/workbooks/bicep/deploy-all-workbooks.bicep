// ===================================================
// MAIN WORKBOOK DEPLOYMENT FILE
// Deploys all three advanced workbooks
// ===================================================

targetScope = 'resourceGroup'

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics Workspace Resource ID')
param workspaceResourceId string

@description('Tags to apply to all resources')
param tags object = {
  Solution: 'Sentinel Threat Intelligence'
  DeploymentType: 'Workbooks'
  Version: '1.0'
  CreatedBy: 'Advanced Analytics Team'
}

// Generate unique IDs for each workbook
var commandCenterWorkbookId = guid(resourceGroup().id, 'command-center')
var executiveWorkbookId = guid(resourceGroup().id, 'executive-dashboard')
var huntersArsenalWorkbookId = guid(resourceGroup().id, 'hunters-arsenal')

// ===================================================
// 1. THREAT INTELLIGENCE COMMAND CENTER
// ===================================================
module commandCenterWorkbook 'workbook-threat-intelligence-command-center.bicep' = {
  name: 'deploy-command-center-workbook'
  params: {
    location: location
    workspaceId: workspaceResourceId
    workbookDisplayName: '🎯 Threat Intelligence Command Center'
    workbookId: commandCenterWorkbookId
  }
}

// ===================================================
// 2. EXECUTIVE RISK DASHBOARD
// ===================================================
module executiveWorkbook 'workbook-executive-risk-dashboard.bicep' = {
  name: 'deploy-executive-workbook'
  params: {
    location: location
    workspaceId: workspaceResourceId
    workbookDisplayName: '📊 Executive Risk Dashboard'
    workbookId: executiveWorkbookId
  }
}

// ===================================================
// 3. THREAT HUNTER'S ARSENAL
// ===================================================
module huntersArsenalWorkbook 'workbook-threat-hunters-arsenal.bicep' = {
  name: 'deploy-hunters-arsenal-workbook'
  params: {
    location: location
    workspaceId: workspaceResourceId
    workbookDisplayName: '🔍 Threat Hunter\'s Arsenal'
    workbookId: huntersArsenalWorkbookId
  }
}

// ===================================================
// OUTPUTS
// ===================================================
output commandCenterWorkbookId string = commandCenterWorkbook.outputs.workbookId
output executiveWorkbookId string = executiveWorkbook.outputs.workbookId
output huntersArsenalWorkbookId string = huntersArsenalWorkbook.outputs.workbookId

output deploymentSummary object = {
  totalWorkbooksDeployed: 3
  workbooks: [
    {
      name: 'Threat Intelligence Command Center'
      id: commandCenterWorkbook.outputs.workbookId
      purpose: 'Real-time operational dashboard with predictive analytics'
    }
    {
      name: 'Executive Risk Dashboard'
      id: executiveWorkbook.outputs.workbookId
      purpose: 'Business impact metrics and C-level visibility'
    }
    {
      name: 'Threat Hunter\'s Arsenal'
      id: huntersArsenalWorkbook.outputs.workbookId
      purpose: 'Advanced investigation and correlation capabilities'
    }
  ]
}
