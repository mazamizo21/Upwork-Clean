// ===================================================
// EXECUTIVE RISK DASHBOARD WORKBOOK
// Business impact metrics and C-level visibility
// ===================================================

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics workspace ID')
param workspaceId string

@description('Workbook display name')
param workbookDisplayName string = 'Executive Risk Dashboard'

@description('Workbook unique identifier')
param workbookId string = newGuid()

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: string(loadTextContent('../templates/executive-dashboard-template.json'))
    version: '1.0'
    sourceId: workspaceId
    category: 'sentinel'
    tags: [
      'Executive'
      'Risk Management'
      'Business Impact'
      'SLA Metrics'
      'Financial Risk'
    ]
  }
}

output workbookId string = workbook.id
output workbookName string = workbook.name
