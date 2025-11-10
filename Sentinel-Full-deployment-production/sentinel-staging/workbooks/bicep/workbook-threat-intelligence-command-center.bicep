// ===================================================
// THREAT INTELLIGENCE COMMAND CENTER WORKBOOK
// Advanced operational dashboard with predictive analytics
// ===================================================

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics workspace ID')
param workspaceId string

@description('Workbook display name')
param workbookDisplayName string = 'Threat Intelligence Command Center'

@description('Workbook unique identifier')
param workbookId string = newGuid()

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: string(loadTextContent('../templates/command-center-workbook-template.json'))
    version: '1.0'
    sourceId: workspaceId
    category: 'sentinel'
    tags: [
      'Threat Intelligence'
      'Advanced Analytics'
      'Predictive'
      'Cyren'
      'TacitRed'
    ]
  }
}

output workbookId string = workbook.id
output workbookName string = workbook.name
