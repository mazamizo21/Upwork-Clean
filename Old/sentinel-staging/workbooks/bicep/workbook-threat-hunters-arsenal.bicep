// ===================================================
// THREAT HUNTER'S ARSENAL WORKBOOK
// Advanced investigation and correlation capabilities
// ===================================================

@description('Location for all resources')
param location string = resourceGroup().location

@description('Log Analytics workspace ID')
param workspaceId string

@description('Workbook display name')
param workbookDisplayName string = 'Threat Hunter\'s Arsenal'

@description('Workbook unique identifier')
param workbookId string = newGuid()

resource workbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookDisplayName
    serializedData: string(loadTextContent('../templates/threat-hunters-arsenal-template.json'))
    version: '1.0'
    sourceId: workspaceId
    category: 'sentinel'
    tags: [
      'Threat Hunting'
      'Investigation'
      'Correlation'
      'MITRE ATT&CK'
      'Behavioral Analytics'
    ]
  }
}

output workbookId string = workbook.id
output workbookName string = workbook.name
