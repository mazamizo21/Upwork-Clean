// Associates a DCR and optional DCE to a target resource (workspace)
// Scope: Workspace (extension resource)

@description('Target Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Full resource ID of the Data Collection Rule')
param dcrResourceId string


@description('Association name')
param associationName string = 'assoc-dcr-tacitred-workspace'

// Parse the workspace name
var workspaceName = last(split(workspaceResourceId, '/'))

// Existing workspace (this module is already scoped to the workspace's resource group)
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Create association on the workspace scope - only DCR ID is required
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = {
  name: associationName
  scope: workspace
  properties: {
    dataCollectionRuleId: dcrResourceId
    description: 'Associate DCR with the Log Analytics workspace for CCF ingestion.'
  }
}

output associationId string = dcrAssociation.id
