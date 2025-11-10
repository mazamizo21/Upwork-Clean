// Data Collection Endpoint for TacitRed CCF Connector
// This is required for CCF connectors to send data to DCRs

@description('Location for the Data Collection Endpoint')
param location string = resourceGroup().location

@description('Name of the Data Collection Endpoint')
param dceName string = 'dce-sentinel-threatintel'

@description('Tags for the resource')
param tags object = {
  Solution: 'Sentinel-ThreatIntel'
  Component: 'DataCollectionEndpoint'
}

// Create Data Collection Endpoint
resource dataCollectionEndpoint 'Microsoft.Insights/dataCollectionEndpoints@2022-06-01' = {
  name: dceName
  location: location
  tags: tags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

output dceId string = dataCollectionEndpoint.id
output dceEndpoint string = dataCollectionEndpoint.properties.logsIngestion.endpoint
output dceName string = dataCollectionEndpoint.name
