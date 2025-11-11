@description('DCR name')
param dcrName string = 'dcr-tacitred-findings'

@description('Location')
param location string = resourceGroup().location

@description('Workspace resource ID')
param workspaceResourceId string

@description('DCE resource ID')
param dceResourceId string

resource dcr 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dcrName
  location: location
  properties: {
    dataCollectionEndpointId: dceResourceId
    streamDeclarations: {
      'Custom-TacitRed_Findings_Raw': {
        columns: [
          {
            name: 'email'
            type: 'string'
          }
          {
            name: 'domain'
            type: 'string'
          }
          {
            name: 'findingType'
            type: 'string'
          }
          {
            name: 'confidence'
            type: 'string'
          }
          {
            name: 'firstSeen'
            type: 'string'
          }
          {
            name: 'lastSeen'
            type: 'string'
          }
          {
            name: 'notes'
            type: 'string'
          }
          {
            name: 'source'
            type: 'string'
          }
          {
            name: 'severity'
            type: 'string'
          }
          {
            name: 'status'
            type: 'string'
          }
          {
            name: 'campaign_id'
            type: 'string'
          }
          {
            name: 'user_id'
            type: 'string'
          }
          {
            name: 'username'
            type: 'string'
          }
          {
            name: 'detection_ts'
            type: 'string'
          }
          {
            name: 'metadata'
            type: 'string'
          }
        ]
      }
      'Custom-TacitRed_Findings_CL': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'email_s'
            type: 'string'
          }
          {
            name: 'domain_s'
            type: 'string'
          }
          {
            name: 'findingType_s'
            type: 'string'
          }
          {
            name: 'confidence_d'
            type: 'int'
          }
          {
            name: 'firstSeen_t'
            type: 'datetime'
          }
          {
            name: 'lastSeen_t'
            type: 'datetime'
          }
          {
            name: 'notes_s'
            type: 'string'
          }
          {
            name: 'source_s'
            type: 'string'
          }
          {
            name: 'severity_s'
            type: 'string'
          }
          {
            name: 'status_s'
            type: 'string'
          }
          {
            name: 'campaign_id_s'
            type: 'string'
          }
          {
            name: 'user_id_s'
            type: 'string'
          }
          {
            name: 'username_s'
            type: 'string'
          }
          {
            name: 'detection_ts_t'
            type: 'datetime'
          }
          {
            name: 'metadata_s'
            type: 'string'
          }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'ws1'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-TacitRed_Findings_Raw'
        ]
        destinations: [
          'ws1'
        ]
        transformKql: 'source | extend tg1=todatetime(detection_ts) | extend tg2=iif(isnull(tg1), todatetime(lastSeen), tg1) | extend tg=iif(isnull(tg2), now(), tg2) | project TimeGenerated=tg, email_s=tostring(email), domain_s=tostring(domain), findingType_s=tostring(findingType), confidence_d=toint(confidence), firstSeen_t=todatetime(firstSeen), lastSeen_t=todatetime(lastSeen), notes_s=tostring(notes), source_s=tostring(source), severity_s=tostring(severity), status_s=tostring(status), campaign_id_s=tostring(campaign_id), user_id_s=tostring(user_id), username_s=tostring(username), detection_ts_t=todatetime(detection_ts), metadata_s=tostring(metadata)'
        outputStream: 'Custom-TacitRed_Findings_CL'
      }
    ]
  }
}

output id string = dcr.id
output immutableId string = dcr.properties.immutableId
