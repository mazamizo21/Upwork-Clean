// =============================================================================
// Analytics Rules for Sentinel CCF Solution
// Scheduled rules for correlation and detection
// =============================================================================

@description('Workspace name')
param workspaceName string

@description('Enable analytics rules')
param enabled bool = true

@description('Default severity for analytics rules')
@allowed(['Informational', 'Low', 'Medium', 'High'])
param defaultSeverity string = 'Medium'

@description('Query frequency in minutes')
param queryFrequency int = 360  // 6 hours

@description('Query period in hours')
param queryPeriod int = 48

@description('Trigger threshold')
param triggerThreshold int = 0

// Reference existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// -----------------------------------------------------------------------------
// Rule 1: Compromised Email with Active Malicious Infrastructure
// -----------------------------------------------------------------------------
resource rule1_CompromisedWithActiveMalware 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rule-compromised-active-malware', workspaceName)
  kind: 'Scheduled'
  scope: workspace
  properties: {
    displayName: 'TI - Compromised Account with Active Malicious Infrastructure'
    description: 'Detects compromised accounts (TacitRed) that are associated with domains hosting active malicious infrastructure (Cyren) in the last 48 hours. This indicates the account may be actively used in ongoing attacks.'
    severity: 'High'
    enabled: enabled
    query: '''
parser_tacitred_findings()
| where TimeGenerated >= ago(7d)
| join kind=inner (
    parser_cyren_indicators()
    | where LastSeen >= ago(48h)
    | where RiskScore >= 50
    | where isnotempty(Domain)
) on $left.Domain == $right.Domain
| extend 
    AccountName = tostring(split(Email, '@')[0]),
    UPNSuffix = tostring(split(Email, '@')[1])
| project 
    TimeGenerated,
    CompromisedEmail = Email,
    CompromisedDomain = Domain,
    FindingType,
    Confidence,
    MaliciousIOC = IOC,
    ThreatType,
    RiskScore,
    ThreatLastSeen = LastSeen1,
    FirstSeenCompromise = FirstSeen,
    CampaignId,
    AccountName,
    UPNSuffix,
    Notes,
    Relationships
'''
    queryFrequency: 'PT${queryFrequency}M'
    queryPeriod: 'PT${queryPeriod}H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'InitialAccess'
      'CommandAndControl'
    ]
    techniques: [
      'T1078'  // Valid Accounts
      'T1566'  // Phishing
      'T1071'  // Application Layer Protocol
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UPNSuffix'
          }
        ]
      }
      {
        entityType: 'URL'
        fieldMappings: [
          {
            identifier: 'Url'
            columnName: 'MaliciousIOC'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT24H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: [
          'DisplayName'
        ]
        groupByCustomDetails: []
      }
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Compromised Account {{CompromisedEmail}} linked to active malware infrastructure'
      alertDescriptionFormat: 'Account {{CompromisedEmail}} from TacitRed findings is associated with domain {{CompromisedDomain}} which is hosting active malicious infrastructure ({{ThreatType}}) detected by Cyren with risk score {{RiskScore}}. Last malicious activity: {{ThreatLastSeen}}'
      alertSeverityColumnName: 'Confidence'
      alertDynamicProperties: [
        {
          alertProperty: 'AlertLink'
          value: 'MaliciousIOC'
        }
        {
          alertProperty: 'ProductName'
          value: 'ThreatType'
        }
      ]
    }
  }
}

// -----------------------------------------------------------------------------
// Rule 2: Repeat Compromise - Same Account Multiple Times
// -----------------------------------------------------------------------------
resource rule2_RepeatCompromise 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rule-repeat-compromise', workspaceName)
  kind: 'Scheduled'
  scope: workspace
  properties: {
    displayName: 'TI - Repeat Account Compromise Detected'
    description: 'Detects accounts that have been compromised multiple times within 7 days, indicating persistent targeting or insufficient remediation.'
    severity: 'High'
    enabled: enabled
    query: '''
parser_tacitred_findings()
| where TimeGenerated >= ago(7d)
| summarize 
    Findings = count(),
    FirstCompromise = min(FirstSeen),
    LastCompromise = max(LastSeen),
    FindingTypes = make_set(FindingType),
    Domains = make_set(Domain),
    AvgConfidence = avg(Confidence),
    CampaignIds = make_set(CampaignId)
    by Email
| where Findings > 1
| extend 
    AccountName = tostring(split(Email, '@')[0]),
    UPNSuffix = tostring(split(Email, '@')[1]),
    DaysSinceFirst = datetime_diff('day', now(), FirstCompromise)
| project 
    TimeGenerated = now(),
    Email,
    CompromiseCount = Findings,
    FirstCompromise,
    LastCompromise,
    DaysSinceFirst,
    FindingTypes,
    Domains,
    AvgConfidence,
    CampaignIds,
    AccountName,
    UPNSuffix
'''
    queryFrequency: 'PT${queryFrequency}M'
    queryPeriod: 'PT168H'  // 7 days
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'Persistence'
      'CredentialAccess'
    ]
    techniques: [
      'T1078'  // Valid Accounts
      'T1110'  // Brute Force
    ]
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UPNSuffix'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: true
        lookbackDuration: 'PT168H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Account {{Email}} compromised {{CompromiseCount}} times in 7 days'
      alertDescriptionFormat: 'Account {{Email}} has been compromised {{CompromiseCount}} times between {{FirstCompromise}} and {{LastCompromise}}. Finding types: {{FindingTypes}}. Average confidence: {{AvgConfidence}}. This indicates persistent targeting or insufficient remediation.'
    }
  }
}

// -----------------------------------------------------------------------------
// Rule 3: High-Risk Indicator with Multiple Related Threats
// -----------------------------------------------------------------------------
resource rule3_HighRiskWithRelationships 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rule-high-risk-relationships', workspaceName)
  kind: 'Scheduled'
  scope: workspace
  properties: {
    displayName: 'TI - High-Risk Indicator with Multiple Threat Relationships'
    description: 'Detects high-risk Cyren indicators (risk >= 80) that have multiple relationship connections to other malicious entities, indicating sophisticated threat infrastructure.'
    severity: 'Medium'
    enabled: enabled
    query: '''
parser_cyren_indicators()
| where TimeGenerated >= ago(48h)
| where RiskScore >= 80
| where isnotempty(Relationships)
| extend RelationshipCount = array_length(Relationships)
| where RelationshipCount >= 2
| project 
    TimeGenerated,
    IOC,
    ThreatType,
    RiskScore,
    FirstSeen,
    LastSeen,
    RelationshipCount,
    Relationships,
    DetectionMethods,
    Domain,
    IP,
    URL
'''
    queryFrequency: 'PT${queryFrequency}M'
    queryPeriod: 'PT${queryPeriod}H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
      'DefenseEvasion'
    ]
    techniques: [
      'T1071'  // Application Layer Protocol
      'T1568'  // Dynamic Resolution
    ]
    entityMappings: [
      {
        entityType: 'URL'
        fieldMappings: [
          {
            identifier: 'Url'
            columnName: 'IOC'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IP'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT48H'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: [
          'DisplayName'
        ]
        groupByCustomDetails: [
          {
            customDetailsKey: 'Domain'
            detailsValue: 'Domain'
          }
        ]
      }
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'High-risk {{ThreatType}} indicator {{IOC}} with {{RelationshipCount}} threat relationships'
      alertDescriptionFormat: 'High-risk indicator {{IOC}} (risk score: {{RiskScore}}) detected with {{RelationshipCount}} relationship connections to other malicious entities. This indicates sophisticated threat infrastructure. Threat type: {{ThreatType}}. Last seen: {{LastSeen}}'
    }
  }
}

// -----------------------------------------------------------------------------
// Rule 4: Campaign Spreading Across Multiple Domains
// -----------------------------------------------------------------------------
resource rule4_MultiDomainCampaign 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rule-multi-domain-campaign', workspaceName)
  kind: 'Scheduled'
  scope: workspace
  properties: {
    displayName: 'TI - Campaign Spreading Across Multiple Domains'
    description: 'Detects threat campaigns affecting multiple domains within 24 hours, indicating a widespread attack or coordinated threat activity.'
    severity: defaultSeverity
    enabled: enabled
    query: '''
parser_tacitred_findings()
| where TimeGenerated >= ago(24h)
| where isnotempty(CampaignId)
| summarize 
    AffectedDomains = dcount(Domain),
    Domains = make_set(Domain),
    CompromisedUsers = dcount(Email),
    Users = make_set(Email),
    FindingTypes = make_set(FindingType),
    FirstSeen = min(FirstSeen),
    LastSeen = max(LastSeen),
    AvgConfidence = avg(Confidence)
    by CampaignId
| where AffectedDomains >= 2
| project 
    TimeGenerated = now(),
    CampaignId,
    AffectedDomains,
    CompromisedUsers,
    Domains,
    Users,
    FindingTypes,
    FirstSeen,
    LastSeen,
    AvgConfidence
'''
    queryFrequency: 'PT${queryFrequency}M'
    queryPeriod: 'PT24H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'Collection'
    ]
    techniques: [
      'T1566'  // Phishing
      'T1114'  // Email Collection
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT24H'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          {
            customDetailsKey: 'CampaignId'
            detailsValue: 'CampaignId'
          }
        ]
      }
    }
    customDetails: {
      CampaignId: 'CampaignId'
      AffectedDomains: 'AffectedDomains'
      CompromisedUsers: 'CompromisedUsers'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Campaign {{CampaignId}} affecting {{AffectedDomains}} domains and {{CompromisedUsers}} users'
      alertDescriptionFormat: 'Threat campaign {{CampaignId}} detected spreading across {{AffectedDomains}} domains with {{CompromisedUsers}} compromised users. Affected domains: {{Domains}}. Finding types: {{FindingTypes}}. First seen: {{FirstSeen}}, Last seen: {{LastSeen}}'
    }
  }
}

// -----------------------------------------------------------------------------
// Rule 5: New Malware Infrastructure from Known Compromised Domain
// -----------------------------------------------------------------------------
resource rule5_NewMalwareFromCompromisedDomain 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid('rule-new-malware-compromised-domain', workspaceName)
  kind: 'Scheduled'
  scope: workspace
  properties: {
    displayName: 'TI - New Malware Infrastructure on Known Compromised Domain'
    description: 'Detects when new malicious infrastructure appears on a domain that has known compromised accounts, indicating the domain may be fully compromised and weaponized.'
    severity: 'High'
    enabled: enabled
    query: '''
let CompromisedDomains = parser_tacitred_findings()
    | where TimeGenerated >= ago(30d)
    | distinct Domain;
parser_cyren_indicators()
| where TimeGenerated >= ago(24h)
| where ThreatType in ('malware', 'phishing')
| where isnotempty(Domain)
| where Domain in (CompromisedDomains)
| join kind=inner (
    parser_tacitred_findings()
    | summarize CompromisedUsers = dcount(Email), Users = make_set(Email) by Domain
) on Domain
| project 
    TimeGenerated,
    Domain,
    NewThreatIOC = IOC,
    ThreatType,
    RiskScore,
    FirstSeen,
    LastSeen,
    CompromisedUsers,
    Users,
    Relationships,
    DetectionMethods
'''
    queryFrequency: 'PT${queryFrequency}M'
    queryPeriod: 'PT24H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: triggerThreshold
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'ResourceDevelopment'
      'CommandAndControl'
    ]
    techniques: [
      'T1584'  // Compromise Infrastructure
      'T1071'  // Application Layer Protocol
    ]
    entityMappings: [
      {
        entityType: 'DNS'
        fieldMappings: [
          {
            identifier: 'DomainName'
            columnName: 'Domain'
          }
        ]
      }
      {
        entityType: 'URL'
        fieldMappings: [
          {
            identifier: 'Url'
            columnName: 'NewThreatIOC'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT48H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'DNS'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'New {{ThreatType}} infrastructure detected on compromised domain {{Domain}}'
      alertDescriptionFormat: 'New malicious infrastructure ({{ThreatType}}) detected on domain {{Domain}} which has {{CompromisedUsers}} compromised accounts. IOC: {{NewThreatIOC}} with risk score {{RiskScore}}. This indicates the domain may be fully compromised and weaponized for attacks.'
    }
  }
}

output analyticsRulesDeployed array = [
  rule1_CompromisedWithActiveMalware.name
  rule2_RepeatCompromise.name
  rule3_HighRiskWithRelationships.name
  rule4_MultiDomainCampaign.name
  rule5_NewMalwareFromCompromisedDomain.name
]
