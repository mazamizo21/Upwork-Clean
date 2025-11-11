// Bicep template for Sentinel Analytics Rules - Phase 2
// Deploys TacitRed-focused detection rules

param workspaceName string
param location string = resourceGroup().location

@description('Enable or disable individual rules')
param enableRepeatCompromise bool = true
param enableHighRiskUser bool = true
param enableActiveCompromisedAccount bool = true
param enableDepartmentCluster bool = true
param enableCrossFeedCorrelation bool = false // Disabled until Cyren is available

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// Analytics Rule 1: Repeat Compromise Detection
resource ruleRepeatCompromise 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (enableRepeatCompromise) {
  scope: workspace
  name: guid(workspace.id, 'RepeatCompromise')
  kind: 'Scheduled'
  properties: {
    displayName: 'TacitRed - Repeat Compromise Detection'
    description: 'Detects users who have been compromised multiple times within a 7-day window. This may indicate a persistent threat or inadequate remediation.'
    severity: 'High'
    enabled: true
    query: loadTextContent('../analytics-rules/rule-repeat-compromise.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110' // Brute Force
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Repeat Compromise: {{Email}} ({{CompromiseCount}}x) - Domains: {{Domains}}'
      alertDescriptionFormat: 'User {{Email}} compromised {{CompromiseCount}} times across {{Domains}}'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      CompromiseCount: 'CompromiseCount'
      FirstCompromise: 'FirstCompromise'
      LatestCompromise: 'LatestCompromise'
      CompromiseWindow: 'CompromiseWindow'
      AverageConfidence: 'AverageConfidence'
      FindingTypes: 'FindingTypes'
      Domains: 'Domains'
      AllNotes: 'AllNotes'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Email'
          }
          {
            identifier: 'Name'
            columnName: 'Username'
          }
        ]
      }
      {
        entityType: 'DNS'
        fieldMappings: [
          {
            identifier: 'DomainName'
            columnName: 'Domains'
          }
        ]
      }
    ]
  }
}

// Analytics Rule 2: High-Risk User Compromised
resource ruleHighRiskUser 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (enableHighRiskUser) {
  scope: workspace
  name: guid(workspace.id, 'HighRiskUserCompromised')
  kind: 'Scheduled'
  properties: {
    displayName: 'TacitRed - High-Risk User Compromised'
    description: 'Detects when a user with risky sign-ins is also found in TacitRed compromised credentials. Correlates multiple threat signals.'
    severity: 'High'
    enabled: true
    query: loadTextContent('../analytics-rules/rule-high-risk-user-compromised.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110' // Brute Force
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'High-Risk User: {{Email}} - {{TacitRedFindings}} Compromises + {{RiskySignInCount}} Risky Sign-Ins'
      alertDescriptionFormat: 'User {{Email}} has {{TacitRedFindings}} compromises and {{RiskySignInCount}} risky sign-ins'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      TacitRedFindings: 'TacitRedFindings'
      LatestCompromise: 'LatestCompromise'
      RiskySignInCount: 'RiskySignInCount'
      LatestRiskySignIn: 'LatestRiskySignIn'
      TimeBetweenEvents: 'TimeBetweenEvents'
      RiskLevels: 'RiskLevels'
      RiskDetails: 'RiskDetails'
      IPAddresses: 'IPAddresses'
      Locations: 'Locations'
      FindingTypes: 'FindingTypes'
      AvgConfidence: 'AvgConfidence'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Email'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddresses'
          }
        ]
      }
    ]
  }
}

// Analytics Rule 3: Active Compromised Account
resource ruleActiveCompromised 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (enableActiveCompromisedAccount) {
  scope: workspace
  name: guid(workspace.id, 'ActiveCompromisedAccount')
  kind: 'Scheduled'
  properties: {
    displayName: 'TacitRed - Active Compromised Account'
    description: 'Detects compromised users who still have active/enabled accounts in Entra ID. These accounts should be disabled or reset immediately.'
    severity: 'High'
    enabled: true
    query: loadTextContent('../analytics-rules/rule-active-compromised-account.kql')
    queryFrequency: 'PT6H'
    queryPeriod: 'P14D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'Persistence'
    ]
    techniques: [
      'T1098' // Account Manipulation
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Active Account: {{Email}} ({{Department}}) - {{DaysSinceCompromise}} days since compromise'
      alertDescriptionFormat: '{{Email}} compromised {{DaysSinceCompromise}} days ago, account still enabled'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      Email: 'Email'
      AccountEnabled: 'AccountEnabled'
      CompromiseCount: 'CompromiseCount'
      FirstCompromise: 'FirstCompromise'
      LatestCompromise: 'LatestCompromise'
      DaysSinceCompromise: 'DaysSinceCompromise'
      AvgConfidence: 'AvgConfidence'
      FindingTypes: 'FindingTypes'
      Domains: 'Domains'
      Department: 'Department'
      JobTitle: 'JobTitle'
      Manager: 'Manager'
      RiskReason: 'RiskReason'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Email'
          }
        ]
      }
    ]
  }
}

// Analytics Rule 4: Department Compromise Cluster
resource ruleDepartmentCluster 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (enableDepartmentCluster) {
  scope: workspace
  name: guid(workspace.id, 'DepartmentCompromiseCluster')
  kind: 'Scheduled'
  properties: {
    displayName: 'TacitRed - Department Compromise Cluster'
    description: 'Detects when multiple users from the same department are compromised. May indicate targeted campaign or department-wide vulnerability.'
    severity: 'High'
    enabled: true
    query: loadTextContent('../analytics-rules/rule-department-compromise-cluster.kql')
    queryFrequency: 'PT6H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT6H'
    suppressionEnabled: false
    tactics: [
      'Collection'
    ]
    techniques: [
      'T1114' // Email Collection
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          'Department'
        ]
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Department Cluster: {{Department}} - {{AffectedUserCount}} users ({{TotalCompromises}} compromises)'
      alertDescriptionFormat: '{{AffectedUserCount}} users in {{Department}} compromised over {{CompromiseWindow}} days'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      Department: 'Department'
      AffectedUserCount: 'AffectedUserCount'
      AffectedUsers: 'AffectedUsers'
      TotalCompromises: 'TotalCompromises'
      FirstCompromise: 'FirstCompromise'
      LatestCompromise: 'LatestCompromise'
      CompromiseWindow: 'CompromiseWindow'
      AvgConfidence: 'AvgConfidence'
      JobTitles: 'JobTitles'
      Managers: 'Managers'
      FindingTypes: 'FindingTypes'
      ThreatDescription: 'ThreatDescription'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'AffectedUsers'
          }
        ]
      }
    ]
  }
}

// Analytics Rule 5: Cross-Feed Correlation (Disabled by default until Cyren is available)
resource ruleCrossFeed 'Microsoft.SecurityInsights/alertRules@2023-02-01' = if (enableCrossFeedCorrelation) {
  scope: workspace
  name: guid(workspace.id, 'CrossFeedCorrelation')
  kind: 'Scheduled'
  properties: {
    displayName: 'TacitRed + Cyren - Cross-Feed Correlation'
    description: 'Detects when a compromised domain (TacitRed) matches active malicious infrastructure (Cyren). Indicates active exploitation.'
    severity: 'Critical'
    enabled: true
    query: loadTextContent('../analytics-rules/rule-cross-feed-correlation.kql')
    queryFrequency: 'PT1H'
    queryPeriod: 'P7D'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
    ]
    techniques: [
      'T1071' // Application Layer Protocol
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P7D'
        matchingMethod: 'Selected'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: [
          'Domain'
        ]
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Active Exploitation: {{Domain}} - {{UserCount}} users + Risk Score {{MaxRiskScore}}'
      alertDescriptionFormat: '{{Domain}} has {{UserCount}} compromised users and active malicious content'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      Domain: 'Domain'
      CompromisedUsers: 'CompromisedUsers'
      UserCount: 'UserCount'
      LatestCompromise: 'LatestCompromise'
      MaliciousIOCs: 'MaliciousIOCs'
      IOCTypes: 'IOCTypes'
      Categories: 'Categories'
      MaxRiskScore: 'MaxRiskScore'
      AvgConfidence: 'AvgConfidence'
      FindingTypes: 'FindingTypes'
      CyrenFirstSeen: 'CyrenFirstSeen'
      CyrenLastSeen: 'CyrenLastSeen'
      ThreatDescription: 'ThreatDescription'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'CompromisedUsers'
          }
        ]
      }
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
            columnName: 'MaliciousIOCs'
          }
        ]
      }
    ]
  }
}

output ruleIds array = [
  enableRepeatCompromise ? ruleRepeatCompromise.id : ''
  enableHighRiskUser ? ruleHighRiskUser.id : ''
  enableActiveCompromisedAccount ? ruleActiveCompromised.id : ''
  enableDepartmentCluster ? ruleDepartmentCluster.id : ''
  enableCrossFeedCorrelation ? ruleCrossFeed.id : ''
]
