// Cyren Threat Intelligence Workbook
// Provides detailed visibility into Cyren IP Reputation and Malware URLs feeds
// Displays risk trends, top threats, geographic distribution, and correlation insights

param workspaceId string
param location string = 'eastus'
param workbookName string = 'Cyren Threat Intelligence Dashboard'

var workbookId = guid(workspaceId, workbookName)

resource cyrenWorkbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: workbookId
  location: location
  kind: 'shared'
  properties: {
    displayName: workbookName
    serializedData: string({
      version: 'Notebook/1.0'
      items: [
        {
          type: 1
          content: {
            json: '## Cyren Threat Intelligence Dashboard\n\nReal-time visibility into Cyren IP Reputation and Malware URLs feeds\n\n---'
          }
        }
        // Overview Stats
        {
          type: 9
          content: {
            version: 'KqlParametersItem/1.0'
            parameters: [
              {
                id: 'time-range'
                name: 'TimeRange'
                type: 4
                value: {
                  durationMs: 604800000  // 7 days
                }
                typeSettings: {
                  selectableValues: [
                    { durationMs: 3600000, label: '1 hour' }
                    { durationMs: 86400000, label: '24 hours' }
                    { durationMs: 604800000, label: '7 days' }
                    { durationMs: 2592000000, label: '30 days' }
                  ]
                }
              }
            ]
          }
        }
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| summarize 
    TotalIndicators = count(),
    UniqueIPs = dcount(ip_s),
    UniqueURLs = dcount(url_s),
    HighRisk = countif(toint(risk_d) >= 80),
    MediumRisk = countif(toint(risk_d) >= 50 and toint(risk_d) < 80),
    LowRisk = countif(toint(risk_d) < 50)
| project 
    ["Total Indicators"] = TotalIndicators,
    ["Unique IPs"] = UniqueIPs,
    ["Unique URLs"] = UniqueURLs,
    ["High Risk (≥80)"] = HighRisk,
    ["Medium Risk (50-79)"] = MediumRisk,
    ["Low Risk (<50)"] = LowRisk
'''
            size: 4
            title: 'Threat Intelligence Overview'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'tiles'
            tileSettings: {
              titleContent: {
                columnMatch: 'Column'
                formatter: 1
              }
              leftContent: {
                columnMatch: 'Value'
                formatter: 12
                formatOptions: {
                  palette: 'auto'
                }
              }
              showBorder: true
            }
          }
        }
        // Risk Distribution Chart
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| extend RiskBucket = case(
    toint(risk_d) >= 80, "Critical (80-100)",
    toint(risk_d) >= 60, "High (60-79)",
    toint(risk_d) >= 40, "Medium (40-59)",
    toint(risk_d) >= 20, "Low (20-39)",
    "Minimal (<20)"
)
| summarize Count = count() by RiskBucket, bin(TimeGenerated, 1h)
| render timechart
'''
            size: 0
            title: 'Risk Distribution Over Time'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'timechart'
          }
        }
        // Top Malicious Domains
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| where isnotempty(domain_s)
| extend Domain = tolower(tostring(domain_s))
| summarize 
    Count = count(),
    MaxRisk = max(toint(risk_d)),
    Categories = make_set(category_s),
    Types = make_set(type_s),
    FirstSeen = min(todatetime(firstSeen_t)),
    LastSeen = max(todatetime(lastSeen_t))
    by Domain
| top 20 by MaxRisk desc
| project Domain, MaxRisk, Count, Categories, Types, FirstSeen, LastSeen
'''
            size: 0
            title: 'Top 20 Malicious Domains (by Risk Score)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
            gridSettings: {
              formatters: [
                {
                  columnMatch: 'MaxRisk'
                  formatter: 8
                  formatOptions: {
                    palette: 'redGreen'
                    aggregation: 'Max'
                  }
                }
                {
                  columnMatch: 'FirstSeen'
                  formatter: 6
                }
                {
                  columnMatch: 'LastSeen'
                  formatter: 6
                }
              ]
              filter: true
              sortBy: [
                {
                  itemKey: 'MaxRisk'
                  sortOrder: 2
                }
              ]
            }
          }
        }
        // Threat Categories
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| extend Category = tolower(tostring(category_s))
| where isnotempty(Category)
| summarize Count = count() by Category
| order by Count desc
| render piechart
'''
            size: 1
            title: 'Threat Categories Distribution'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'piechart'
          }
        }
        // Threat Types
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| extend Type = tolower(tostring(type_s))
| where isnotempty(Type)
| summarize Count = count() by Type
| order by Count desc
| render piechart
'''
            size: 1
            title: 'Threat Types Distribution'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'piechart'
          }
        }
        // TacitRed Correlation (if overlap exists)
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
let CyrenDomains = Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| extend d = tolower(tostring(domain_s))
| extend u = tostring(url_s)
| extend host = iif(isnotempty(d), d, extract(@"://([^/]+)", 1, u))
| extend p = split(host, '.')
| extend RegDomain = iif(array_length(p) >= 2, strcat(p[-2], '.', p[-1]), host)
| where isnotempty(RegDomain)
| summarize 
    CyrenCount = count(),
    MaxRisk = max(toint(risk_d)),
    CyrenCategories = make_set(category_s),
    CyrenTypes = make_set(type_s)
    by RegDomain;

let TacitRedDomains = TacitRed_Findings_CL
| where TimeGenerated {TimeRange}
| extend d = tolower(tostring(domain_s))
| extend p = split(d, '.')
| extend RegDomain = iif(array_length(p) >= 2, strcat(p[-2], '.', p[-1]), d)
| where isnotempty(RegDomain)
| summarize 
    CompromisedUsers = dcount(tostring(email_s)),
    TacitRedCount = count(),
    FindingTypes = make_set(tostring(findingType_s))
    by RegDomain;

CyrenDomains
| join kind=inner (TacitRedDomains) on RegDomain
| project 
    Domain = RegDomain,
    ["Cyren Risk"] = MaxRisk,
    ["Cyren Indicators"] = CyrenCount,
    ["TacitRed Findings"] = TacitRedCount,
    ["Compromised Users"] = CompromisedUsers,
    ["Cyren Categories"] = CyrenCategories,
    ["Cyren Types"] = CyrenTypes,
    ["Finding Types"] = FindingTypes
| order by MaxRisk desc
'''
            size: 0
            title: 'TacitRed ↔ Cyren Correlation (Overlapping Domains)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
            gridSettings: {
              formatters: [
                {
                  columnMatch: 'Cyren Risk'
                  formatter: 8
                  formatOptions: {
                    min: 0
                    max: 100
                    palette: 'redGreen'
                  }
                }
                {
                  columnMatch: 'Compromised Users'
                  formatter: 4
                  formatOptions: {
                    palette: 'red'
                  }
                }
              ]
              filter: true
            }
          }
        }
        // Recent High-Risk Indicators
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated {TimeRange}
| where toint(risk_d) >= 70
| extend 
    URL = tostring(url_s),
    IP = tostring(ip_s),
    Domain = tolower(tostring(domain_s)),
    Risk = toint(risk_d),
    Category = tolower(tostring(category_s)),
    Type = tolower(tostring(type_s)),
    LastSeen = todatetime(lastSeen_t)
| project TimeGenerated, Risk, Domain, URL, IP, Category, Type, LastSeen
| order by TimeGenerated desc
| take 50
'''
            size: 0
            title: 'Recent High-Risk Indicators (Risk ≥ 70)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
            gridSettings: {
              formatters: [
                {
                  columnMatch: 'TimeGenerated'
                  formatter: 6
                }
                {
                  columnMatch: 'Risk'
                  formatter: 18
                  formatOptions: {
                    thresholdsOptions: 'icons'
                    thresholdsGrid: [
                      { operator: '>=' value: '90' icon: 'Sev0' }
                      { operator: '>=' value: '70' icon: 'Sev1' }
                      { operator: 'Default' icon: 'Sev2' }
                    ]
                  }
                }
                {
                  columnMatch: 'LastSeen'
                  formatter: 6
                }
              ]
              filter: true
              sortBy: [
                {
                  itemKey: 'TimeGenerated'
                  sortOrder: 2
                }
              ]
            }
          }
        }
        // Ingestion Health
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
Cyren_Indicators_CL
| where TimeGenerated > ago(7d)
| summarize Count = count() by bin(TimeGenerated, 1h)
| render timechart
'''
            size: 0
            title: 'Ingestion Volume (Last 7 Days)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'timechart'
          }
        }
      ]
      styleSettings: {}
      $schema: 'https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json'
    })
    version: '1.0'
    sourceId: workspaceId
    category: 'sentinel'
  }
}

output workbookId string = cyrenWorkbook.id
