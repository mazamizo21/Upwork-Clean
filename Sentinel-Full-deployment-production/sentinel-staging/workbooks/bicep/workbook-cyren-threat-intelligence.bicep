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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend 
    Risk = toint(coalesce(payload.risk, payload.score, 50)),
    IP = tostring(coalesce(payload.ip, payload.ipAddress, "")),
    URL = tostring(coalesce(payload.url, payload.malwareUrl, ""))
| summarize 
    TotalIndicators = count(),
    UniqueIPs = dcount(IP),
    UniqueURLs = dcount(URL),
    HighRisk = countif(Risk >= 80),
    MediumRisk = countif(Risk >= 50 and Risk < 80),
    LowRisk = countif(Risk < 50)
'''
            size: 0
            title: 'Threat Intelligence Overview'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
            gridSettings: {
              formatters: [
                {
                  columnMatch: 'TotalIndicators'
                  formatter: 4
                  formatOptions: {
                    palette: 'blue'
                  }
                }
                {
                  columnMatch: 'HighRisk'
                  formatter: 4
                  formatOptions: {
                    palette: 'red'
                  }
                }
              ]
            }
          }
        }
        // Risk Distribution Chart
        {
          type: 3
          content: {
            version: 'KqlItem/1.0'
            query: '''
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend Risk = toint(coalesce(payload.risk, payload.score, 50))
| extend RiskBucket = case(
    Risk >= 80, "Critical (80-100)",
    Risk >= 60, "High (60-79)",
    Risk >= 40, "Medium (40-59)",
    Risk >= 20, "Low (20-39)",
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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend 
    Domain = tolower(tostring(coalesce(payload.domain, payload.host, ""))),
    Risk = toint(coalesce(payload.risk, payload.score, 50)),
    Category = tostring(coalesce(payload.category, payload.type, "")),
    FirstSeen = coalesce(todatetime(payload.firstSeen), todatetime(payload.first_seen), TimeGenerated),
    LastSeen = coalesce(todatetime(payload.lastSeen), todatetime(payload.last_seen), TimeGenerated)
| where isnotempty(Domain)
| summarize 
    Count = count(),
    MaxRisk = max(Risk),
    Categories = make_set(Category),
    EarliestSeen = min(FirstSeen),
    LatestSeen = max(LastSeen)
    by Domain
| top 20 by MaxRisk desc
| project Domain, MaxRisk, Count, Categories, FirstSeen = EarliestSeen, LastSeen = LatestSeen
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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend Category = tolower(tostring(coalesce(payload.category, payload.type, "unknown")))
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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend Type = tolower(tostring(coalesce(payload.type, payload.indicatorType, "unknown")))
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
let CyrenDomains = union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend 
    d = tolower(tostring(coalesce(payload.domain, payload.host, ""))),
    u = tostring(coalesce(payload.url, payload.malwareUrl, "")),
    Risk = toint(coalesce(payload.risk, payload.score, 50)),
    Category = tostring(coalesce(payload.category, payload.type, ""))
| extend host = iif(isnotempty(d), d, extract(@"://([^/]+)", 1, u))
| extend p = split(host, '.')
| extend RegDomain = iif(array_length(p) >= 2, strcat(p[-2], '.', p[-1]), host)
| where isnotempty(RegDomain)
| summarize 
    CyrenCount = count(),
    MaxRisk = max(Risk),
    CyrenCategories = make_set(Category)
    by RegDomain;

let TacitRedDomains = TacitRed_Findings_CL
| where TimeGenerated {TimeRange}
| extend 
    d = tolower(tostring(domain_s)),
    Email = tostring(coalesce(email_s, username_s, "")),
    FindingType = tostring(findingType_s)
| extend p = split(d, '.')
| extend RegDomain = iif(array_length(p) >= 2, strcat(p[-2], '.', p[-1]), d)
| where isnotempty(RegDomain)
| summarize 
    CompromisedUsers = dcount(Email),
    TacitRedCount = count(),
    FindingTypes = make_set(FindingType)
    by RegDomain;

CyrenDomains
| join kind=inner (TacitRedDomains) on RegDomain
| project 
    Domain = RegDomain,
    CyrenRisk = MaxRisk,
    CyrenIndicators = CyrenCount,
    TacitRedFindings = TacitRedCount,
    CompromisedUsers,
    CyrenCategories,
    FindingTypes
| order by CyrenRisk desc
'''
            size: 0
            title: 'TacitRed ↔ Cyren Correlation (Overlapping Domains)'
            queryType: 0
            resourceType: 'microsoft.operationalinsights/workspaces'
            visualization: 'table'
            gridSettings: {
              formatters: [
                {
                  columnMatch: 'CyrenRisk'
                  formatter: 8
                  formatOptions: {
                    min: 0
                    max: 100
                    palette: 'redGreen'
                  }
                }
                {
                  columnMatch: 'CompromisedUsers'
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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
| where TimeGenerated {TimeRange}
| extend payload = parse_json(payload_s)
| extend 
    Risk = toint(coalesce(payload.risk, payload.score, 50)),
    URL = tostring(coalesce(payload.url, payload.malwareUrl, "")),
    IP = tostring(coalesce(payload.ip, payload.ipAddress, "")),
    Domain = tolower(tostring(coalesce(payload.domain, payload.host, ""))),
    Category = tolower(tostring(coalesce(payload.category, payload.type, ""))),
    LastSeen = coalesce(todatetime(payload.lastSeen), todatetime(payload.last_seen), TimeGenerated)
| where Risk >= 70
| project TimeGenerated, Risk, Domain, URL, IP, Category, LastSeen
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
                      { operator: '>=', value: '90', icon: 'Sev0' }
                      { operator: '>=', value: '70', icon: 'Sev1' }
                      { operator: 'Default', icon: 'Sev2' }
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
union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL
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
      '$schema': 'https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json'
    })
    version: '1.0'
    sourceId: workspaceId
    category: 'sentinel'
  }
}

output workbookId string = cyrenWorkbook.id
