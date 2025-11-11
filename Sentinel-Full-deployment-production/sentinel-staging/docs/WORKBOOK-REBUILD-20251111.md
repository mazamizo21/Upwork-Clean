# Complete Workbook Rebuild & Deployment
**Date:** November 11, 2025, 3:41 PM EST  
**Status:** ✅ ALL WORKBOOKS DEPLOYED SUCCESSFULLY

## Overview
Rebuilt and redeployed all 4 production workbooks with corrected schemas and advanced KQL queries.

## Workbooks Deployed

### 1. 📊 Executive Risk Dashboard
**Purpose:** Business impact metrics and C-level visibility  
**Template:** `workbooks/templates/executive-dashboard-template.json`  
**Bicep:** `workbooks/bicep/workbook-executive-risk-dashboard.bicep`  
**Status:** ✅ Deployed  

**Key Features:**
- Overall Risk Assessment with business impact scoring
- 30-Day Threat Trend visualization
- SLA Performance Metrics
- Financial risk exposure calculations

**Schema Corrections:**
- Fixed: `Cyren_MalwareUrls_CL` → `Cyren_Indicators_CL`
- Fixed: Removed `payload_s` parsing
- Fixed: Direct column access (`risk_d`, `lastSeen_t`, etc.)

---

### 2. 🎯 Threat Intelligence Command Center
**Purpose:** Real-time operational dashboard with predictive analytics  
**Template:** `workbooks/templates/command-center-workbook-template.json`  
**Bicep:** `workbooks/bicep/workbook-threat-intelligence-command-center.bicep`  
**Status:** ✅ Deployed  

**Key Features:**
- Real-Time Threat Score Timeline
- Threat Velocity & Acceleration metrics
- Statistical Anomaly Detection
- Cross-feed correlation analysis

**Schema Corrections:**
- Fixed: `Cyren_MalwareUrls_CL` → `Cyren_Indicators_CL`
- Fixed: Removed parser function calls
- Fixed: Use `iif(isnull())` pattern for null handling

---

### 3. 🔍 Threat Hunter's Arsenal
**Purpose:** Advanced investigation and correlation capabilities  
**Template:** `workbooks/templates/hunters-arsenal-template.json`  
**Bicep:** `workbooks/bicep/workbook-threat-hunters-arsenal.bicep`  
**Status:** ✅ Deployed  

**Key Features:**
- Rapid Credential Reuse Detection
- Persistent Infrastructure Identification
- Attack Chain Reconstruction
- MITRE ATT&CK Mapping
- IOC Multi-Context Enrichment

**Advanced KQL Queries Created:**
- `workbooks/kql/threat-hunting-advanced.kql` - Behavioral analytics
- `workbooks/kql/cross-feed-correlation.kql` - Multi-source correlation
- `workbooks/kql/mitre-attack-mapping.kql` - ATT&CK framework mapping

---

### 4. 🌐 Cyren Threat Intelligence
**Purpose:** Cyren-specific threat analysis and visualization  
**Bicep:** `workbooks/bicep/workbook-cyren-threat-intelligence.bicep`  
**Status:** ✅ Deployed  

**Key Features:**
- Cyren indicator analysis
- Category breakdown
- Risk distribution
- Geographic analysis (if available)

---

## Advanced KQL Queries Created

### 1. Cross-Feed Correlation Analysis
**File:** `workbooks/kql/cross-feed-correlation.kql`  
**Innovation:** Advanced multi-source threat correlation

**Features:**
- Domain overlap detection between Cyren and TacitRed
- Temporal correlation analysis
- Correlation strength scoring (0-100)
- Attack pattern inference
- Campaign detection

**Key Metrics:**
- Correlation Strength (multi-factor scoring)
- Threat Impact Assessment
- Attack Pattern Classification
- Campaign Indicators

---

### 2. Executive Risk Metrics
**File:** `workbooks/kql/executive-risk-metrics.kql`  
**Innovation:** Translates technical threats into business risk language

**Features:**
- Financial risk exposure calculations
- Business impact scoring
- SLA compliance metrics
- Trend analysis with moving averages

**Key Metrics:**
- Estimated Financial Risk ($USD)
- Potential Impact Score
- Overall Risk Level
- Risk Exposure Trend

---

### 3. MITRE ATT&CK Mapping
**File:** `workbooks/kql/mitre-attack-mapping.kql`  
**Innovation:** Automated technique mapping from threat intelligence

**Tactics Covered:**
- **TA0001** - Initial Access (Phishing, Exploits)
- **TA0003** - Persistence (Compromise Infrastructure, Valid Accounts)
- **TA0006** - Credential Access (Credential Dumping, Keylogging)
- **TA0011** - Command and Control (DNS, Web Protocols)

**Features:**
- Automatic technique detection
- Tactic coverage heatmap
- Technique severity scoring
- Priority-based investigation queue

---

### 4. Advanced Threat Hunting
**File:** `workbooks/kql/threat-hunting-advanced.kql`  
**Innovation:** Behavioral analytics + IOC pivot + Timeline reconstruction

**Hunting Patterns:**
- **Rapid Credential Reuse** - Detects bot/spray attacks
- **Persistent Infrastructure** - Long-lived malware domains
- **Attack Chain Reconstruction** - Links credentials to malware
- **Multi-Context IOCs** - Indicators across multiple threat contexts

**Scoring Algorithms:**
- Behavior Score (0-100)
- Persistence Score (0-100)
- Chain Likelihood Assessment
- Investigation Priority Ranking

---

### 5. Advanced Threat Scoring
**File:** `workbooks/kql/threat-scoring-advanced.kql`  
**Innovation:** Multi-factor composite scoring with weighted factors

**Scoring Factors:**

**Cyren Threats:**
- Recency Score (35% weight) - How recent is the threat?
- Persistence Score (20% weight) - How long has it existed?
- Risk Score (30% weight) - Cyren's risk rating
- Relationship Score (15% weight) - Infrastructure connections

**TacitRed Threats:**
- Recency Score (35% weight) - How recent is the compromise?
- Freshness Score (25% weight) - How new is the finding?
- Confidence Score (25% weight) - TacitRed's confidence level
- Status Score (15% weight) - Active/Unresolved/Investigating

**Output:**
- Composite Threat Score (0-100)
- Severity Classification (Critical/High/Medium/Low)
- Activity Status (Active Now/Active 24h/Recent/Historical)

---

## Schema Reference

### Cyren_Indicators_CL
```
TimeGenerated (datetime)
url_s (string)
ip_s (string)
fileHash_s (string)
domain_s (string)
protocol_s (string)
port_d (int)
category_s (string)
risk_d (int)              ← Risk score (0-100)
firstSeen_t (datetime)
lastSeen_t (datetime)
source_s (string)
relationships_s (string)
detection_methods_s (string)
action_s (string)
type_s (string)
identifier_s (string)
detection_ts_t (datetime)
object_type_s (string)
```

### TacitRed_Findings_CL
```
TimeGenerated (datetime)
email_s (string)
domain_s (string)
findingType_s (string)
confidence_d (int)        ← Confidence score (0-100)
firstSeen_t (datetime)
lastSeen_t (datetime)
notes_s (string)
source_s (string)
severity_s (string)
status_s (string)
campaign_id_s (string)
user_id_s (string)
username_s (string)
detection_ts_t (datetime)
metadata_s (string)
```

---

## Build & Deployment Process

### Step 1: Build Bicep Templates
```powershell
cd d:\REPO\Upwork-Clean\Sentinel-Full-deployment-production\sentinel-staging

# Build all workbook Bicep files to ARM JSON
az bicep build --file ".\workbooks\bicep\workbook-executive-risk-dashboard.bicep"
az bicep build --file ".\workbooks\bicep\workbook-threat-intelligence-command-center.bicep"
az bicep build --file ".\workbooks\bicep\workbook-threat-hunters-arsenal.bicep"
az bicep build --file ".\workbooks\bicep\workbook-cyren-threat-intelligence.bicep"
az bicep build --file ".\workbooks\bicep\deploy-all-workbooks.bicep"
```

### Step 2: Deploy All Workbooks
```powershell
$rg = 'SentinelTestStixImport'
$ws = 'DefaultWorkspace-774bee0e-b281-4f70-8e40-199e35b65117-EUS'
$wbId = "/subscriptions/774bee0e-b281-4f70-8e40-199e35b65117/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws"
$ts = Get-Date -Format 'yyyyMMddHHmmss'

# Deploy each workbook
az deployment group create -g $rg `
  --template-file ".\workbooks\bicep\workbook-executive-risk-dashboard.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "workbook-executive-risk-dashboard-$ts" --mode Incremental

az deployment group create -g $rg `
  --template-file ".\workbooks\bicep\workbook-threat-intelligence-command-center.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "workbook-threat-intelligence-command-center-$ts" --mode Incremental

az deployment group create -g $rg `
  --template-file ".\workbooks\bicep\workbook-threat-hunters-arsenal.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "workbook-threat-hunters-arsenal-$ts" --mode Incremental

az deployment group create -g $rg `
  --template-file ".\workbooks\bicep\workbook-cyren-threat-intelligence.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "workbook-cyren-threat-intelligence-$ts" --mode Incremental
```

---

## Deployment Results

### Timestamp: 2025-11-11 15:41:00 EST

| Workbook | Status | Deployment Name |
|----------|--------|----------------|
| Executive Risk Dashboard | ✅ Success | workbook-executive-risk-dashboard-20251111154100 |
| Threat Intelligence Command Center | ✅ Success | workbook-threat-intelligence-command-center-20251111154100 |
| Threat Hunter's Arsenal | ✅ Success | workbook-threat-hunters-arsenal-20251111154100 |
| Cyren Threat Intelligence | ✅ Success | workbook-cyren-threat-intelligence-20251111154100 |

**Total:** 4/4 workbooks deployed successfully

---

## Validation Steps

### 1. Access Workbooks
1. Navigate to **Microsoft Defender** → **Workbooks**
2. Verify all 4 workbooks are listed
3. Open each workbook to confirm no errors

### 2. Test Queries
```kql
// Verify Cyren data
Cyren_Indicators_CL
| where TimeGenerated >= ago(7d)
| summarize Count = count(), AvgRisk = avg(risk_d)

// Verify TacitRed data
TacitRed_Findings_CL
| where TimeGenerated >= ago(7d)
| summarize Count = count(), AvgConfidence = avg(confidence_d)

// Test correlation
let cyren = Cyren_Indicators_CL | where TimeGenerated >= ago(7d) | extend Domain = tolower(domain_s);
let tacit = TacitRed_Findings_CL | where TimeGenerated >= ago(7d) | extend Domain = tolower(domain_s);
cyren | join kind=inner (tacit) on Domain | summarize OverlapCount = count()
```

### 3. Expected Behavior
- ✅ No parser errors
- ✅ All visualizations render
- ✅ Time range selectors work
- ✅ Data populates in all panels
- ✅ Drill-down functionality works

---

## Key Improvements

### Schema Corrections
- ✅ All workbooks use correct table names
- ✅ Direct column access (no `payload_s` parsing)
- ✅ Proper null handling with `iif(isnull())` pattern
- ✅ No parser function dependencies

### Advanced Analytics
- ✅ Multi-factor threat scoring algorithms
- ✅ Behavioral anomaly detection
- ✅ Attack chain reconstruction
- ✅ MITRE ATT&CK framework mapping
- ✅ Cross-feed correlation analysis

### Business Value
- ✅ Executive-level risk metrics
- ✅ Financial impact calculations
- ✅ SLA compliance tracking
- ✅ Trend analysis with predictive insights

---

## Files Modified/Created

### Templates Updated
- `workbooks/templates/executive-dashboard-template.json`
- `workbooks/templates/command-center-workbook-template.json`

### KQL Queries Created
- `workbooks/kql/cross-feed-correlation.kql`
- `workbooks/kql/executive-risk-metrics.kql`
- `workbooks/kql/mitre-attack-mapping.kql`
- `workbooks/kql/threat-hunting-advanced.kql`
- `workbooks/kql/threat-scoring-advanced.kql`

### Bicep Files Rebuilt
- `workbooks/bicep/workbook-executive-risk-dashboard.bicep` → `.json`
- `workbooks/bicep/workbook-threat-intelligence-command-center.bicep` → `.json`
- `workbooks/bicep/workbook-threat-hunters-arsenal.bicep` → `.json`
- `workbooks/bicep/workbook-cyren-threat-intelligence.bicep` → `.json`
- `workbooks/bicep/deploy-all-workbooks.bicep` → `.json`

---

## Next Steps

### 1. Validate Workbooks in Portal
- Open each workbook in Microsoft Defender
- Test all time range selections
- Verify data displays correctly
- Check for any error messages

### 2. User Training
- Share workbook locations with SOC team
- Explain key metrics and visualizations
- Demonstrate drill-down capabilities
- Review investigation workflows

### 3. Continuous Improvement
- Monitor workbook usage
- Gather user feedback
- Add custom queries as needed
- Optimize performance if needed

---

## Related Documentation
- **Fix Report:** `docs/WORKBOOK-FIX-20251111.md`
- **Deployment Guide:** `README-DEPLOYMENT.md`
- **Schema Reference:** `infrastructure/bicep/dcr-*.bicep`
- **Analytics Rules:** `analytics-rules/rules/*.kql`

---

## Status Summary
✅ **COMPLETE** - All 4 workbooks successfully rebuilt and deployed with advanced analytics capabilities
