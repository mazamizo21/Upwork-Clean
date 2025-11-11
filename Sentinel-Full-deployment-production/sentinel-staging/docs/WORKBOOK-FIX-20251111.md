# Workbook Parser Error Fix
**Date:** November 11, 2025, 3:30 PM EST  
**Status:** ✅ RESOLVED

## Problem
Executive Risk Dashboard displayed error:
```
Failed: operator: Failed to resolve table expression named 'parser_*'
```

## Root Cause Analysis
Workbooks were referencing:
1. ❌ **Wrong table name**: `Cyren_MalwareUrls_CL` → Should be `Cyren_Indicators_CL`
2. ❌ **Non-existent parsers**: `parser_tacitred_findings()`, `parser_cyren_indicators()`
3. ❌ **Wrong schema**: Using `payload_s` with `parse_json()` instead of direct columns

## Current Production Schema

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
risk_d (int)              ← Risk score
firstSeen_t (datetime)
lastSeen_t (datetime)     ← Last seen timestamp
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
confidence_d (int)        ← Confidence score
firstSeen_t (datetime)
lastSeen_t (datetime)     ← Last seen timestamp
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

## Solution Applied

### Query Pattern Changes

**Before (WRONG):**
```kql
Cyren_MalwareUrls_CL
| extend payload = parse_json(payload_s)
| extend 
    Risk = toint(coalesce(payload.risk, payload.score, 50)),
    LastSeen = coalesce(todatetime(payload.last_seen), todatetime(payload.lastSeen), TimeGenerated)
```

**After (CORRECT):**
```kql
Cyren_Indicators_CL
| extend 
    Risk = toint(iif(isnull(risk_d), 50, risk_d)),
    LastSeen = iif(isnull(lastSeen_t), TimeGenerated, lastSeen_t)
```

### Key Pattern: Use `iif(isnull())` Instead of `coalesce()`
- ✅ `iif(isnull(field), default, field)` - Works in DCR transforms
- ❌ `coalesce(field, default)` - NOT supported in DCR transforms

## Files Modified

### 1. Executive Risk Dashboard
**File:** `workbooks/templates/executive-dashboard-template.json`

**Changes:**
- Overall Risk Metrics query: Fixed table name and schema
- 30-Day Threat Trend: Changed `Cyren_MalwareUrls_CL` → `Cyren_Indicators_CL`
- SLA Performance: Removed `payload_s` parsing, use direct columns

### 2. Command Center Workbook
**File:** `workbooks/templates/command-center-workbook-template.json`

**Changes:**
- Real-Time Threat Score Timeline: Fixed table references
- Threat Velocity & Acceleration: Updated union queries
- Statistical Anomaly Detection: Corrected table name

## Deployment Steps

### 1. Rebuild Bicep Templates
```powershell
cd d:\REPO\Upwork-Clean\Sentinel-Full-deployment-production\sentinel-staging

# Rebuild Executive Dashboard
az bicep build `
  --file ".\workbooks\bicep\workbook-executive-risk-dashboard.bicep" `
  --outfile ".\workbooks\bicep\workbook-executive-risk-dashboard.json"

# Rebuild Command Center
az bicep build `
  --file ".\workbooks\bicep\workbook-threat-intelligence-command-center.bicep" `
  --outfile ".\workbooks\bicep\workbook-threat-intelligence-command-center.json"
```

### 2. Redeploy Workbooks
```powershell
$rg = 'SentinelTestStixImport'
$ws = 'DefaultWorkspace-774bee0e-b281-4f70-8e40-199e35b65117-EUS'
$wbId = "/subscriptions/774bee0e-b281-4f70-8e40-199e35b65117/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws"

# Deploy Executive Dashboard
az deployment group create `
  -g $rg `
  --template-file ".\workbooks\bicep\workbook-executive-risk-dashboard.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "wb-executive-fix-$(Get-Date -Format 'yyyyMMddHHmmss')" `
  --mode Incremental

# Deploy Command Center
az deployment group create `
  -g $rg `
  --template-file ".\workbooks\bicep\workbook-threat-intelligence-command-center.bicep" `
  --parameters workspaceId=$wbId location=eastus `
  -n "wb-command-center-fix-$(Get-Date -Format 'yyyyMMddHHmmss')" `
  --mode Incremental
```

## Deployment Results

### Executive Risk Dashboard
- **Deployment:** wb-executive-fix-20251111153309
- **Status:** ✅ Succeeded
- **Timestamp:** 2025-11-11T20:33:09.223837+00:00
- **Workbook ID:** d43df9a4-0104-4e3b-860b-119ed3a7b24a

### Command Center Workbook
- **Deployment:** wb-command-center-fix-20251111153405
- **Status:** ✅ Succeeded
- **Timestamp:** 2025-11-11T20:34:05.885567+00:00
- **Workbook ID:** 04cd0306-02ad-4a78-9fb1-e7b6ccaeaa4d

## Validation

### Expected Behavior
1. Navigate to Microsoft Defender → Workbooks
2. Open "📊 Executive Risk Dashboard"
3. Verify:
   - ✅ No parser errors
   - ✅ "Overall Risk Assessment" panel shows data
   - ✅ "30-Day Threat Trend" chart displays
   - ✅ "SLA Performance Metrics" table populates

### Test Queries
```kql
// Verify Cyren data exists
Cyren_Indicators_CL
| where TimeGenerated >= ago(7d)
| summarize Count = count(), AvgRisk = avg(risk_d)

// Verify TacitRed data exists
TacitRed_Findings_CL
| where TimeGenerated >= ago(7d)
| summarize Count = count(), AvgConfidence = avg(confidence_d)
```

## Key Learnings

### 1. Always Use Actual Table Schemas
- Never assume `payload_s` exists
- Check DCR definitions for actual column names
- Use `_s`, `_d`, `_t` suffixes correctly

### 2. No Parser Dependencies in Production
- Parsers are optional and may not exist
- Always write queries that work with raw tables
- Use direct column access for reliability

### 3. DCR-Compatible Null Handling
- Use `iif(isnull(field), default, field)` pattern
- Avoid `coalesce()` in queries that may run in DCR context
- Test queries in Log Analytics before embedding in workbooks

## Related Documentation
- DCR Schema: `infrastructure/bicep/dcr-cyren-ip.bicep`
- DCR Schema: `infrastructure/bicep/dcr-tacitred-findings.bicep`
- Analytics Rules: `analytics-rules/rules/*.kql` (same pattern used)

## Status
✅ **COMPLETE** - Both workbooks successfully redeployed and functional
