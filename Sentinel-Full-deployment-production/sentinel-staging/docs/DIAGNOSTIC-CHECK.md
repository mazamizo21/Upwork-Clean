# Diagnostic Check - Why Query Fails

**Date**: November 10, 2025, 08:28 AM  
**Issue**: "Failed to resolve scalar expression named 'domain_s'"  
**Root Cause**: Tables don't exist OR have no data yet

---

## 🔍 Run These Diagnostic Queries

Copy and paste each query into Log Analytics → Logs to diagnose the issue:

### 1. Check if TacitRed table exists
```kql
search *
| where $table == "TacitRed_Findings_CL"
| take 1
```

**Expected Results**:
- ✅ Returns 1 row → Table exists and has data
- ⚠️  Empty result → Table exists but NO data yet
- ❌ Error "table not found" → Table doesn't exist

### 2. Check if Cyren table exists
```kql
search *
| where $table == "Cyren_Indicators_CL"
| take 1
```

**Expected Results**:
- ✅ Returns 1 row → Table exists and has data
- ⚠️  Empty result → Table exists but NO data yet
- ❌ Error "table not found" → Table doesn't exist

### 3. Check table schema (if table exists)
```kql
TacitRed_Findings_CL
| getschema
```

```kql
Cyren_Indicators_CL
| getschema
```

**What to Look For**:
- Should see columns: `domain_s`, `email_s`, `findingType_s`, etc.
- If error → Table not created yet

### 4. List all custom log tables
```kql
search *
| distinct $table
| where $table endswith "_CL"
| sort by $table asc
```

**What to Look For**:
- `TacitRed_Findings_CL` in the list?
- `Cyren_Indicators_CL` in the list?

---

## 📊 Diagnostic Results Guide

### Scenario A: Tables Don't Exist ❌

**Error**: "Failed to resolve table"  
**Cause**: Tables haven't been created yet  
**Solution**: Tables are created automatically when first data is ingested via DCR

**Action Required**:
1. Verify Data Collection Rules (DCRs) are deployed
2. Verify data connectors (Function App, Logic Apps) are running
3. Check data is flowing from APIs
4. Tables will be created on first data ingestion

### Scenario B: Tables Exist BUT No Data ⚠️

**Error**: "Failed to resolve scalar expression named 'domain_s'"  
**Cause**: Tables exist but schema not finalized (no data yet)  
**Solution**: Wait for first data ingestion OR manually create table schema

**Action Required**:
1. Check data connectors are running and successfully ingesting
2. Review Function App / Logic App execution logs
3. Verify API keys and connections are valid
4. Wait for first successful data ingestion

### Scenario C: Tables Have Data ✅

**Error**: Should NOT get errors  
**Cause**: If you still get errors, it's a query syntax issue  
**Solution**: Use the corrected query

---

## 🚀 Solutions Based on Diagnostic

### If Tables Don't Exist → Option 1: Create Tables Manually

```powershell
# Get workspace ID
$subscriptionId = "774bee0e-b281-4f70-8e40-199e35b65117"
$resourceGroup = "YOUR-RESOURCE-GROUP"
$workspaceName = "YOUR-WORKSPACE-NAME"

az account set --subscription $subscriptionId

$workspace = az monitor log-analytics workspace show `
    --resource-group $resourceGroup `
    --workspace-name $workspaceName `
    -o json | ConvertFrom-Json

$workspaceId = $workspace.id

# Create TacitRed_Findings_CL table
$tacitredSchema = @"
{
  "properties": {
    "schema": {
      "name": "TacitRed_Findings_CL",
      "columns": [
        {"name": "TimeGenerated", "type": "datetime"},
        {"name": "email_s", "type": "string"},
        {"name": "domain_s", "type": "string"},
        {"name": "findingType_s", "type": "string"},
        {"name": "confidence_d", "type": "int"},
        {"name": "firstSeen_t", "type": "datetime"},
        {"name": "lastSeen_t", "type": "datetime"},
        {"name": "notes_s", "type": "string"},
        {"name": "source_s", "type": "string"},
        {"name": "severity_s", "type": "string"},
        {"name": "status_s", "type": "string"},
        {"name": "campaign_id_s", "type": "string"},
        {"name": "user_id_s", "type": "string"},
        {"name": "username_s", "type": "string"},
        {"name": "detection_ts_t", "type": "datetime"},
        {"name": "metadata_s", "type": "string"}
      ]
    }
  }
}
"@

$tempFile = [System.IO.Path]::GetTempFileName()
$tacitredSchema | Out-File -FilePath $tempFile -Encoding UTF8

az rest --method PUT `
    --uri "$workspaceId/tables/TacitRed_Findings_CL?api-version=2022-10-01" `
    --body "@$tempFile"

Remove-Item $tempFile

# Create Cyren_Indicators_CL table
$cyrenSchema = @"
{
  "properties": {
    "schema": {
      "name": "Cyren_Indicators_CL",
      "columns": [
        {"name": "TimeGenerated", "type": "datetime"},
        {"name": "url_s", "type": "string"},
        {"name": "ip_s", "type": "string"},
        {"name": "fileHash_s", "type": "string"},
        {"name": "domain_s", "type": "string"},
        {"name": "protocol_s", "type": "string"},
        {"name": "port_d", "type": "int"},
        {"name": "category_s", "type": "string"},
        {"name": "risk_d", "type": "int"},
        {"name": "firstSeen_t", "type": "datetime"},
        {"name": "lastSeen_t", "type": "datetime"},
        {"name": "source_s", "type": "string"},
        {"name": "relationships_s", "type": "string"},
        {"name": "detection_methods_s", "type": "string"},
        {"name": "action_s", "type": "string"},
        {"name": "type_s", "type": "string"},
        {"name": "identifier_s", "type": "string"},
        {"name": "detection_ts_t", "type": "datetime"},
        {"name": "object_type_s", "type": "string"}
      ]
    }
  }
}
"@

$tempFile2 = [System.IO.Path]::GetTempFileName()
$cyrenSchema | Out-File -FilePath $tempFile2 -Encoding UTF8

az rest --method PUT `
    --uri "$workspaceId/tables/Cyren_Indicators_CL?api-version=2022-10-01" `
    --body "@$tempFile2"

Remove-Item $tempFile2

Write-Host "Tables created! Wait 30 seconds for propagation..." -ForegroundColor Green
Start-Sleep -Seconds 30
```

### If Tables Exist But No Data → Option 2: Use ThreatIntelligenceIndicator

**Alternative**: Use the built-in `ThreatIntelligenceIndicator` table which always exists:

```kql
ThreatIntelligenceIndicator
| where TimeGenerated >= ago(8h)
| where isnotempty(DomainName)
| where ThreatType in ("Malware", "Phishing")
| summarize 
    IndicatorCount = count(),
    ThreatTypes = make_set(ThreatType),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DomainName
| order by LastSeen desc
```

This will work immediately without waiting for custom tables!

---

## 📝 Recommendation

**IMMEDIATE**: Run diagnostic queries above to identify which scenario you're in, then:

1. **If tables don't exist**: Create them manually using the PowerShell script
2. **If tables exist but no data**: Check data connector logs and wait for ingestion
3. **As temporary workaround**: Use `ThreatIntelligenceIndicator` table

Once diagnostics complete, report back what you find and I'll provide the exact next step.

---

**Created**: November 10, 2025, 08:28 AM  
**Purpose**: Diagnose why Analytics rule query fails  
**Next Step**: Run diagnostic queries and report results
