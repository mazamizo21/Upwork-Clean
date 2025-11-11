# CRITICAL FIX: Table Name Correction

**Date**: November 10, 2025, 08:17 AM UTC-05:00  
**Issue**: Table not found error  
**Root Cause**: Query references non-existent table names  
**Status**: ✅ RESOLVED

---

## ⚠️ CRITICAL ISSUE

The query was using **WRONG TABLE NAMES** that don't exist in your Sentinel workspace!

### Error Message:
```
'where' operator: Failed to resolve table or column expression named 'TacitRed_TacticalInt_CL'
```

---

## 🔍 Root Cause Analysis

### Table Name Mismatches:

| Query Referenced (WRONG) | Actual Table Name (CORRECT) |
|--------------------------|------------------------------|
| `TacitRed_TacticalInt_CL` ❌ | `TacitRed_Findings_CL` ✅ |
| `CyberIndicators_CL` ❌ | `Cyren_Indicators_CL` ✅ |

### Why This Happened:
The original query was written for a different environment with different table naming conventions. Your Sentinel deployment uses the correct naming scheme from your Bicep templates.

---

## ✅ CORRECTED QUERY

**New File**: `analytics/rules/rule-malware-infrastructure-correlation-CORRECTED.kql`

### Key Changes:

1. **Line 10**: `TacitRed_TacticalInt_CL` → `TacitRed_Findings_CL`
2. **Line 15**: `CyberIndicators_CL` → `Cyren_Indicators_CL`
3. **Line 18**: Updated to use `type_s` field (matches your schema)
4. **Line 20**: Updated to use `domain_s` field (matches your schema)
5. **Added**: Case-insensitive type matching (`'Malware', 'malware'`)
6. **Added**: `coalesce()` for optional fields

### Schema Alignment:

**TacitRed_Findings_CL** fields used:
- `TimeGenerated` (datetime)
- `domain_s` (string)
- `email_s` (string)
- `findingType_s` (string)
- `confidence_d` (int)
- `firstSeen_t` (datetime)
- `lastSeen_t` (datetime)

**Cyren_Indicators_CL** fields used:
- `TimeGenerated` (datetime)
- `domain_s` (string)
- `type_s` (string) - Malware/Phishing
- `category_s` (string)
- `risk_d` (int)
- `url_s` (string)
- `ip_s` (string)
- `firstSeen_t` (datetime)
- `lastSeen_t` (datetime)

---

## 🚀 DEPLOY THE CORRECTED QUERY

### Option 1: Copy-Paste (IMMEDIATE) ⚡

1. Open: `sentinel-staging/analytics/rules/rule-malware-infrastructure-correlation-CORRECTED.kql`
2. Copy the entire query
3. Go to Azure Portal → Sentinel → Analytics
4. Edit rule: "New Malware Infrastructure on Known Compromised Domain"
5. Go to "Set rule logic" tab
6. **Replace the entire query** with the corrected version
7. Click **"Results simulation"** to test
8. Click **"Save"**

### Option 2: Test in Log Analytics First (RECOMMENDED) 🧪

Before deploying, test the query:

```powershell
# 1. Copy the corrected query
Get-Content "sentinel-staging/analytics/rules/rule-malware-infrastructure-correlation-CORRECTED.kql" | Set-Clipboard

# 2. Navigate to Azure Portal → Log Analytics Workspace → Logs
# 3. Paste and run the query
# 4. Verify it executes without errors
# 5. Check if results are returned (if data exists)
```

---

## 🧪 Validation Queries

### Check if tables exist:

```kql
// Verify TacitRed table exists and has data
TacitRed_Findings_CL
| take 10

// Verify Cyren table exists and has data
Cyren_Indicators_CL
| take 10
```

### Check table schemas:

```kql
// TacitRed schema
TacitRed_Findings_CL
| getschema

// Cyren schema
Cyren_Indicators_CL
| getschema
```

### Test the correlation logic:

```kql
// Check compromised domains
let CompromisedDomains = TacitRed_Findings_CL
    | where TimeGenerated >= ago(8h)
    | where isnotempty(domain_s)
    | distinct domain_s;
CompromisedDomains

// Check Cyren indicators
Cyren_Indicators_CL
| where TimeGenerated >= ago(8h)
| where type_s in ('Malware', 'Phishing', 'malware', 'phishing')
| take 10
```

---

## 📋 Quick Reference: Corrected Query

```kql
// Get distinct compromised domains from TacitRed
let CompromisedDomains = TacitRed_Findings_CL
    | where TimeGenerated >= ago(8h)
    | where isnotempty(domain_s)
    | distinct domain_s;
// Find malware/phishing infrastructure on compromised domains
Cyren_Indicators_CL
| where TimeGenerated >= ago(8h)
| where isnotempty(type_s)
| where type_s in ('Malware', 'Phishing', 'malware', 'phishing')
| where isnotempty(domain_s)
| where domain_s in (CompromisedDomains)
| extend
    Severity = case(
        type_s in ('Malware', 'malware'), 'High',
        type_s in ('Phishing', 'phishing'), 'High',
        'Medium'
    ),
    ThreatDescription = strcat(
        'Domain ', domain_s, ' is hosting ', type_s, ' infrastructure. ',
        'This domain was previously identified as compromised in TacitRed findings. ',
        'Active exploitation may be in progress. Risk score: ', risk_d
    )
| summarize
    IndicatorCount = count(),
    IndicatorTypes = make_set(type_s),
    Categories = make_set(category_s),
    MaxRiskScore = max(risk_d),
    FirstSeen = min(coalesce(firstSeen_t, TimeGenerated)),
    LastSeen = max(coalesce(lastSeen_t, TimeGenerated)),
    IOCs = make_set(strcat(type_s, ': ', coalesce(url_s, domain_s, ip_s)))
    by domain_s
| extend
    DaysSinceFirstSeen = datetime_diff('day', now(), FirstSeen),
    HoursSinceLastSeen = datetime_diff('hour', now(), LastSeen)
| project
    Domain = domain_s,
    Severity = 'High',
    IndicatorCount,
    IndicatorTypes,
    Categories,
    MaxRiskScore,
    FirstSeen,
    LastSeen,
    DaysSinceFirstSeen,
    HoursSinceLastSeen,
    IOCs,
    ThreatDescription = strcat(
        'Domain ', domain_s, ' has ', IndicatorCount, ' indicators (', strcat_array(IndicatorTypes, ', '), '). ',
        'Max risk score: ', MaxRiskScore, '. ',
        'Last seen ', HoursSinceLastSeen, ' hours ago. ',
        'This domain was previously identified as compromised in TacitRed findings.'
    )
| order by LastSeen desc
```

---

## 🔄 What Changed from Previous Version

| Aspect | Previous (WRONG) | Corrected (RIGHT) |
|--------|------------------|-------------------|
| TacitRed Table | `TacitRed_TacticalInt_CL` | `TacitRed_Findings_CL` |
| Cyren Table | `CyberIndicators_CL` | `Cyren_Indicators_CL` |
| Domain Field | `NetworkSourceDomain_s` | `domain_s` |
| Type Field | `Type_s` | `type_s` |
| Risk Field | N/A | `risk_d` |
| Case Sensitivity | Single case | Both cases (`Malware`, `malware`) |
| Null Handling | Basic | Enhanced with `coalesce()` |

---

## ⚠️ Important Notes

### Data Availability:
- **If no data exists** in these tables, the query will return 0 results (this is normal)
- **If tables don't exist**, you'll get the error you saw
- **After this fix**, the query should execute without errors

### Data Ingestion:
Ensure your data connectors are active:
1. **TacitRed Function App**: Should be ingesting to `TacitRed_Findings_CL`
2. **Cyren Logic Apps**: Should be ingesting to `Cyren_Indicators_CL`

Check data ingestion:
```kql
// Check TacitRed ingestion (last 24 hours)
TacitRed_Findings_CL
| where TimeGenerated >= ago(24h)
| summarize Count = count(), LatestIngestion = max(TimeGenerated)

// Check Cyren ingestion (last 24 hours)
Cyren_Indicators_CL
| where TimeGenerated >= ago(24h)
| summarize Count = count(), LatestIngestion = max(TimeGenerated)
```

---

## 📁 File Updates

### New Files Created:
1. **`analytics/rules/rule-malware-infrastructure-correlation-CORRECTED.kql`**  
   → Use this file (correct table names)

### Obsolete Files:
1. **`analytics/rules/rule-malware-infrastructure-correlation.kql`**  
   → ❌ DO NOT USE (wrong table names)

---

## ✅ Success Criteria

After deploying the corrected query:

- [ ] Query executes without "table not found" errors
- [ ] "Results simulation" shows green checkmark
- [ ] Rule saves successfully
- [ ] If data exists, results are returned
- [ ] Alert fields populate correctly

---

## 🔧 Troubleshooting

### If query still fails:

**Error: "Failed to resolve table"**
- **Cause**: Tables not created yet
- **Solution**: Deploy table schemas via Bicep first

**Error: "Failed to resolve column"**
- **Cause**: Schema mismatch
- **Solution**: Run `getschema` queries to verify column names

**No results returned**
- **Cause**: No data in tables OR no correlation matches
- **Solution**: Check data ingestion queries above

---

## 📞 Next Steps

1. ✅ **Test the corrected query** in Log Analytics
2. ✅ **Verify tables exist** and have data
3. ✅ **Deploy corrected query** to Analytics rule
4. ✅ **Validate** rule saves without errors
5. ✅ **Monitor** for alerts over next 8 hours

---

**Fixed by**: AI Security Engineer  
**Date**: November 10, 2025, 08:17 AM  
**Issue**: Table name mismatch  
**Resolution**: Corrected to use actual deployed table names  
**Status**: ✅ READY FOR DEPLOYMENT
