# One-Click Deployment Guide
## Sentinel Threat Intelligence Solution - Production Ready

**Version:** 1.0.0 (Validated Nov 10, 2025)  
**Status:** ✅ Fully Automated - Zero Manual Steps Required

---

## Prerequisites

### Azure Requirements
- **Azure Subscription** with Owner/Contributor + User Access Administrator roles
- **Microsoft Sentinel Workspace** (existing) - must be created beforehand
- **Azure CLI** installed and authenticated (`az login`)
- **PowerShell 7+** installed

### API Credentials Required
1. **TacitRed API Key** (from TacitRed portal)
2. **Cyren IP Reputation JWT Token** (from Cyren portal)
3. **Cyren Malware URLs JWT Token** (from Cyren portal)

---

## Deployment Steps

### 1. Configure Credentials

Edit `client-config-COMPLETE.json` and update these values:

```json
{
  "parameters": {
    "azure": {
      "value": {
        "subscriptionId": "YOUR-SUBSCRIPTION-ID",
        "resourceGroupName": "YOUR-RESOURCE-GROUP",
        "workspaceName": "YOUR-SENTINEL-WORKSPACE-NAME",
        "location": "eastus",
        "tenantId": "YOUR-TENANT-ID"
      }
    },
    "tacitRed": {
      "value": {
        "apiKey": "YOUR-TACITRED-API-KEY"
      }
    },
    "cyren": {
      "value": {
        "ipReputation": {
          "jwtToken": "YOUR-CYREN-IP-JWT-TOKEN",
          "clientId": "YOUR-CYREN-IP-CLIENT-ID"
        },
        "malwareUrls": {
          "jwtToken": "YOUR-CYREN-MALWARE-JWT-TOKEN",
          "clientId": "YOUR-CYREN-MALWARE-CLIENT-ID"
        }
      }
    }
  }
}
```

### 2. Run Deployment

From the `sentinel-staging` directory:

```powershell
.\DEPLOY-COMPLETE.ps1
```

**That's it!** No manual steps required.

---

## What Gets Deployed

### Infrastructure (Phase 1-2)
- ✅ **1 Data Collection Endpoint (DCE)** - Central ingestion endpoint
- ✅ **2 Custom Log Analytics Tables** with full schemas:
  - `TacitRed_Findings_CL` (16 columns)
  - `Cyren_Indicators_CL` (19 columns - unified from IP + Malware feeds)
- ✅ **3 Data Collection Rules (DCRs)** with transforms:
  - `dcr-tacitred-findings` - Parses TacitRed JSON → TacitRed_Findings_CL
  - `dcr-cyren-ip` - Parses Cyren IP Reputation → Cyren_Indicators_CL
  - `dcr-cyren-malware` - Parses Cyren Malware URLs → Cyren_Indicators_CL

### Automation (Phase 3)
- ✅ **3 Logic Apps** with managed identities and RBAC:
  - `logic-tacitred-ingestion` - Polls TacitRed API every 1 hour
  - `logicapp-cyren-ip-reputation` - Polls Cyren IP feed every 6 hours
  - `logicapp-cyren-malware-urls` - Polls Cyren Malware feed every 6 hours
- ✅ **Automatic RBAC assignments** (Monitoring Metrics Publisher role)
- ✅ **120-second propagation wait** for managed identity + RBAC readiness

### Analytics (Phase 4)
- ✅ **6 Scheduled Analytics Rules** (NO parsers required):
  1. **TacitRed - Repeat Compromise Detection** (PT1H frequency)
  2. **TacitRed - High-Risk User Compromised** (PT1H frequency)
  3. **TacitRed - Active Compromised Account** (PT6H frequency)
  4. **TacitRed - Department Compromise Cluster** (PT6H frequency)
  5. **Cyren + TacitRed - Malware Infrastructure** (PT1H frequency)
  6. **TacitRed + Cyren - Cross-Feed Correlation** (PT1H frequency)

### Visualization (Phase 5)
- ✅ **3 Workbooks** (enabled by default):
  - Threat Intelligence Command Center
  - Executive Risk Dashboard
  - Threat Hunter Arsenal

### Validation (Phase 6)
- ✅ **Automated test triggers** for Logic Apps
- ✅ **60-second ingestion validation**

---

## Architecture Overview

```
┌─────────────────────┐
│  TacitRed API       │──┐
│  Cyren IP Feed      │──├──> Logic Apps (Managed Identity)
│  Cyren Malware Feed │──┘         │
└─────────────────────┘            │ (RBAC: Monitoring Metrics Publisher)
                                   ▼
                          ┌────────────────┐
                          │ DCE + 3 DCRs   │ (Transform JSON)
                          └────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Log Analytics Tables        │
                    │  - TacitRed_Findings_CL      │
                    │  - Cyren_Indicators_CL       │
                    └──────────────────────────────┘
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
          ┌─────────────┐  ┌─────────────┐  ┌──────────┐
          │ Analytics   │  │  Workbooks  │  │ Hunting  │
          │ Rules (6)   │  │   (3)       │  │ Queries  │
          └─────────────┘  └─────────────┘  └──────────┘
```

---

## Key Technical Decisions

### 1. **No Parser Functions Required**
- ❌ **Old approach:** Parser functions (complex, error-prone)
- ✅ **New approach:** DCR transforms handle all parsing
- **Benefit:** Analytics rules query tables directly with full schema

### 2. **Unified Cyren Table**
- Both Cyren IP Reputation and Malware URLs → `Cyren_Indicators_CL`
- Unified schema with `type_s` and `category_s` discrimination
- Simplifies correlation queries and workbook visualizations

### 3. **Domain Normalization**
- Analytics rules extract **registrable domain** (SLD.TLD) for correlation
- Example: `mail.google.com` → `google.com`
- Improves TacitRed ↔ Cyren correlation accuracy

### 4. **Production-Ready Filters**
- Cyren correlation rules: `risk_d >= 60`, `type/category = malware|phishing`
- Balanced for high-quality alerts while minimizing false positives
- Can be adjusted post-deployment via Azure Portal

---

## Post-Deployment Validation

### Check Data Ingestion

Run in Sentinel → Logs:

```kusto
// TacitRed
TacitRed_Findings_CL
| where TimeGenerated > ago(24h)
| summarize Count = count()

// Cyren (unified)
Cyren_Indicators_CL
| where TimeGenerated > ago(24h)
| summarize Count = count() by type_s, category_s
```

**Expected Results:**
- TacitRed: 100-500 findings per day (varies by feed)
- Cyren: 200-1000 indicators per day (combined IP + Malware)

### Check Analytics Rules

Navigate to: **Sentinel → Analytics → Active rules**

Expected status:
- ✅ All 6 rules **Enabled**
- ✅ Rules with results: Repeat Compromise, Active Account, Department Cluster
- ⚠️ Rules may show 0 initially: Malware Infrastructure, Cross-Feed Correlation (requires domain overlap)

### Check Logic Apps

Navigate to: **Logic Apps → [logic-app-name] → Runs history**

Expected:
- ✅ Recent successful runs (green checkmarks)
- ✅ No authentication errors (HTTP 200/204 responses)

---

## Troubleshooting

### Issue: Logic App Authentication Failures (HTTP 403)

**Cause:** RBAC propagation delay  
**Fix:** Wait 2-3 minutes and retry. Script already includes 120s wait; if still failing, manually re-run Logic App.

### Issue: Analytics Rules Show 0 Results

**Root Causes:**
1. **Data not yet ingested** → Wait for next Logic App run (check schedule)
2. **Correlation rules:** No domain overlap between TacitRed and Cyren (this is normal if feeds don't intersect)
3. **High-Risk User rule:** Requires `SigninLogs` table (Entra ID integration) - may show 0 without it

**Validation:** Run the KQL queries above to confirm data presence.

### Issue: DCR Deployment Fails

**Cause:** Unsupported `coalesce()` in transformKql  
**Fix:** Already resolved in this version. DCRs use `iif(isnull(...))` pattern instead.

### Issue: Table Schema Mismatch

**Cause:** Tables exist with old schema (e.g., only `payload_s` column)  
**Fix:** Delete and recreate tables via script, or manually delete via Log Analytics → Tables.

---

## Manual Steps (If Needed)

### Disable/Enable Specific Rules

If you want to disable High-Risk User rule (requires SigninLogs):

```powershell
az sentinel alert-rule update `
  --resource-group $rg `
  --workspace-name $ws `
  --rule-id <RULE-GUID> `
  --enabled false
```

### Adjust Correlation Filters

Edit `analytics/rules/rule-malware-infrastructure.kql` and change:

```kusto
| where RiskScore >= 60  // Lower to 40 for more matches
| where (Category in ('malware','phishing'))  // Add 'spam' etc.
```

Then redeploy:

```powershell
az deployment group create `
  -g $rg `
  --template-file ".\analytics\analytics-rules.bicep" `
  --parameters workspaceName=$ws
```

---

## Logs and State

After deployment, check:
- **Transcript:** `docs/deployment-logs/complete-<timestamp>/transcript.log`
- **State file:** `docs/deployment-logs/complete-<timestamp>/state.json`
- **Analytics logs:** `docs/deployment-logs/complete-<timestamp>/analytics-deploy.log`

---

## Customer Handoff Checklist

- [ ] Verify `client-config-COMPLETE.json` with customer credentials
- [ ] Run `DEPLOY-COMPLETE.ps1` in customer environment
- [ ] Validate ingestion (TacitRed + Cyren) via KQL
- [ ] Confirm Analytics rules enabled and producing results
- [ ] Review workbooks with customer stakeholders
- [ ] Provide access to `docs/` folder for troubleshooting guides
- [ ] Schedule follow-up to tune alert thresholds based on customer feedback

---

## Support & Documentation

- **Official Azure Docs:** [Monitor Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- **Sentinel Analytics:** [Scheduled Rules Best Practices](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- **Internal Docs:** `docs/RBAC-BEST-PRACTICES.md`, `docs/FINAL-DEPLOYMENT-REPORT-*.md`

---

## Version History

**1.0.0 (Nov 10, 2025)**
- ✅ Fixed DCR `coalesce()` → `iif(isnull())` transforms
- ✅ Unified Cyren feeds into single `Cyren_Indicators_CL` table
- ✅ Domain normalization in correlation rules
- ✅ Validated zero manual steps required
- ✅ Production-ready filters (risk ≥ 60)
- ✅ RBAC 120s propagation wait
- ✅ Full automation with dependency handling
