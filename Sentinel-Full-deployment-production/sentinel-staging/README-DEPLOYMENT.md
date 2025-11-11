# Azure Sentinel Threat Intelligence Solution - Deployment Guide

## Overview

This solution deploys a complete Azure Sentinel Threat Intelligence infrastructure with:
- **TacitRed** threat intelligence ingestion
- **Cyren** IP reputation and malware URL feeds
- **Automated data collection** via Logic Apps
- **Analytics rules** for threat detection
- **Workbooks** for visualization

## One-Click Deployment

### Prerequisites

1. **Azure CLI** installed and authenticated
2. **PowerShell 7+** (recommended) or Windows PowerShell 5.1+
3. **Azure Subscription** with:
   - Contributor role on target resource group
   - Permission to create managed identities and assign RBAC roles
4. **API Credentials**:
   - TacitRed API key
   - Cyren JWT tokens (IP reputation + malware URLs)

### Deployment Steps

1. **Configure credentials** in `client-config-COMPLETE.json`:
   ```json
   {
     "parameters": {
       "tacitred": {
         "value": {
           "apiKey": "YOUR_TACITRED_API_KEY"
         }
       },
       "cyren": {
         "value": {
           "ipReputation": {
             "jwtToken": "YOUR_CYREN_IP_TOKEN"
           },
           "malwareUrls": {
             "jwtToken": "YOUR_CYREN_MALWARE_TOKEN"
           }
         }
       }
     }
   }
   ```

2. **Run deployment**:
   ```powershell
   .\DEPLOY-COMPLETE.ps1
   ```

3. **Wait for completion** (~12-15 minutes):
   - Phase 1: DCE & Tables (2 min)
   - Phase 2: DCRs & Logic Apps (3 min)
   - Phase 3: RBAC assignments + 5 min propagation wait
   - Phase 4: Analytics Rules (1 min)
   - Phase 5: Workbooks (1 min)
   - Phase 6: Initial testing (1 min)

4. **Validate deployment** (after 30-60 minutes):
   ```powershell
   .\VALIDATE-DEPLOYMENT.ps1
   ```

## Important: RBAC Propagation Delay

### Expected Behavior

⚠️ **Azure RBAC propagation can take 30-60 minutes after deployment completes.**

During this time:
- ✅ All resources are deployed successfully
- ✅ RBAC role assignments are created
- ❌ Logic Apps may show **403 Forbidden** errors
- ⏳ This is **NORMAL** and expected behavior

### Why This Happens

Azure's RBAC system uses eventual consistency:
1. Role assignments are created immediately in the database
2. Permission changes propagate across Azure's distributed infrastructure
3. Propagation time varies: typically 5-30 minutes, can be up to 60 minutes

**The deployment script accounts for this by:**
- Assigning all RBAC roles upfront
- Waiting 5 minutes for initial propagation
- Running initial tests (expected to fail)
- Providing validation script for later verification

### Validation Process

Run `VALIDATE-DEPLOYMENT.ps1` to check:
- ✓ RBAC assignments on all Logic Apps (DCR & DCE scopes)
- ✓ Logic App execution status
- ✓ Data ingestion into Log Analytics tables

**Repeat validation every 15-30 minutes until all checks pass.**

## Deployment Components

### Data Collection

| Component | Description | RBAC Required |
|-----------|-------------|---------------|
| DCE (Data Collection Endpoint) | Ingestion endpoint for all data | Monitoring Metrics Publisher |
| DCR - TacitRed Findings | Transforms TacitRed JSON to table schema | Monitoring Metrics Publisher |
| DCR - Cyren IP Reputation | Transforms Cyren IP data to indicators | Monitoring Metrics Publisher |
| DCR - Cyren Malware URLs | Transforms Cyren malware data to indicators | Monitoring Metrics Publisher |

### Logic Apps

| Logic App | Schedule | Function |
|-----------|----------|----------|
| logic-cyren-ip-reputation | Every 12 hours | Fetch IP reputation indicators from Cyren |
| logic-cyren-malware-urls | Every 12 hours | Fetch malware URL indicators from Cyren |
| logic-tacitred-ingestion | Every 6 hours | Fetch compromise findings from TacitRed |

**Each Logic App has:**
- System-assigned managed identity
- Monitoring Metrics Publisher role on its DCR (for data ingestion)
- Monitoring Metrics Publisher role on DCE (for endpoint access)

### Log Analytics Tables

| Table | Schema | Use Case |
|-------|--------|----------|
| Cyren_Indicators_CL | 19 columns (url, ip, domain, hash, etc.) | Combined Cyren threat indicators |
| TacitRed_Findings_CL | 16 columns (email, domain, findingType, etc.) | User compromise detections |

### Analytics Rules

6 scheduled analytics rules for threat detection:
1. **TacitRed - Repeat Compromise Detection**
2. **TacitRed - High-Risk User Compromised**
3. **TacitRed - Active Compromised Account**
4. **Cyren + TacitRed - Malware Infrastructure**
5. **TacitRed + Cyren - Cross-Feed Correlation**
6. **TacitRed - Department Compromise Cluster**

## Troubleshooting

### Issue: Logic Apps show 403 Forbidden errors

**Cause:** RBAC propagation delay (expected)

**Solution:**
1. Wait 30-60 minutes after deployment
2. Run `.\VALIDATE-DEPLOYMENT.ps1`
3. If RBAC shows as assigned, manually trigger Logic Apps from Azure Portal
4. Check again after 15 minutes

### Issue: No data in Log Analytics tables

**Cause:** Logic Apps haven't run successfully yet

**Solution:**
1. Verify RBAC is propagated: `.\VALIDATE-DEPLOYMENT.ps1`
2. Check Logic App run history in Azure Portal
3. Manually trigger Logic Apps if needed
4. Wait 5-10 minutes and query tables again

### Issue: Validation script shows missing RBAC

**Cause:** Azure propagation still in progress

**Solution:**
1. Wait additional 15-30 minutes
2. Re-run validation script
3. If persists after 90 minutes, check Azure Portal → IAM for manual verification

## Files Reference

| File | Purpose |
|------|---------|
| `DEPLOY-COMPLETE.ps1` | Main deployment script (one-click install) |
| `VALIDATE-DEPLOYMENT.ps1` | Post-deployment validation script |
| `client-config-COMPLETE.json` | Configuration file (API keys, settings) |
| `infrastructure/` | Bicep templates for all Azure resources |
| `analytics/` | KQL analytics rules |
| `workbooks/` | Azure Workbook templates |
| `Docs/` | Deployment logs and reports |

## Deployment Logs

All deployment artifacts are saved in timestamped folders:
- `Docs/deployment-YYYYMMDDHHMMSS/`
  - `deployment-log.txt` - Full transcript
  - `rbac-assignments.json` - RBAC assignment results
  - `initial-test-results.json` - First Logic App test results
  - `state.json` - Deployment state for reference

## Customer Support

For issues not resolved by validation script:

1. **Check deployment logs** in `Docs/deployment-*/`
2. **Review Logic App run history** in Azure Portal
3. **Verify RBAC assignments** in Azure Portal → Resource → Access Control (IAM)
4. **Check API credentials** are valid and not expired
5. **Review Azure Activity Log** for deployment errors

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    External APIs                            │
│  ┌──────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │ TacitRed │  │ Cyren IP Feeds │  │ Cyren Malware   │   │
│  └────┬─────┘  └────────┬─────────┘  └────────┬────────┘   │
└───────┼─────────────────┼─────────────────────┼────────────┘
        │                 │                     │
        │                 │                     │
┌───────▼─────────────────▼─────────────────────▼────────────┐
│                    Azure Logic Apps                         │
│  ┌──────────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ TacitRed         │  │ Cyren IP     │  │ Cyren        │ │
│  │ Ingestion        │  │ Reputation   │  │ Malware URLs │ │
│  │ (Every 6h)       │  │ (Every 12h)  │  │ (Every 12h)  │ │
│  └────────┬─────────┘  └──────┬───────┘  └──────┬────────┘ │
└───────────┼────────────────────┼──────────────────┼──────────┘
            │                    │                  │
            │  HTTPS POST        │                  │
            │  (RBAC Required)   │                  │
            │                    │                  │
┌───────────▼────────────────────▼──────────────────▼──────────┐
│           Data Collection Endpoint (DCE)                      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ DCR TacitRed │  │ DCR Cyren IP │  │ DCR Cyren Malware│  │
│  │ (Transform)  │  │ (Transform)  │  │ (Transform)      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬────────────┘  │
└─────────┼──────────────────┼──────────────────┼───────────────┘
          │                  │                  │
          │  Write to        │                  │
          │  Tables          │                  │
┌─────────▼──────────────────▼──────────────────▼───────────────┐
│              Log Analytics Workspace                           │
│                                                                │
│  ┌────────────────────────┐  ┌───────────────────────────┐   │
│  │ TacitRed_Findings_CL   │  │ Cyren_Indicators_CL       │   │
│  │ (User compromises)     │  │ (Threat indicators)       │   │
│  └────────────────────────┘  └───────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │         Analytics Rules (6)                            │  │
│  │  • Repeat Compromise Detection                         │  │
│  │  • High-Risk User Compromised                          │  │
│  │  • Malware Infrastructure Correlation                  │  │
│  └────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Version History

- **v1.0** (2025-11-11): Initial release with RBAC automation and validation script
  - Full end-to-end automation
  - RBAC propagation handling
  - Post-deployment validation
  - Customer-ready one-click deployment

## License

This solution is provided as-is for Azure Sentinel deployments.
