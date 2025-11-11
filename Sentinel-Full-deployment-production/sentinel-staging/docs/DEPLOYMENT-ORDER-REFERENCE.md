# Deployment Order Reference
**Date**: 2025-11-10 15:00 EST  
**Status**: ✅ **CORRECT ORDER IMPLEMENTED**

---

## CRITICAL: DEPLOYMENT ORDER MATTERS

### The Correct Order

```
1. Deploy Infrastructure (DCE, DCRs, Tables)
   ↓
2. Deploy Logic Apps (with managed identities)
   ↓
3. WAIT 60 SECONDS (for identity propagation)
   ↓
4. Assign RBAC (Monitoring Metrics Publisher)
   ↓
5. WAIT 120 SECONDS (for RBAC propagation)
   ↓
6. Deploy Analytics & Workbooks
   ↓
7. Logic Apps can now write to DCE/DCR ✅
```

---

## WHY THIS ORDER IS CRITICAL

### Problem if Wrong Order
❌ **RBAC before Identity Propagation**:
- RBAC assignment fails (identity doesn't exist yet)
- Logic Apps get "Forbidden" errors

❌ **No Wait After RBAC**:
- Logic Apps try to write immediately
- RBAC not propagated yet
- Get "authentication token provided does not have access" error

❌ **Logic Apps Triggered Before RBAC**:
- Immediate "Forbidden" errors
- Must wait 2-5 minutes and retry

### Solution: Proper Wait Times
✅ **60 seconds after identity creation**:
- Ensures managed identity exists in Azure AD
- RBAC assignments will succeed

✅ **120 seconds after RBAC assignment**:
- Ensures permissions propagate across Azure
- Logic Apps can write to DCE/DCR immediately

---

## DEPLOY-COMPLETE.PS1 IMPLEMENTATION

### Phase 2: Infrastructure (Lines 65-164)
```powershell
# Deploy DCE
az deployment group create ... dce-sentinel-ti

# Create tables
TacitRed_Findings_CL
Cyren_Indicators_CL

# Deploy DCRs (using Bicep templates)
dcr-cyren-ip
dcr-cyren-malware
dcr-tacitred-findings

# Deploy Logic Apps
logic-cyren-ip-reputation
logic-cyren-malware-urls
logic-tacitred-ingestion
```

### Identity Propagation Wait (Lines 180-183)
```powershell
Write-Host "Waiting 60s for managed identities to propagate..."
Start-Sleep -Seconds 60
Write-Host "✓ Identity propagation complete"
```

### Phase 3: RBAC (Lines 185-201)
```powershell
# Assign RBAC to all Logic Apps
if($ipPrincipal){
    az role assignment create --assignee $ipPrincipal --role "Monitoring Metrics Publisher" --scope $ipDcrId
    az role assignment create --assignee $ipPrincipal --role "Monitoring Metrics Publisher" --scope $dceId
}
if($malPrincipal){
    az role assignment create --assignee $malPrincipal --role "Monitoring Metrics Publisher" --scope $malDcrId
    az role assignment create --assignee $malPrincipal --role "Monitoring Metrics Publisher" --scope $dceId
}
if($tacitredPrincipal){
    az role assignment create --assignee $tacitredPrincipal --role "Monitoring Metrics Publisher" --scope $tacitredDcrId
    az role assignment create --assignee $tacitredPrincipal --role "Monitoring Metrics Publisher" --scope $dceId
}

# Wait for RBAC propagation
Write-Host "Waiting 120s for RBAC..."
Start-Sleep -Seconds 120
Write-Host "✓ RBAC complete"
```

### Phase 4: Analytics & Workbooks (Lines 203+)
```powershell
# Deploy analytics rules
# Deploy workbooks
# Everything is ready to use
```

---

## TIMELINE BREAKDOWN

| Step | Duration | Cumulative | Purpose |
|------|----------|------------|---------|
| Deploy DCE | ~10s | 10s | Data collection endpoint |
| Create Tables | ~30s | 40s | Log Analytics tables |
| Deploy DCRs | ~30s | 70s | Data collection rules |
| Deploy Logic Apps | ~30s | 100s | Get managed identities |
| **Wait (Identity)** | **60s** | **160s** | **Identity propagation** |
| Assign RBAC | ~5s | 165s | Grant permissions |
| **Wait (RBAC)** | **120s** | **285s** | **RBAC propagation** |
| Deploy Analytics | ~20s | 305s | Analytics rules |
| Deploy Workbooks | ~30s | 335s | Workbooks |
| **Total** | **~5.5 min** | - | **Complete deployment** |

---

## COMMON ERRORS AND FIXES

### Error 1: "Forbidden" or "OperationFailed"
```json
{
  "error": {
    "code": "OperationFailed",
    "message": "The authentication token provided does not have access to ingest data for the data collection rule..."
  }
}
```

**Cause**: RBAC not propagated yet  
**Fix**: Wait 2-3 more minutes, then trigger Logic App again  
**Prevention**: Ensure 120-second wait after RBAC assignment

### Error 2: "Principal does not exist"
```
ERROR: Principal <guid> does not exist in the directory
```

**Cause**: Managed identity not propagated yet  
**Fix**: Wait 60 seconds after Logic App deployment  
**Prevention**: Add 60-second wait before RBAC assignment

### Error 3: "RequestEntityTooLarge"
```
{
  "error": {
    "code": "RequestEntityTooLarge",
    "message": "The request body is too large..."
  }
}
```

**Cause**: Batch size too large (fetchCount > 100)  
**Fix**: Reduce fetchCount parameter to 100 or less  
**Prevention**: Use fetchCount=100 in Logic App Bicep templates

---

## BEST PRACTICES

### 1. Always Use Full Deployment Script
✅ Run `DEPLOY-COMPLETE.ps1` for complete deployments  
❌ Don't manually redeploy individual components

**Why**: Full script includes all wait times and proper order

### 2. Never Skip Wait Times
✅ 60 seconds after identity creation  
✅ 120 seconds after RBAC assignment  
❌ Don't reduce wait times to "save time"

**Why**: Azure propagation is not instant, shorter waits cause failures

### 3. Test After Full Propagation
✅ Wait for script to complete fully  
✅ Trigger Logic Apps after RBAC wait  
❌ Don't test immediately after deployment

**Why**: Permissions need time to propagate across Azure regions

### 4. Monitor Logic App Runs
✅ Check run history in Azure Portal  
✅ Review action details for errors  
✅ Verify data in Log Analytics tables

**Why**: Catch issues early and verify successful ingestion

---

## VERIFICATION CHECKLIST

After running DEPLOY-COMPLETE.ps1:

- [ ] All deployments succeeded (no errors in transcript)
- [ ] 60-second identity wait completed
- [ ] RBAC assigned to all Logic Apps
- [ ] 120-second RBAC wait completed
- [ ] Trigger Logic Apps manually
- [ ] Check Logic App run status (should be "Succeeded")
- [ ] Verify data in tables:
  - [ ] `TacitRed_Findings_CL | where TimeGenerated > ago(1h)`
  - [ ] `Cyren_IpReputation_CL | where TimeGenerated > ago(1h)`
  - [ ] `Cyren_MalwareUrls_CL | where TimeGenerated > ago(1h)`

---

## TROUBLESHOOTING

### If Logic Apps Still Fail After RBAC Wait

1. **Check RBAC assignments**:
   ```powershell
   az role assignment list --assignee <principalId> --scope <dcrId>
   ```

2. **Wait longer** (Azure can take up to 5 minutes):
   ```powershell
   Start-Sleep -Seconds 180  # Wait 3 more minutes
   ```

3. **Manually trigger Logic App**:
   ```powershell
   az rest --method POST --uri "https://management.azure.com/.../triggers/Recurrence/run?api-version=2016-06-01"
   ```

4. **Check Logic App run details**:
   - Azure Portal → Logic Apps → Run History
   - Look for "Send_to_DCE" action
   - Review error details

---

## OFFICIAL DOCUMENTATION

1. **Azure RBAC Propagation**:
   - https://learn.microsoft.com/azure/role-based-access-control/troubleshooting#role-assignment-changes-are-not-being-detected

2. **Managed Identities**:
   - https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview

3. **Data Collection Rules**:
   - https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview

---

## SUMMARY

### The Golden Rule
**ALWAYS WAIT FOR PROPAGATION**

- 60 seconds after identity creation
- 120 seconds after RBAC assignment
- Total: 180 seconds (3 minutes)

### Why It Matters
Azure is a distributed system. Changes need time to propagate across:
- Azure Active Directory (identities)
- Azure Resource Manager (RBAC)
- Regional data centers
- Service endpoints

**Skipping waits = Guaranteed failures**

---

**Last Updated**: 2025-11-10 15:00 EST  
**Script Version**: DEPLOY-COMPLETE.ps1 (with 60s + 120s waits)  
**Status**: Production Ready ✅
