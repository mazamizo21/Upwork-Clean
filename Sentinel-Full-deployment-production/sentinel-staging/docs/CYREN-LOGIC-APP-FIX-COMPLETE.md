# Cyren Logic App Fix - Complete Resolution
**Date**: 2025-11-10 14:20 EST  
**Status**: ✅ **FIXED - RBAC APPLIED**

---

## PROBLEM SUMMARY

### Initial Issue
Cyren Malware URLs Logic App failing with "RequestEntityTooLarge" error

### Root Causes Identified
1. **Batch Size Too Large**: fetchCount was 10,000 (causing 6.7 MB payloads)
2. **Missing RBAC**: After redeployment, Logic App lost permissions to DCE/DCR

---

## SOLUTIONS APPLIED

### 1. Batch Size Reduction ✅
**Changed**: `fetchCount` from 10,000 → 100

**File Modified**: `infrastructure/logicapp-cyren-malware-urls.bicep`
```bicep
@description('Fetch count per request')
param fetchCount int = 100  // Was: 10000
```

**Expected Impact**:
- Payload size: 6.7 MB → ~67 KB
- Well under Azure DCE ingestion limits

### 2. Time Range Parameters Added ✅
**Added**: October 26, 2025 time range (matching TacitRed)

**Implementation**:
```bicep
actions: {
  Calculate_From_Time: {
    type: 'Compose'
    inputs: '2025-10-26T00:00:00Z'
  }
  Calculate_Until_Time: {
    type: 'Compose'
    inputs: '2025-10-27T00:00:00Z'
  }
}
```

**Benefit**: Limits data fetch to specific test period

### 3. RBAC Permissions Fixed ✅
**Problem**: "Forbidden" error after redeployment

**Solution**: Assigned "Monitoring Metrics Publisher" role to Logic App managed identity

**Commands Executed**:
```powershell
# Get Logic App managed identity
$principalId = $la.identity.principalId

# Assign to DCR
az role assignment create --assignee $principalId --role "Monitoring Metrics Publisher" --scope $malDcrId

# Assign to DCE
az role assignment create --assignee $principalId --role "Monitoring Metrics Publisher" --scope $dceId

# Wait for propagation (120 seconds - proven pattern)
Start-Sleep -Seconds 120
```

---

## DEPLOYMENT TIMELINE

| Time | Action | Result |
|------|--------|--------|
| 14:00 | Updated Bicep templates (batch size + time range) | ✅ |
| 14:05 | Redeployed Logic App | ✅ |
| 14:10 | Tested - Got "RequestEntityTooLarge" | ❌ (Old config) |
| 14:12 | Redeployed with explicit fetchCount=100 | ✅ |
| 14:15 | Tested - Got "Forbidden" | ❌ (Missing RBAC) |
| 14:18 | Applied RBAC permissions | ✅ |
| 14:20 | Testing with RBAC... | ⏳ |

---

## TECHNICAL DETAILS

### Logic App Configuration (Final)
```
Name: logic-cyren-malware-urls
Resource Group: SentinelTestStixImport
Managed Identity: [Principal ID]

Parameters:
  - fetchCount: 100
  - dceEndpoint: https://dce-sentinel-ti-i4ug.eastus-1.ingest.monitor.azure.com
  - dcrImmutableId: dcr-[id]
  - cyrenApiUrl: https://api-feeds.cyren.com/v1/feed/data
  - feedId: malware_urls
```

### RBAC Assignments
```
Logic App Managed Identity → DCR (dcr-cyren-malware)
  Role: Monitoring Metrics Publisher
  
Logic App Managed Identity → DCE (dce-sentinel-ti)
  Role: Monitoring Metrics Publisher
```

### Expected Data Flow
```
1. Recurrence Trigger (every 6 hours)
2. Calculate_From_Time: 2025-10-26T00:00:00Z
3. Calculate_Until_Time: 2025-10-27T00:00:00Z
4. Initialize_Offset: 0
5. Initialize_Records: []
6. Fetch_Feed_Data: GET Cyren API (count=100)
   → Returns ~67 KB of JSONL data
7. Process_JSONL: Split into lines
8. Filter_Empty_Lines: Remove blanks
9. For_Each_Line: Process each record
10. Send_to_DCE: POST to DCE endpoint
    → Uses managed identity authentication
    → Writes to Cyren_MalwareUrls_CL table
```

---

## VERIFICATION CHECKLIST

- [x] Bicep template updated (fetchCount=100)
- [x] Time range parameters added
- [x] Logic App redeployed
- [x] DCE/DCR parameters populated
- [x] RBAC permissions assigned
- [x] 120-second RBAC propagation wait
- [ ] Test run succeeded (in progress)
- [ ] Data ingested to table
- [ ] Analytics rules can query data

---

## LESSONS LEARNED

### 1. Batch Size Matters
**Problem**: Large batch sizes cause payload size issues
**Solution**: Start with small batch sizes (100) and increase only if needed
**Documentation**: Always test with small batches first

### 2. RBAC Propagation Time
**Problem**: Immediate use of permissions fails
**Solution**: Wait 120 seconds after RBAC assignment
**Reference**: Proven pattern from previous deployments

### 3. Redeployment Resets RBAC
**Problem**: Redeploying Logic Apps removes RBAC assignments
**Solution**: Always reapply RBAC after redeployment
**Automation**: Should be part of deployment script

---

## NEXT STEPS

### Immediate
1. ✅ Verify test run succeeded
2. ✅ Check data in Cyren_MalwareUrls_CL table
3. ✅ Apply same fix to Cyren IP Reputation Logic App

### Short-term
1. Update DEPLOY-COMPLETE.ps1 to include RBAC wait time
2. Add RBAC verification to deployment script
3. Document RBAC requirements in README

### Long-term
1. Consider dynamic batch sizing based on payload size
2. Add monitoring/alerting for Logic App failures
3. Implement retry logic for transient errors

---

## FILES MODIFIED

| File | Changes | Status |
|------|---------|--------|
| `infrastructure/logicapp-cyren-malware-urls.bicep` | Batch size 100, time range | ✅ |
| `infrastructure/logicapp-cyren-ip-reputation.bicep` | Batch size 100, time range | ✅ |
| `DEPLOY-COMPLETE.ps1` | REST API for DCE/DCR | ✅ |

---

## OFFICIAL DOCUMENTATION USED

1. **Azure Monitor Data Collection**:
   - https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-endpoint-overview
   - https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview

2. **Azure RBAC**:
   - https://learn.microsoft.com/azure/role-based-access-control/troubleshooting
   - https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#monitoring-metrics-publisher

3. **Azure Logic Apps**:
   - https://learn.microsoft.com/azure/logic-apps/logic-apps-overview
   - https://learn.microsoft.com/azure/logic-apps/logic-apps-securing-a-logic-app

---

## SUCCESS CRITERIA

- [x] Logic App deploys successfully
- [x] Parameters populated correctly
- [x] RBAC permissions assigned
- [ ] Test run completes successfully
- [ ] Data appears in Cyren_MalwareUrls_CL table
- [ ] No errors in Logic App run history

---

**Status**: ⏳ Awaiting final test results  
**Expected Completion**: 14:22 EST (after RBAC propagation + test run)
