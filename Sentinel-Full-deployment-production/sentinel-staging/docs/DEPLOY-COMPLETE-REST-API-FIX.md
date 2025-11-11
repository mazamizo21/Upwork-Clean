# DEPLOY-COMPLETE.ps1 - REST API Fix Applied
**Date**: November 10, 2025, 1:50 PM EST  
**Status**: ✅ **MIRRORED TACITRED FIX TO ALL LOGIC APPS**

## Problem Statement
All three Logic Apps (TacitRed, Cyren IP, Cyren Malware) were failing with empty DCE/DCR parameters because `az deployment group create` output was not reliably returning property values.

## Root Cause
Azure CLI `az deployment group create --query` was returning empty values for:
- `properties.outputs.endpoint.value` (DCE)
- `properties.outputs.immutableId.value` (DCR)

This caused Logic Apps to deploy with empty parameters, resulting in:
- **TacitRed**: "InvalidRequestPath" error
- **Cyren Malware**: "RequestEntityTooLarge" error (also needs batch size fix)
- **Cyren IP**: Likely same "InvalidRequestPath" error

## Solution Applied

### Changed From (Unreliable)
```powershell
# Deploy and try to get output
$dce = az deployment group create ... --query "{endpoint:properties.outputs.endpoint.value}" | ConvertFrom-Json
$dceEndpoint = $dce.endpoint  # EMPTY!

# Use in Logic App deployment
--parameters dceEndpoint="$($dce.endpoint)"  # EMPTY STRING!
```

### Changed To (Reliable)
```powershell
# Deploy without capturing output
az deployment group create ... -o none

# Get details via REST API
$dceUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce-sentinel-ti?api-version=2022-06-01"
$dce = az rest --method GET --uri $dceUri | ConvertFrom-Json
$dceEndpoint = $dce.properties.logsIngestion.endpoint  # WORKS!
$dceId = $dce.id

# Use in Logic App deployment
--parameters dceEndpoint="$dceEndpoint"  # CORRECT VALUE!
```

## Changes Made to DEPLOY-COMPLETE.ps1

### 1. DCE Deployment (Lines 43-53)
**Before**:
```powershell
$dce = az deployment group create ... --query "{id:...,endpoint:...}" | ConvertFrom-Json
Write-Host "✓ DCE: $($dce.endpoint)"
```

**After**:
```powershell
az deployment group create ... -o none

$dceUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce-sentinel-ti?api-version=2022-06-01"
$dce = az rest --method GET --uri $dceUri | ConvertFrom-Json
$dceEndpoint = $dce.properties.logsIngestion.endpoint
$dceId = $dce.id
Write-Host "✓ DCE: $dceEndpoint"
```

### 2. Cyren IP DCR (Lines 136-144)
**Before**:
```powershell
$ipDcrOut = az deployment group create ... --query "{id:...,immutableId:...}" | ConvertFrom-Json
```

**After**:
```powershell
az deployment group create ... -o none

$ipDcrUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/dcr-cyren-ip?api-version=2022-06-01"
$ipDcr = az rest --method GET --uri $ipDcrUri | ConvertFrom-Json
$ipDcrImmutableId = $ipDcr.properties.immutableId
$ipDcrId = $ipDcr.id
```

### 3. Cyren Malware DCR (Lines 147-155)
**Before**:
```powershell
$malDcrOut = az deployment group create ... --query "{id:...,immutableId:...}" | ConvertFrom-Json
```

**After**:
```powershell
az deployment group create ... -o none

$malDcrUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/dcr-cyren-malware?api-version=2022-06-01"
$malDcr = az rest --method GET --uri $malDcrUri | ConvertFrom-Json
$malDcrImmutableId = $malDcr.properties.immutableId
$malDcrId = $malDcr.id
```

### 4. TacitRed DCR (Lines 159-168)
**Before**:
```powershell
$tacitredDcrOut = az deployment group create ... --query "{id:...,immutableId:...}" | ConvertFrom-Json
```

**After**:
```powershell
az deployment group create ... -o none

$tacitredDcrUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionRules/dcr-tacitred-findings?api-version=2022-06-01"
$tacitredDcr = az rest --method GET --uri $tacitredDcrUri | ConvertFrom-Json
$tacitredDcrImmutableId = $tacitredDcr.properties.immutableId
$tacitredDcrId = $tacitredDcr.id
```

### 5. Logic App Deployments (Lines 172-181)
**Before**:
```powershell
--parameters dcrImmutableId="$($ipDcrOut.immutableId)" dceEndpoint="$($dce.endpoint)"
--parameters dcrImmutableId="$($malDcrOut.immutableId)" dceEndpoint="$($dce.endpoint)"
--parameters dcrImmutableId="$($tacitredDcrOut.immutableId)" dceEndpoint="$($dce.endpoint)"
```

**After**:
```powershell
--parameters dcrImmutableId="$ipDcrImmutableId" dceEndpoint="$dceEndpoint"
--parameters dcrImmutableId="$malDcrImmutableId" dceEndpoint="$dceEndpoint"
--parameters dcrImmutableId="$tacitredDcrImmutableId" dceEndpoint="$dceEndpoint"
```

### 6. RBAC Assignments (Lines 186-197)
**Before**:
```powershell
--scope $ipDcrOut.id
--scope $malDcrOut.id
--scope $tacitredDcrOut.id
--scope $dce.id
```

**After**:
```powershell
--scope $ipDcrId
--scope $malDcrId
--scope $tacitredDcrId
--scope $dceId
```

## Benefits of REST API Approach

1. **Reliability**: Direct REST API calls always return complete resource properties
2. **Consistency**: Same approach for all resources (DCE, DCRs)
3. **Debugging**: Easier to verify values are correct
4. **Production-Ready**: Proven pattern from successful TacitRed fix

## Variables Changed

| Old Variable | New Variable | Purpose |
|--------------|--------------|---------|
| `$dce.endpoint` | `$dceEndpoint` | DCE logs ingestion endpoint |
| `$dce.id` | `$dceId` | DCE resource ID for RBAC |
| `$ipDcrOut.immutableId` | `$ipDcrImmutableId` | Cyren IP DCR immutable ID |
| `$ipDcrOut.id` | `$ipDcrId` | Cyren IP DCR resource ID |
| `$malDcrOut.immutableId` | `$malDcrImmutableId` | Cyren Malware DCR immutable ID |
| `$malDcrOut.id` | `$malDcrId` | Cyren Malware DCR resource ID |
| `$tacitredDcrOut.immutableId` | `$tacitredDcrImmutableId` | TacitRed DCR immutable ID |
| `$tacitredDcrOut.id` | `$tacitredDcrId` | TacitRed DCR resource ID |

## Testing Required

After this fix, all Logic Apps should deploy with correct parameters. Test by:

1. **Run DEPLOY-COMPLETE.ps1**
2. **Verify Logic App parameters**:
   ```powershell
   $logicApp = az logic workflow show -g SentinelTestStixImport -n "logic-cyren-malware-urls" | ConvertFrom-Json
   Write-Host "DCE: $($logicApp.properties.parameters.dceEndpoint.value)"
   Write-Host "DCR: $($logicApp.properties.parameters.dcrImmutableId.value)"
   ```
3. **Trigger Logic Apps manually**
4. **Check run status** - should succeed

## Additional Fixes Needed

### Cyren Malware URLs - Batch Size Issue
The "RequestEntityTooLarge" error indicates the payload is too large. Need to:
- Reduce `fetchCount` from 10000 to 100
- Add pagination/batching logic
- Add time range parameters (like TacitRed)

This will be addressed in a separate fix to the Bicep template.

## Files Modified

- ✅ `DEPLOY-COMPLETE.ps1` - Lines 43-197 (REST API for all DCE/DCR retrieval)

## Files Pending Modification

- ⏳ `infrastructure/logicapp-cyren-malware-urls.bicep` - Add time range, reduce batch size
- ⏳ `infrastructure/logicapp-cyren-ip-reputation.bicep` - Add time range (optional)

## Success Criteria

- [x] DCE endpoint retrieved via REST API
- [x] All DCR immutable IDs retrieved via REST API
- [x] All Logic Apps use correct variable names
- [x] All RBAC assignments use correct resource IDs
- [ ] Cyren Logic Apps tested end-to-end
- [ ] All Logic App runs succeed
- [ ] Data ingested to all tables

## Rollback Plan

If issues occur, the old approach can be restored by reverting to deployment output queries. However, the REST API approach is more reliable and should be kept.

## Documentation

This fix is documented in:
- `docs/DEPLOY-COMPLETE-REST-API-FIX.md` (this file)
- `docs/FINAL-END-TO-END-TEST-RESULTS.md` (TacitRed testing)
- `docs/END-TO-END-DEPLOYMENT-20251110-1300.md` (deployment summary)

## Key Takeaway

**Always use `az rest` with direct REST API URIs for retrieving Azure resource properties in production scripts. Azure CLI convenience commands (`az monitor`, `az deployment`) may not reliably return all property values.**
