# Resource Consolidation Plan
**Date**: 2025-11-10  
**Objective**: Consolidate all Sentinel resources into single resource group following Azure best practices

## Current State (Split Deployment)

### SentinelTestStixImport (15 resources) ✅ TARGET
- **Sentinel Workspace**: `SentinelTestStixImportInstance`
- **DCE**: `dce-sentinel-ti`
- **DCRs**: `dcr-cyren-ip`, `dcr-cyren-malware`
- **Logic Apps**: `logic-cyren-ip-reputation`, `logic-cyren-malware-urls`
- **Analytics Rules**: 12 rules (6 TacitRed + 6 system)
- **Workbooks**: 3 workbooks
- **Sentinel Solution**: `SecurityInsights(sentinelteststiximportinstance)`

### rg-sentinel-threatintel (10 resources) ⚠️ LEGACY
- **DCE**: `dce-sentinel-threatintel`
- **DCRs**: `dcr-tacitred-findings`, `dcr-cyren-indicators`
- **Logic Apps**: `logic-tacitred-ingestion`, `PB-IP-Enrichment`, `PB-ThreatHunt-M365D`
- **API Connections**: 4 connections (wdatp, azuresentinel, azureloganalytics, azuremonitorlogs)

## Problem
- **Split infrastructure**: TacitRed ingestion in different RG than Sentinel workspace
- **Duplicate DCE/DCRs**: Two separate data collection endpoints for same workspace
- **RBAC complexity**: Cross-RG permissions required
- **Deployment inconsistency**: `DEPLOY-COMPLETE.ps1` doesn't deploy TacitRed resources

## Solution: Single Resource Group Pattern

### Target Architecture (SentinelTestStixImport)
```
SentinelTestStixImport/
├── Sentinel Workspace (SentinelTestStixImportInstance)
├── DCE (dce-sentinel-ti) - consolidated
├── DCRs
│   ├── dcr-cyren-ip
│   ├── dcr-cyren-malware
│   └── dcr-tacitred-findings (MIGRATE)
├── Logic Apps
│   ├── logic-cyren-ip-reputation
│   ├── logic-cyren-malware-urls
│   └── logic-tacitred-ingestion (MIGRATE)
├── Analytics Rules (6 TacitRed rules)
└── Workbooks (3 workbooks)
```

### Benefits
- ✅ Single deployment target
- ✅ Simplified RBAC (all resources in same RG)
- ✅ Consistent naming convention
- ✅ Single DCE for all ingestion
- ✅ Easier lifecycle management

## Implementation Steps

### Phase 1: Add TacitRed to DEPLOY-COMPLETE.ps1
1. Add TacitRed DCR deployment (Phase 2)
2. Add TacitRed Logic App deployment (Phase 3)
3. Configure Logic App with October 26 time range for testing
4. Ensure RBAC for Logic App managed identity

### Phase 2: Deploy and Test
1. Run `DEPLOY-COMPLETE.ps1` with full logging
2. Verify TacitRed DCR created in `SentinelTestStixImport`
3. Verify TacitRed Logic App created in `SentinelTestStixImport`
4. Trigger Logic App manually
5. Verify data ingestion to `TacitRed_Findings_CL`
6. Verify analytics rules execute and show results

### Phase 3: Cleanup Legacy RG
1. Document all resources in `rg-sentinel-threatintel`
2. Verify no active dependencies
3. Delete `rg-sentinel-threatintel` (or keep for audit/rollback)

## Testing Checklist
- [ ] TacitRed DCR deployed to SentinelTestStixImport
- [ ] TacitRed Logic App deployed to SentinelTestStixImport
- [ ] Logic App has correct RBAC to DCE
- [ ] Logic App configured with Oct 26 time range
- [ ] Manual trigger successful
- [ ] Data visible in TacitRed_Findings_CL table
- [ ] Analytics rules execute without errors
- [ ] Analytics rules show results for Oct 26 data
- [ ] Workbooks display TacitRed data
- [ ] All resources in single RG

## Rollback Plan
If consolidation fails:
1. Keep `rg-sentinel-threatintel` intact
2. Point analytics rules to legacy DCR
3. Document issues for troubleshooting

## Best Practice Validation
✅ **Single RG for small/medium deployments** (Microsoft recommended)  
✅ **All data ingestion in same RG as workspace**  
✅ **Workbooks co-located with Sentinel workspace**  
✅ **Consistent naming convention** (`dce-sentinel-ti`, `dcr-*`, `logic-*`)  
✅ **Managed identities for authentication** (no keys in Logic Apps)
