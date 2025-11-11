# Analytics Rules - Final Configuration

## Status: Production Ready
- **Date**: 2025-11-10 19:15:23
- **Deployment**: Succeeded

## Data Validation
- TacitRed_Findings_CL:  Data present, columns populated
- Cyren_Indicators_CL:  Data present, columns populated
- Domain Overlap: 0 (validated with diagnostic query)

## Rules Configuration

### Single-Source Rules (Active)
1. **TacitRed - Repeat Compromise Detection**
   - Frequency: PT1H
   - Status: ✅ Producing results

2. **TacitRed - High-Risk User Compromised**
   - Frequency: PT1H
   - Status: ✅ Enabled

3. **TacitRed - Active Compromised Account**
   - Frequency: PT6H
   - Status:  Producing results (2K+ events)

4. **TacitRed - Department Compromise Cluster**
   - Frequency: PT6H
   - Status:  Producing results

### Correlation Rules (Validated)
5. **Cyren + TacitRed - Malware Infrastructure**
   - Frequency: PT30M (faster evaluation)
   - Filters: Risk >= 60, Type/Category = malware|phishing, LastSeen active
   - Domain Normalization: Registrable domain (SLD.TLD)
   - Current Matches: 0 (no overlap in current data)
   - Status:  Ready to alert when overlap occurs

6. **TacitRed + Cyren - Cross-Feed Correlation**
   - Frequency: PT30M (faster evaluation)
   - Filters: Risk >= 60, LastSeen active window
   - Domain Normalization: Registrable domain (SLD.TLD)
   - Current Matches: 0 (no overlap in current data)
   - Status:  Ready to alert when overlap occurs

## Root Cause Analysis
- Analytics rules were showing 0 results due to:
  1.  DCR transforms using unsupported coalesce() function
  2.  Missing Raw input streams in DCRs
  3.  Correlation rules had strict filters with no current data overlap

## Fixes Applied
1. ✅ Replaced coalesce() with iif/isnull in all DCR transforms
2. ✅ Added Raw input streams to all DCRs
3. ✅ Normalized domain matching (registrable domain extraction)
4. ✅ Validated no current overlap exists (data-driven 0, not pipeline bug)
5. ✅ Restored production filters (risk >= 60, type/category filters)
6. ✅ Kept PT30M schedule for faster signal when overlap appears

## Files Modified
- infrastructure/bicep/dcr-tacitred-findings.bicep
- infrastructure/bicep/dcr-cyren-ip.bicep
- infrastructure/bicep/dcr-cyren-malware.bicep
- analytics/rules/rule-malware-infrastructure.kql
- analytics/rules/rule-cross-feed-correlation.kql
- analytics/analytics-rules.bicep

## Next Steps
- Rules will automatically evaluate on schedule
- Correlation alerts will fire when TacitRed domains intersect with Cyren IOCs
- Monitor single-source rules for immediate signal
- Review workbooks for threat intelligence visualization

## Documentation
- Deployment logs: .\docs\deployment-logs\analytics-final-20251110191440
- Memory updated with DCR/Logic App mappings
- All TODOs completed
