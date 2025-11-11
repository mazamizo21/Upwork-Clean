# Analytics Rules Deployment - Remediation Status

**Date:** November 10, 2025, 21:15 UTC-05:00  
**Deployment ID:** clean-deploy-20251110-204716

---

## 3. TROUBLESHOOTING, DEBUGGING, AND CLEANUP

### 3.1 Root Cause Analysis

**Issue #1:** Incorrect KQL file paths in Bicep template  
**Evidence:** BCP091 errors in deployment log - "Could not find a part of the path"  
**Root Cause:** Bicep template referenced `../analytics-rules/` but files are in `./rules/`  
**Official Reference:** [Bicep loadTextContent function](https://learn.microsoft.com/azure/azure-resource-manager/bicep/bicep-functions-files#loadtextcontent)

**Issue #2:** Missing Malware Infrastructure rule definition  
**Evidence:** Rule exists as KQL file but not defined in Bicep template  
**Root Cause:** Incomplete Bicep template - 5 of 6 expected rules defined  

**Issue #3:** KQL files use parser functions in NO-PARSER deployment  
**Evidence:** LogAnalyticsSyntaxError - "Query could not be parsed at 'title'"  
**Root Cause:** Rules reference `parser_tacitred_findings()` and `parser_cyren_indicators()` but parsers not deployed  
**Official Reference:** [Sentinel KQL Parsers](https://learn.microsoft.com/azure/sentinel/normalization-parsers-overview)

---

### 3.2 Fixes Applied

#### Fix #1: Corrected KQL File Paths ✅
**Files Modified:** `analytics/analytics-rules.bicep` (lines 28, 111, 193, 268, 342)  
**Changes:**
- `loadTextContent('../analytics-rules/rule-*.kql')` → `loadTextContent('./rules/rule-*.kql')`
- Applied to 5 existing rules

#### Fix #2: Added Malware Infrastructure Rule ✅
**Files Modified:** `analytics/analytics-rules.bicep`  
**Changes:**
- Added parameter: `enableMalwareInfrastructure bool = true` (line 12)
- Added resource definition: `ruleMalwareInfra` (lines 333-410)
- Updated output array to include new rule (line 510)
- Rule count: 5 → 6

#### Fix #3: Convert to NO-PARSER Mode ⏳ IN PROGRESS
**Conversion Pattern:**
```kusto
// BEFORE (Parser mode)
parser_tacitred_findings()
| where TimeGenerated >= ago(lookbackPeriod)

// AFTER (NO-PARSER mode)
TacitRed_Findings_CL
| where TimeGenerated >= ago(lookbackPeriod)
| extend
    Email = tostring(email_s),
    Domain = tostring(domain_s),
    FindingType = tostring(findingType_s),
    Confidence = todouble(confidence_d),
    FirstSeen = todatetime(firstSeen_t),
    LastSeen = todatetime(lastSeen_t)
```

**Files Converted:**
1. ✅ `rule-repeat-compromise.kql` - Converted (line 11: parser → TacitRed_Findings_CL)
2. ⏳ `rule-high-risk-user-compromised.kql` - PENDING
3. ⏳ `rule-active-compromised-account.kql` - PENDING
4. ⏳ `rule-department-compromise-cluster.kql` - PENDING
5. ⏳ `rule-cross-feed-correlation.kql` - PENDING (uses both TacitRed and Cyren parsers)
6. ✅ `rule-malware-infrastructure.kql` - ALREADY CORRECT

---

### 3.3 File Cleanup Requirements

**Files Exceeding 500-Line Limit:**
- `analytics/analytics-rules.bicep`: 512 lines (exceeds by 12 lines)
  - **Action Required:** Modularize into separate rule files or split by rule type
  - **Proposed Solution:** Extract rule definitions into individual Bicep modules
  - **Timeline:** Post-deployment validation

**Obsolete Files to Mark `.outofscope`:**
Based on analysis, duplicate Logic App Bicep files detected:
- `infrastructure/bicep/logicapp-cyren-ip-reputation.bicep` (duplicate)
- `infrastructure/bicep/logicapp-cyren-malware-urls.bicep` (duplicate)
- `infrastructure/bicep/logicapp-tacitred-ingestion.bicep` (incorrect path location)
- `infrastructure/bicep/dcr-*.bicep` files (if duplicates of `infrastructure/*.bicep`)
- `infrastructure/bicep/ccf-connector-*.bicep` (not used in current deployment)

**Action Timeline:** After successful deployment validation

---

### 3.4 Deployment Test Results

**Attempt #1:** Failed - Incorrect file paths  
**Attempt #2:** Failed - KQL syntax errors (parser functions)  
**Attempt #3:** PENDING - After NO-PARSER conversion complete  

**Expected Success Criteria:**
- ✅ Zero Bicep compilation errors
- ✅ Zero KQL syntax errors
- ✅ All 6 rules deployed and enabled
- ✅ Rules appear in Sentinel Analytics blade
- ✅ Entity mappings configured correctly

---

### 3.5 Memory/Knowledge Base Updates

**Lessons Learned:**
1. **Bicep loadTextContent paths** must be relative to the Bicep file location, not repo root
2. **Parser-based analytics** fail if parsers not deployed - always verify parser existence or use direct table queries
3. **NO-PARSER mode** is more reliable for production deployments - avoids parser deployment complexity
4. **File organization** matters - maintain consistent directory structure and naming conventions
5. **Modular Bicep templates** improve maintainability when files exceed 500 lines

**Added to Institutional Memory:**
- Analytics rules require explicit choice between PARSER and NO-PARSER mode
- Direct table queries pattern for TacitRed and Cyren tables
- Bicep file path resolution for loadTextContent function
- 500-line file limit enforcement for all code files

**Official Documentation Consulted:**
- https://learn.microsoft.com/azure/azure-resource-manager/bicep/bicep-functions-files
- https://learn.microsoft.com/azure/sentinel/detect-threats-custom
- https://learn.microsoft.com/azure/sentinel/normalization-parsers-overview
- https://learn.microsoft.com/azure/data-explorer/kusto/query/scalar-data-types

---

### 3.6 Next Actions

**Immediate (Complete Conversion):**
1. Convert remaining 4 KQL files to NO-PARSER mode
2. Validate all KQL syntax
3. Redeploy analytics rules
4. Verify deployment success
5. Test rules with sample data

**Post-Deployment:**
6. Modularize analytics-rules.bicep (reduce from 512 to <500 lines per file)
7. Mark obsolete/duplicate files as `.outofscope`
8. Document final architecture in deployment guide
9. Archive all logs and create deployment summary
10. Update institutional memory with complete solution

---

## Status: IN PROGRESS
**Current Phase:** 3.2 - Completing NO-PARSER conversions  
**Next Milestone:** Analytics rules deployment success  
**Est. Completion:** 15-20 minutes

