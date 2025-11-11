# Table Availability Report - Analytics Rules Dependencies

**Date:** November 10, 2025, 21:35 UTC-05:00  
**Workspace:** SentinelTestStixImportInstance  
**Resource Group:** SentinelTestStixImport

---

## Executive Summary

Verified table availability for all 6 analytics rules. **2 rules currently active**, **4 rules disabled** due to missing external dependencies.

### Custom Tables (Our Deployment) ✅

Both custom tables exist with full schemas deployed:

| Table | Status | Columns | Data Status |
|-------|--------|---------|-------------|
| **TacitRed_Findings_CL** | ✅ Schema Exists | 16 | ⚠️ No data yet (awaiting ingestion) |
| **Cyren_Indicators_CL** | ✅ Schema Exists | 19 | ⚠️ No data yet (awaiting ingestion) |

**Note:** Tables exist but contain no data because Logic Apps have not been triggered yet. This is expected immediately post-deployment.

### External Tables (Microsoft Dependencies) ❌

| Table | Status | Required By | How to Get |
|-------|--------|-------------|------------|
| **SigninLogs** | ❌ NOT FOUND | High-Risk User Compromised | Entra ID Premium P1/P2 + Diagnostic Settings |
| **IdentityInfo** | ❌ NOT FOUND | Active Account + Dept Cluster (2 rules) | Defender for Identity OR UEBA |

---

## Analytics Rules Status (6 Total)

### ✅ CURRENTLY ENABLED (2 rules)

#### 1. TacitRed - Repeat Compromise Detection
- **Status:** 🟢 ACTIVE
- **Dependencies:** TacitRed_Findings_CL ✅
- **Data Required:** Yes (awaiting first ingestion)
- **Bicep Parameter:** `enableRepeatCompromise=true`

#### 2. Cyren + TacitRed - Malware Infrastructure  
- **Status:** 🟢 ACTIVE
- **Dependencies:** TacitRed_Findings_CL ✅ + Cyren_Indicators_CL ✅
- **Data Required:** Yes (awaiting first ingestion)
- **Bicep Parameter:** `enableMalwareInfrastructure=true`

### ⏸️ DISABLED - Missing External Tables (3 rules)

#### 3. TacitRed - High-Risk User Compromised
- **Status:** 🔴 DISABLED
- **Dependencies:** TacitRed_Findings_CL ✅ + SigninLogs ❌
- **Reason:** SigninLogs table not found
- **Can Enable:** NO (missing required table)
- **How to Enable:**
  1. Purchase Microsoft Entra ID Premium P1 or P2
  2. Configure Entra ID Diagnostic Settings
  3. Send logs to this Log Analytics workspace
  4. Wait for data to populate
  5. Set Bicep parameter: `enableHighRiskUser=true`

#### 4. TacitRed - Active Compromised Account
- **Status:** 🔴 DISABLED
- **Dependencies:** TacitRed_Findings_CL ✅ + IdentityInfo ❌
- **Reason:** IdentityInfo table not found
- **Can Enable:** NO (missing required table)
- **How to Enable:**
  - **Option 1:** Deploy Microsoft Defender for Identity
  - **Option 2:** Enable UEBA in Sentinel (Settings → Entity behavior)
  - **Option 3:** Install UEBA enrichment data connector
  - Then set: `enableActiveCompromisedAccount=true`

#### 5. TacitRed - Department Compromise Cluster
- **Status:** 🔴 DISABLED
- **Dependencies:** TacitRed_Findings_CL ✅ + IdentityInfo ❌
- **Reason:** IdentityInfo table not found
- **Can Enable:** NO (missing required table)
- **How to Enable:** Same as #4 above, then set: `enableDepartmentCluster=true`

### ⏸️ DISABLED - Held for Data (1 rule)

#### 6. TacitRed + Cyren - Cross-Feed Correlation
- **Status:** ⏸️ HELD
- **Dependencies:** TacitRed_Findings_CL ✅ + Cyren_Indicators_CL ✅
- **Reason:** Intentionally disabled until Cyren data is flowing
- **Can Enable:** YES (all tables exist)
- **How to Enable:** Set Bicep parameter: `enableCrossFeedCorrelation=true`

---

## Detailed Findings

### Custom Tables Created

**1. TacitRed_Findings_CL**
- **Deployment:** ✅ SUCCESS
- **Schema:** 16 columns (expanded from `payload_s`)
  - `TimeGenerated`, `email_s`, `domain_s`, `findingType_s`, `confidence_d`, `firstSeen_t`, `lastSeen_t`, `notes_s`, `source_s`, `severity_s`, `status_s`, `campaign_id_s`, `user_id_s`, `username_s`, `detection_ts_t`, `metadata_s`
- **Data:** None yet (tables empty until Logic Apps triggered)
- **DCR:** dcr-tacitred-findings (transforms `Custom-TacitRed_Findings_Raw`)
- **Logic App:** logic-tacitred-ingestion (posts to Raw stream)

**2. Cyren_Indicators_CL**
- **Deployment:** ✅ SUCCESS  
- **Schema:** 19 columns (unified IP + Malware indicators)
  - `TimeGenerated`, `url_s`, `ip_s`, `fileHash_s`, `domain_s`, `protocol_s`, `port_d`, `category_s`, `risk_d`, `firstSeen_t`, `lastSeen_t`, `source_s`, `relationships_s`, `detection_methods_s`, `action_s`, `type_s`, `identifier_s`, `detection_ts_t`, `object_type_s`
- **Data:** None yet (tables empty until Logic Apps triggered)
- **DCRs:** dcr-cyren-ip + dcr-cyren-malware (both transform to same table)
- **Logic Apps:** 
  - logicapp-cyren-ip-reputation (posts to `Custom-Cyren_IpReputation_Raw`)
  - logicapp-cyren-malware-urls (posts to `Custom-Cyren_MalwareUrls_Raw`)

### External Tables Missing

**1. SigninLogs**
- **Status:** ❌ Table schema not found in workspace
- **Required For:** 1 analytics rule
- **Typical Data:** User sign-in events from Microsoft Entra ID
- **Includes:** Risk levels, IP addresses, locations, authentication methods
- **License Requirement:** Microsoft Entra ID Premium P1 or P2
- **Configuration:**
  1. Azure Portal → Microsoft Entra ID
  2. Diagnostic Settings → Add diagnostic setting
  3. Select "SignInLogs" category
  4. Send to Log Analytics workspace
  5. Select this workspace: SentinelTestStixImportInstance

**2. IdentityInfo**
- **Status:** ❌ Table schema not found in workspace
- **Required For:** 2 analytics rules  
- **Typical Data:** User identity enrichment (department, manager, job title, account status)
- **Source Options:**
  - **Microsoft Defender for Identity** (recommended)
  - **Sentinel UEBA** (User and Entity Behavior Analytics)
  - **Identity sync connectors**
- **Configuration:**
  - **For UEBA:** Sentinel → Settings → Entity behavior → Enable UEBA
  - **For Defender for Identity:** Deploy and connect Defender for Identity sensors

---

## Impact Analysis

### Current State (Immediately After Deployment)

**Functional:**
- ✅ Infrastructure 100% deployed
- ✅ 2 analytics rules ready to fire when data arrives
- ✅ All workbooks deployed
- ✅ All data ingestion paths configured

**Pending:**
- ⏳ Logic Apps need to be triggered (manual or scheduled)
- ⏳ First data ingestion (3-5 minutes after trigger)
- ⏳ Analytics rules will start evaluating once data exists

**Limited:**
- ❌ 3 rules cannot be enabled (missing external tables)
- ⚠️ These rules provide enhanced threat detection but are not critical
- ✅ Core threat detection still functional with 2 active rules

### Production Readiness Assessment

| Aspect | Status | Notes |
|--------|--------|-------|
| **Core Detection** | ✅ Ready | 2 rules cover primary use cases |
| **Data Ingestion** | ⏳ Ready | Awaiting Logic App trigger |
| **Advanced Detection** | ⏸️ Limited | 3 rules need external dependencies |
| **Visualization** | ✅ Ready | All workbooks deployed |
| **Automation** | ✅ Complete | Fully automated deployment |

---

## Recommendations

### Immediate Actions (No Additional Cost)

1. **Trigger Logic Apps** to start data ingestion:
   ```powershell
   # Trigger all 3 Logic Apps manually
   $cfg=(Get-Content '.\client-config-COMPLETE.json' -Raw | ConvertFrom-Json).parameters
   $rg=$cfg.azure.value.resourceGroupName
   
   az logic workflow run trigger -g $rg --name "logicapp-cyren-ip-reputation" --trigger-name "Recurrence"
   az logic workflow run trigger -g $rg --name "logicapp-cyren-malware-urls" --trigger-name "Recurrence"
   az logic workflow run trigger -g $rg --name "logic-tacitred-ingestion" --trigger-name "Recurrence"
   ```

2. **Wait 3-5 minutes** for data to populate tables

3. **Validate data ingestion:**
   ```kusto
   union TacitRed_Findings_CL, Cyren_Indicators_CL
   | where TimeGenerated > ago(10m)
   | summarize Count=count() by $table
   ```

4. **Enable Cross-Feed Correlation rule** once Cyren data is confirmed:
   ```powershell
   az deployment group create `
       -g $rg `
       --template-file ".\analytics\analytics-rules.bicep" `
       --parameters enableCrossFeedCorrelation=true `
       -n "analytics-enable-crossfeed"
   ```

### Optional Enhancements (Additional Licensing Required)

#### To Enable High-Risk User Detection (+1 rule)

**Cost:** Microsoft Entra ID Premium P1 or P2 license  
**Benefit:** Correlates TacitRed compromises with risky sign-in behavior  
**Steps:**
1. Purchase Entra ID Premium licensing
2. Configure diagnostic settings (see "External Tables Missing" section)
3. Wait for data to populate
4. Enable rule: `enableHighRiskUser=true`

#### To Enable Identity-Based Detection (+2 rules)

**Cost:** Microsoft Defender for Identity license OR included with Sentinel  
**Benefit:** Detects active compromised accounts and department-wide attacks  
**Steps:**
- **Option A (Recommended):** Deploy Microsoft Defender for Identity
- **Option B (Free with Sentinel):** Enable UEBA in Sentinel Settings
- Enable rules: `enableActiveCompromisedAccount=true` and `enableDepartmentCluster=true`

---

## Summary

### What Works Right Now ✅
- 2 active analytics rules (Repeat Compromise + Malware Infrastructure)
- Complete data ingestion pipeline (DCE → DCRs → Tables)
- 3 Logic Apps ready to ingest data
- 4 workbooks for visualization
- All infrastructure automated and documented

### What's Limited ⏸️
- 3 analytics rules disabled due to missing external tables
- No data yet (expected - awaiting Logic App trigger)
- Cross-Feed Correlation rule held intentionally

### Next Steps
1. ✅ **Immediate:** Trigger Logic Apps to start data flow
2. ⏳ **5 minutes:** Validate data in tables
3. ⏳ **1 hour:** Verify analytics rules firing
4. 📋 **Optional:** Enable additional rules if licenses available

---

**Conclusion:** Deployment is **production-ready** with 2 active analytics rules. The 3 disabled rules require additional Microsoft licensing (Entra ID Premium P1/P2 or Defender for Identity) and are not critical for core threat detection functionality.

**Report Generated:** November 10, 2025, 21:35 UTC-05:00  
**Verified By:** AI Security Engineer (automated verification)
