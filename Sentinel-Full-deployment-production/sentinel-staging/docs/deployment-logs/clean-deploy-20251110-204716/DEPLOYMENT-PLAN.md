# Clean Deployment Plan - Production Automation
**Date:** November 10, 2025, 20:47 UTC-05:00  
**Deployment ID:** clean-deploy-20251110-204716  
**Authority:** Full administrator rights, zero manual intervention required

---

## Mission Statement

Deploy a complete, production-grade Sentinel Threat Intelligence solution with:
- ✅ 100% automation (no manual steps)
- ✅ Zero errors or exceptions
- ✅ Full logging and diagnostics
- ✅ Complete operational visibility
- ✅ Validated data ingestion and analytics

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL THREAT INTELLIGENCE                  │
│                        Data Flow Architecture                    │
└─────────────────────────────────────────────────────────────────┘

External APIs                  Azure Monitor Ingestion         Sentinel Workspace
─────────────                 ────────────────────────        ─────────────────────

Cyren IP API ────┐
                 ├──→ Logic Apps ──→ DCE ──→ DCR (*_Raw) ──→ Transform ──→ Custom Tables
Cyren Malware ───┤                            │                  │            │
                 │                            │                  │            ├─ Cyren_MalwareUrls_CL
TacitRed API ────┘                            │                  │            ├─ Cyren_IpReputation_CL
                                              │                  │            └─ TacitRed_Findings_CL
                                              │                  │
                                              │                  └──→ JSON → Expanded Columns
                                              │
                                              └─ Streams:
                                                 • Custom-Cyren_IpReputation_Raw
                                                 • Custom-Cyren_MalwareUrls_Raw
                                                 • Custom-TacitRed_Findings_Raw

                                                                 Analytics Rules (8)
                                                                 ───────────────────
                                                                 │
                                                                 ├─ Malware Infrastructure
                                                                 ├─ Cross-Feed Correlation
                                                                 ├─ Repeat Compromise
                                                                 ├─ High Risk User
                                                                 ├─ Active Compromised Account
                                                                 ├─ Department Cluster
                                                                 ├─ Threat Actor Campaign
                                                                 └─ Account Takeover

                                                                 Workbooks (4)
                                                                 ─────────────
                                                                 │
                                                                 ├─ Cyren Threat Intelligence
                                                                 ├─ Executive Risk Dashboard
                                                                 ├─ Threat Hunter Arsenal
                                                                 └─ Threat Intelligence Command Center
```

---

## Official References

All implementation based exclusively on:
1. **Azure Monitor Logs Ingestion API**  
   https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview

2. **Azure Sentinel Analytics Rules**  
   https://learn.microsoft.com/azure/sentinel/detect-threats-custom

3. **Azure Sentinel Solutions**  
   https://github.com/Azure/Azure-Sentinel/tree/master/Solutions

4. **Data Collection Rules (DCRs)**  
   https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview

5. **Azure RBAC Best Practices**  
   https://learn.microsoft.com/azure/role-based-access-control/best-practices

---

## Deployment Phases

### Phase 1: Infrastructure Foundation (Est. 5 min)

**Components:**
1. **Data Collection Endpoint (DCE)**
   - Name: `dce-sentinel-ti`
   - Purpose: Ingestion endpoint for custom logs
   - Network: Public access (production: use Private Link)

2. **Custom Tables** (Simple Schema: TimeGenerated + payload_s)
   - `TacitRed_Findings_CL`
   - `Cyren_MalwareUrls_CL`
   - `Cyren_IpReputation_CL`

3. **Data Collection Rules (DCRs)** with Transform Streams
   - `dcr-cyren-ip` (Input: Raw → Output: Cyren_IpReputation_CL)
   - `dcr-cyren-malware` (Input: Raw → Output: Cyren_MalwareUrls_CL)
   - `dcr-tacitred-findings` (Input: Raw → Output: TacitRed_Findings_CL)

**Critical Design Decision:**
- **Simple Schema Pattern** (TimeGenerated + payload_s)
- DCR transforms parse JSON into expanded columns
- Parsers provide virtual column extraction for analytics
- **Proven working pattern from previous deployments**

**Logs:** `docs/deployment-logs/clean-deploy-20251110-204716/infrastructure/`

---

### Phase 2: Logic Apps & RBAC (Est. 5 min)

**Components:**
1. **Cyren IP Reputation Logic App**
   - Schedule: Every 6 hours
   - Stream: `Custom-Cyren_IpReputation_Raw` ✅
   - Auth: JWT token from config

2. **Cyren Malware URLs Logic App**
   - Schedule: Every 6 hours
   - Stream: `Custom-Cyren_MalwareUrls_Raw` ✅
   - Auth: JWT token from config

3. **TacitRed Ingestion Logic App**
   - Schedule: Every 15 minutes
   - Stream: `Custom-TacitRed_Findings_Raw` ✅
   - Auth: API key from config

**RBAC Configuration:**
- Role: `Monitoring Metrics Publisher` (for DCE/DCR ingestion)
- Scope: Subscription level
- Wait: 120 seconds after assignment (proven propagation time)

**Critical Constraint:**
- Logic Apps MUST post to `*_Raw` streams
- Direct posting to `*_CL` tables bypasses DCR transforms
- Results in empty payloads (documented issue from previous session)

**Logs:** `docs/deployment-logs/clean-deploy-20251110-204716/infrastructure/`

---

### Phase 3: Analytics & Workbooks (Est. 2 min)

**Analytics Rules (8 total):**

| Rule Name | Type | Data Sources | Entity Mapping |
|-----------|------|--------------|----------------|
| Malware Infrastructure Correlation | Correlation | TacitRed + Cyren | Domain, Account |
| Cross-Feed Threat Correlation | Correlation | TacitRed + Cyren | Domain |
| Repeat User Compromise Pattern | Single-source | TacitRed | Account |
| High Risk User Compromised | Correlation | TacitRed + SigninLogs | Account, IP |
| Active Compromised Account | Correlation | TacitRed + IdentityInfo | Account |
| Department Compromise Cluster | Single-source | TacitRed | Account, Domain |
| Threat Actor Campaign Detection | Correlation | TacitRed + Cyren | Domain |
| Account Takeover Indicator | Correlation | TacitRed + SigninLogs | Account, IP |

**Schedule:**
- Frequency: PT30M (every 30 minutes)
- Lookback: P7D (7 days)
- Trigger threshold: 1 event minimum

**Workbooks (4 total):**

1. **Cyren Threat Intelligence Dashboard**
   - Overview stats, risk distribution, top domains
   - TacitRed correlation insights
   - Ingestion health monitoring

2. **Executive Risk Dashboard**
   - Overall risk assessment
   - 30-day threat trends
   - SLA performance metrics

3. **Threat Hunter Arsenal**
   - Rapid credential reuse detection
   - MITRE ATT&CK mapping
   - Advanced hunting queries

4. **Threat Intelligence Command Center**
   - Real-time threat timeline
   - Velocity and acceleration metrics
   - Statistical anomaly detection

**Logs:** 
- `docs/deployment-logs/clean-deploy-20251110-204716/analytics/`
- `docs/deployment-logs/clean-deploy-20251110-204716/workbooks/`

---

### Phase 4: Validation & Testing (Est. 5 min)

**Test Plan:**

1. **Logic App Trigger** (Manual, immediate)
   - Trigger all 3 Logic Apps
   - Wait 180 seconds for ingestion

2. **Data Validation Queries:**
   ```kusto
   // Check record counts and payload structure
   union Cyren_MalwareUrls_CL, Cyren_IpReputation_CL, TacitRed_Findings_CL
   | where TimeGenerated > ago(10m)
   | extend PayloadLength = strlen(payload_s)
   | summarize Count=count(), AvgPayloadSize=avg(PayloadLength) by Type=$table
   ```

3. **Analytics Rule Validation:**
   ```kusto
   // Simulate analytics rule queries
   TacitRed_Findings_CL
   | where TimeGenerated > ago(1h)
   | summarize CompromisedUsers=dcount(email_s), Domains=dcount(domain_s)
   ```

4. **Workbook Smoke Test:**
   - Open each workbook in Azure Portal
   - Verify no query errors
   - Confirm data visualization populates

**Expected Results:**
- ✅ Tables contain data with non-empty payloads
- ✅ Analytics rules show "Active" status
- ✅ Workbooks render without errors
- ✅ No failed Logic App runs

**Logs:** `docs/deployment-logs/clean-deploy-20251110-204716/validation/`

---

## Success Criteria

| Criteria | Target | Validation Method |
|----------|--------|-------------------|
| Zero deployment errors | 0 errors | Review all log files |
| All resources deployed | 16 resources | Count in Azure Portal |
| Logic Apps functional | 3/3 successful runs | Check run history |
| Data ingestion working | >0 rows in tables | KQL query validation |
| Analytics rules active | 8/8 enabled | Sentinel Analytics blade |
| Workbooks operational | 4/4 no errors | Manual verification |
| RBAC propagated | All assignments | Test ingestion success |
| Documentation complete | All logs in docs/ | File structure validation |

---

## Known Issues & Mitigations

### Issue 1: Empty Payloads (RESOLVED)
**Root Cause:** Logic Apps posting to `*_CL` tables instead of `*_Raw` streams  
**Mitigation:** All Bicep files verified to use `*_Raw` streams  
**Memory Updated:** Yes, documented in institutional knowledge base

### Issue 2: RBAC Propagation Delays
**Root Cause:** Azure RBAC assignments require propagation time  
**Mitigation:** 120-second wait after all assignments (proven pattern)  
**Official Ref:** https://learn.microsoft.com/azure/role-based-access-control/troubleshooting#role-assignment-changes-are-not-being-detected

### Issue 3: Correlation Rules Return Zero Results (EXPECTED)
**Root Cause:** No domain overlap between TacitRed and Cyren datasets  
**Mitigation:** None needed - working as designed. Rules will trigger when overlap occurs  
**Validation:** Single-source rules should show results

---

## Rollback Plan

If deployment fails:
1. Delete resource group (clean slate)
2. Review error logs in `docs/deployment-logs/clean-deploy-*/`
3. Fix identified issues
4. Re-run deployment script
5. Document lessons learned in memory

**Note:** With clean state and verified configurations, rollback should not be necessary.

---

## Post-Deployment Actions

1. ✅ Validate all components
2. ✅ Archive deployment logs
3. ✅ Update institutional memory/knowledge base
4. ✅ Mark obsolete files as `.outofscope`
5. ✅ Generate deployment summary report
6. ✅ Document any deviations or innovations

---

## Innovation & Optimization

**Enhanced Logging Structure:**
- Organized by deployment phase (infrastructure, analytics, workbooks, validation)
- Timestamped with unique deployment ID
- Enables rapid root cause analysis for future issues
- **Rationale:** Exceeds standard practice by providing granular phase-specific logs

**Stream Name Validation:**
- Pre-flight check ensures all Bicep files use correct `*_Raw` streams
- Prevents repeat of empty payload issue
- **Rationale:** Proactive validation prevents known failure modes

**RBAC Wait Optimization:**
- Single consolidated 120s wait after all assignments
- More efficient than per-assignment waits
- **Rationale:** Based on official Azure documentation and proven deployment patterns

---

## Deployment Timeline

| Phase | Start | Est. Duration | Completion |
|-------|-------|---------------|------------|
| Preparation | 20:47 | 2 min | TBD |
| Infrastructure | TBD | 5 min | TBD |
| Logic Apps & RBAC | TBD | 5 min | TBD |
| Analytics & Workbooks | TBD | 2 min | TBD |
| Validation | TBD | 5 min | TBD |
| **TOTAL** | **20:47** | **19 min** | **TBD** |

---

**Status:** Deployment in progress...  
**Next Update:** After Phase 1 completion
