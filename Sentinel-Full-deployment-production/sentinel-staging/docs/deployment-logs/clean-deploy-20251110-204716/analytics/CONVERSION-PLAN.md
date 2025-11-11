# Analytics Rules Parser → NO-PARSER Conversion Plan

**Date:** November 10, 2025, 21:08 UTC-05:00  
**Issue:** KQL files reference parser functions that don't exist  
**Solution:** Convert to direct table queries

---

## Parser Function Mapping

### TacitRed Parser Function
**Function:** `parser_tacitred_findings()`  
**Replace With:** `TacitRed_Findings_CL`  
**Direct Table Access Pattern:**
```kusto
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

### Cyren Parser Function
**Function:** `parser_cyren_indicators()`  
**Replace With:** `Cyren_Indicators_CL`  
**Direct Table Access Pattern:**
```kusto
Cyren_Indicators_CL
| where TimeGenerated >= ago(lookbackPeriod)
| extend 
    Domain = tostring(domain_s),
    URL = tostring(url_s),
    RiskScore = toint(risk_d),
    Category = tostring(category_s),
    Type = tostring(type_s),
    FirstSeen = todatetime(firstSeen_t),
    LastSeen = todatetime(lastSeen_t)
```

---

## Files Requiring Conversion

1. ✅ **rule-malware-infrastructure.kql** - Already uses direct table access (correct pattern)
2. ❌ **rule-repeat-compromise.kql** - Uses `parser_tacitred_findings()`
3. ❌ **rule-high-risk-user-compromised.kql** - Uses `parser_tacitred_findings()`
4. ❌ **rule-active-compromised-account.kql** - Uses `parser_tacitred_findings()`
5. ❌ **rule-department-compromise-cluster.kql** - Uses `parser_tacitred_findings()`
6. ❌ **rule-cross-feed-correlation.kql** - Uses both `parser_tacitred_findings()` and `parser_cyren_indicators()`

---

## Conversion Steps (Per File)

1. Replace `parser_tacitred_findings()` with `TacitRed_Findings_CL`
2. Add explicit `extend` statements for field extraction
3. Remove parser-specific columns (e.g., `IsRecent` - use `TimeGenerated` filter instead)
4. Update column references to use `_s`, `_d`, `_t` suffixes
5. Verify KQL syntax with test query
6. Update comments to reflect NO-PARSER approach

---

## Testing Strategy

After conversion:
1. Validate Bicep compilation: `az bicep build --file .\analytics\analytics-rules.bicep`
2. Deploy to test workspace
3. Verify rules appear in Sentinel Analytics blade
4. Test each rule with sample data query
5. Confirm entity mappings work correctly

---

## Reference: Correct Pattern Example

From `rule-malware-infrastructure.kql`:
```kusto
let CompromisedDomains = TacitRed_Findings_CL
    | where TimeGenerated >= ago(lookbackPeriod)
    | where isnotempty(domain_s)
    | extend DomainRaw = tolower(tostring(domain_s))
    | extend Parts = split(DomainRaw, '.')
    | extend RegDomain = iif(array_length(Parts) >= 2, strcat(Parts[-2], '.', Parts[-1]), DomainRaw)
    | summarize 
        CompromisedUsers = make_set(tostring(email_s)),
        UserCount = dcount(tostring(email_s)),
        FirstCompromise = min(todatetime(firstSeen_t)),
        LatestCompromise = max(todatetime(lastSeen_t)),
        FindingTypes = make_set(tostring(findingType_s)),
        AvgConfidence = avg(todouble(confidence_d))
        by RegDomain;
```

**Key Points:**
- Direct table name (`TacitRed_Findings_CL`)
- Explicit type conversions (`tostring()`, `toint()`, `todatetime()`)
- Column suffixes (`_s` for string, `_d` for double, `_t` for datetime)
- No IsRecent column (use TimeGenerated filter)

---

## Official Documentation References

- [Azure Monitor Custom Tables](https://learn.microsoft.com/azure/azure-monitor/logs/create-custom-table)
- [KQL Data Types](https://learn.microsoft.com/azure/data-explorer/kusto/query/scalar-data-types)
- [Sentinel Analytics Rules](https://learn.microsoft.com/azure/sentinel/detect-threats-custom)
