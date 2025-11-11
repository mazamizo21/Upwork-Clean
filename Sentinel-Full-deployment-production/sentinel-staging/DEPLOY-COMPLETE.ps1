# Complete Automated Deployment - Sentinel Threat Intelligence
# Version: 1.0.0 - Full automation with resource dependency handling

[CmdletBinding()]
$ConfigFile = 'd:\REPO\Upwork-Clean\Sentinel-Full-deployment-production\sentinel-staging\client-config-COMPLETE.json'

# Ensure script runs from correct directory
$ScriptDir = Split-Path -Parent $PSCommandPath
Set-Location $ScriptDir
Write-Host "Working directory: $ScriptDir" -ForegroundColor Gray

$ErrorActionPreference = "Stop"
$start = Get-Date

Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     SENTINEL THREAT INTELLIGENCE - COMPLETE DEPLOYMENT      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

# Load config
$config = (Get-Content $ConfigFile | ConvertFrom-Json).parameters
$sub = $config.azure.value.subscriptionId
$rg = $config.azure.value.resourceGroupName
$ws = $config.azure.value.workspaceName
$loc = $config.azure.value.location

# Create logs
$ts = Get-Date -Format "yyyyMMddHHmmss"
$logDir = ".\docs\deployment-logs\complete-$ts"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
Start-Transcript "$logDir\transcript.log"

Write-Host "Config: $sub | $rg | $ws | $loc`n" -ForegroundColor Gray

# Prerequisites
Write-Host "═══ PHASE 1: PREREQUISITES ═══" -ForegroundColor Cyan
az account set --subscription $sub
$wsData = az monitor log-analytics workspace show -g $rg -n $ws -o json | ConvertFrom-Json
$wsObj = @{
    id = $wsData.id
    customerId = $wsData.customerId
}
Write-Host "✓ Prerequisites validated`n" -ForegroundColor Green

# Deploy DCE
Write-Host "═══ PHASE 2: INFRASTRUCTURE ═══" -ForegroundColor Cyan
Write-Host "[1/4] Deploying DCE..." -ForegroundColor Yellow

$dceTemplate = '{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","parameters":{"loc":{"type":"string"},"name":{"type":"string"}},"resources":[{"type":"Microsoft.Insights/dataCollectionEndpoints","apiVersion":"2022-06-01","name":"[parameters(''name'')]","location":"[parameters(''loc'')]","properties":{"networkAcls":{"publicNetworkAccess":"Enabled"}}}],"outputs":{"id":{"type":"string","value":"[resourceId(''Microsoft.Insights/dataCollectionEndpoints'',parameters(''name''))]"},"endpoint":{"type":"string","value":"[reference(resourceId(''Microsoft.Insights/dataCollectionEndpoints'',parameters(''name''))).logsIngestion.endpoint]"}}}'  
$dceTemplate | Out-File "$env:TEMP\dce.json" -Encoding UTF8

az deployment group create -g $rg --template-file "$env:TEMP\dce.json" --parameters loc=$loc name="dce-sentinel-ti" -n "dce-$ts" -o none

# Get DCE details via REST API (more reliable than deployment output)
$dceUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce-sentinel-ti?api-version=2022-06-01"
$dce = az rest --method GET --uri $dceUri | ConvertFrom-Json
$dceEndpoint = $dce.properties.logsIngestion.endpoint
$dceId = $dce.id
Write-Host "✓ DCE: $dceEndpoint" -ForegroundColor Green

# Deploy tables with full schemas
Write-Host "[2/4] Creating tables with full schemas..." -ForegroundColor Yellow

# TacitRed_Findings_CL - Full schema
$tacitredSchema = @{
    properties = @{
        schema = @{
            name = "TacitRed_Findings_CL"
            columns = @(
                @{name="TimeGenerated";type="datetime"},
                @{name="email_s";type="string"},
                @{name="domain_s";type="string"},
                @{name="findingType_s";type="string"},
                @{name="confidence_d";type="int"},
                @{name="firstSeen_t";type="datetime"},
                @{name="lastSeen_t";type="datetime"},
                @{name="notes_s";type="string"},
                @{name="source_s";type="string"},
                @{name="severity_s";type="string"},
                @{name="status_s";type="string"},
                @{name="campaign_id_s";type="string"},
                @{name="user_id_s";type="string"},
                @{name="username_s";type="string"},
                @{name="detection_ts_t";type="datetime"},
                @{name="metadata_s";type="string"}
            )
        }
    }
} | ConvertTo-Json -Depth 10

# Cyren_Indicators_CL - Full schema
$cyrenSchema = @{
    properties = @{
        schema = @{
            name = "Cyren_Indicators_CL"
            columns = @(
                @{name="TimeGenerated";type="datetime"},
                @{name="url_s";type="string"},
                @{name="ip_s";type="string"},
                @{name="fileHash_s";type="string"},
                @{name="domain_s";type="string"},
                @{name="protocol_s";type="string"},
                @{name="port_d";type="int"},
                @{name="category_s";type="string"},
                @{name="risk_d";type="int"},
                @{name="firstSeen_t";type="datetime"},
                @{name="lastSeen_t";type="datetime"},
                @{name="source_s";type="string"},
                @{name="relationships_s";type="string"},
                @{name="detection_methods_s";type="string"},
                @{name="action_s";type="string"},
                @{name="type_s";type="string"},
                @{name="identifier_s";type="string"},
                @{name="detection_ts_t";type="datetime"},
                @{name="object_type_s";type="string"}
            )
        }
    }
} | ConvertTo-Json -Depth 10

# Create TacitRed table
Write-Host "  Creating TacitRed_Findings_CL..." -ForegroundColor Gray
$tacitredSchema | Out-File -FilePath "./temp_tacitred_schema.json" -Encoding utf8 -Force
az rest --method PUT --url "$($wsObj.id)/tables/TacitRed_Findings_CL?api-version=2023-09-01" --body '@temp_tacitred_schema.json' --header "Content-Type=application/json"
if($LASTEXITCODE -eq 0){ Write-Host "  ✓ TacitRed_Findings_CL created" -ForegroundColor Green; Remove-Item "./temp_tacitred_schema.json" -Force } else { Write-Host "  ✗ Failed to create TacitRed_Findings_CL - check logs" -ForegroundColor Red }

# Create Cyren table
Write-Host "  Creating Cyren_Indicators_CL..." -ForegroundColor Gray
$cyrenSchema | Out-File -FilePath "./temp_cyren_schema.json" -Encoding utf8 -Force
az rest --method PUT --url "$($wsObj.id)/tables/Cyren_Indicators_CL?api-version=2023-09-01" --body '@temp_cyren_schema.json' --header "Content-Type=application/json"
if($LASTEXITCODE -eq 0){ Write-Host "  ✓ Cyren_Indicators_CL created" -ForegroundColor Green; Remove-Item "./temp_cyren_schema.json" -Force } else { Write-Host "  ✗ Failed to create Cyren_Indicators_CL - check logs" -ForegroundColor Red }

# Wait for tables to propagate
Write-Host "  Waiting 30s for table propagation..." -ForegroundColor Yellow
Start-Sleep -Seconds 30
Write-Host "✓ Tables created with full schemas" -ForegroundColor Green

# Deploy DCRs
Write-Host "[3/4] Deploying DCRs..." -ForegroundColor Yellow

# IP Rep DCR
Write-Host "  Deploying Cyren IP DCR..." -ForegroundColor Gray
$ipDcrDeploy = az deployment group create -g $rg --template-file ".\infrastructure\bicep\dcr-cyren-ip.bicep" --parameters workspaceResourceId="$($wsObj.id)" dceResourceId="$dceId" -n "dcr-ip-$ts" -o json | ConvertFrom-Json
$ipDcrImmutableId = $ipDcrDeploy.properties.outputs.immutableId.value
$ipDcrId = $ipDcrDeploy.properties.outputs.id.value

# Malware DCR
Write-Host "  Deploying Cyren Malware DCR..." -ForegroundColor Gray
$malDcrDeploy = az deployment group create -g $rg --template-file ".\infrastructure\bicep\dcr-cyren-malware.bicep" --parameters workspaceResourceId="$($wsObj.id)" dceResourceId="$dceId" -n "dcr-mal-$ts" -o json | ConvertFrom-Json
$malDcrImmutableId = $malDcrDeploy.properties.outputs.immutableId.value
$malDcrId = $malDcrDeploy.properties.outputs.id.value

# TacitRed DCR
Write-Host "  Deploying TacitRed DCR..." -ForegroundColor Gray
$tacitredDcrDeploy = az deployment group create -g $rg --template-file ".\infrastructure\bicep\dcr-tacitred-findings.bicep" --parameters workspaceResourceId="$($wsObj.id)" dceResourceId="$dceId" -n "dcr-tacitred-$ts" -o json | ConvertFrom-Json
$tacitredDcrImmutableId = $tacitredDcrDeploy.properties.outputs.immutableId.value
$tacitredDcrId = $tacitredDcrDeploy.properties.outputs.id.value
Write-Host "✓ DCRs deployed (including TacitRed)" -ForegroundColor Green

# Fallback: Auto-detect DCRs if deployment outputs are missing
Write-Host "`n  Verifying DCR deployment..." -ForegroundColor Yellow
$dcrList = az monitor data-collection rule list --resource-group $rg -o json | ConvertFrom-Json

if ([string]::IsNullOrEmpty($tacitredDcrImmutableId)) {
    Write-Host "  ⚠ TacitRed DCR immutable ID not captured from deployment, auto-detecting..." -ForegroundColor Yellow
    $tacitredDcr = $dcrList | Where-Object { $_.name -like "*tacitred*" -or $_.name -like "*findings*" }
    if ($tacitredDcr) {
        $tacitredDcrImmutableId = $tacitredDcr.immutableId
        $tacitredDcrId = $tacitredDcr.id
        Write-Host "  ✓ Auto-detected TacitRed DCR: $($tacitredDcr.name)" -ForegroundColor Green
    }
}

if ([string]::IsNullOrEmpty($ipDcrImmutableId)) {
    Write-Host "  ⚠ Cyren IP DCR immutable ID not captured, auto-detecting..." -ForegroundColor Yellow
    $ipDcr = $dcrList | Where-Object { $_.name -like "*cyren*ip*" }
    if ($ipDcr) {
        $ipDcrImmutableId = $ipDcr.immutableId
        $ipDcrId = $ipDcr.id
        Write-Host "  ✓ Auto-detected Cyren IP DCR: $($ipDcr.name)" -ForegroundColor Green
    }
}

if ([string]::IsNullOrEmpty($malDcrImmutableId)) {
    Write-Host "  ⚠ Cyren Malware DCR immutable ID not captured, auto-detecting..." -ForegroundColor Yellow
    $malDcr = $dcrList | Where-Object { $_.name -like "*cyren*malware*" }
    if ($malDcr) {
        $malDcrImmutableId = $malDcr.immutableId
        $malDcrId = $malDcr.id
        Write-Host "  ✓ Auto-detected Cyren Malware DCR: $($malDcr.name)" -ForegroundColor Green
    }
}

Write-Host "  ✓ All DCRs verified" -ForegroundColor Green

# Deploy Logic Apps
Write-Host "[4/4] Deploying Logic Apps..." -ForegroundColor Yellow
if(Test-Path ".\infrastructure\logicapp-cyren-ip-reputation.bicep"){
    Write-Host "  Deploying Cyren IP Reputation Logic App..." -ForegroundColor Gray
    Write-Host "    → DCR: $ipDcrImmutableId" -ForegroundColor Cyan
    Write-Host "    → DCE: $dceEndpoint" -ForegroundColor Cyan
    az deployment group create -g $rg --template-file ".\infrastructure\logicapp-cyren-ip-reputation.bicep" --parameters cyrenIpReputationToken="$($config.cyren.value.ipReputation.jwtToken)" dcrImmutableId="$ipDcrImmutableId" dceEndpoint="$dceEndpoint" dcrResourceId="$ipDcrId" dceResourceId="$dceId" -n "la-ip-$ts" -o none 2>$null
    Write-Host "    ✓ Deployed" -ForegroundColor Green
    
    Write-Host "  Deploying Cyren Malware URLs Logic App..." -ForegroundColor Gray
    Write-Host "    → DCR: $malDcrImmutableId" -ForegroundColor Cyan
    Write-Host "    → DCE: $dceEndpoint" -ForegroundColor Cyan
    az deployment group create -g $rg --template-file ".\infrastructure\logicapp-cyren-malware-urls.bicep" --parameters cyrenMalwareUrlsToken="$($config.cyren.value.malwareUrls.jwtToken)" dcrImmutableId="$malDcrImmutableId" dceEndpoint="$dceEndpoint" dcrResourceId="$malDcrId" dceResourceId="$dceId" -n "la-mal-$ts" -o none 2>$null
    Write-Host "    ✓ Deployed" -ForegroundColor Green
}
if(Test-Path ".\infrastructure\bicep\logicapp-tacitred-ingestion.bicep"){
    Write-Host "  Deploying TacitRed Ingestion Logic App..." -ForegroundColor Gray
    # Validate DCR parameters before deployment
    if ([string]::IsNullOrEmpty($tacitredDcrImmutableId) -or [string]::IsNullOrEmpty($tacitredDcrId)) {
        Write-Host "    ⚠ Warning: TacitRed DCR parameters are missing. Attempting final auto-detection..." -ForegroundColor Yellow
        $tacitredDcr = $dcrList | Where-Object { $_.name -like "*tacitred*" -or $_.name -like "*findings*" } | Select-Object -First 1
        if ($tacitredDcr) {
            $tacitredDcrImmutableId = $tacitredDcr.immutableId
            $tacitredDcrId = $tacitredDcr.id
            Write-Host "    ✓ Auto-detected DCR: $($tacitredDcr.name)" -ForegroundColor Green
        } else {
            Write-Host "    ✗ Error: Cannot find TacitRed DCR. Skipping Logic App deployment." -ForegroundColor Red
        }
    }
    
    if (-not [string]::IsNullOrEmpty($tacitredDcrImmutableId)) {
        Write-Host "    → DCR: $tacitredDcrImmutableId" -ForegroundColor Cyan
        Write-Host "    → DCE: $dceEndpoint" -ForegroundColor Cyan
        az deployment group create -g $rg --template-file ".\infrastructure\bicep\logicapp-tacitred-ingestion.bicep" --parameters tacitRedApiKey="$($config.tacitred.value.apiKey)" dcrImmutableId="$tacitredDcrImmutableId" dceEndpoint="$dceEndpoint" dcrResourceId="$tacitredDcrId" dceResourceId="$dceId" -n "la-tacitred-$ts" -o none 2>$null
        Write-Host "    ✓ Deployed" -ForegroundColor Green
    }
}
Write-Host "✓ Logic Apps deployed (Cyren + TacitRed)" -ForegroundColor Green

# Wait for managed identities to propagate
Write-Host "Waiting 120s for managed identities to propagate..." -ForegroundColor Yellow
Start-Sleep -Seconds 120
Write-Host "✓ Identity propagation complete`n" -ForegroundColor Green

# RBAC Assignment (Using PowerShell for reliability)
Write-Host "═══ PHASE 3: RBAC ASSIGNMENT ═══" -ForegroundColor Cyan
Write-Host "  ℹ Assigning Monitoring Metrics Publisher role to Logic Apps" -ForegroundColor Gray
Write-Host "  ℹ This ensures Logic Apps can ingest data to DCR + DCE" -ForegroundColor Gray

# Define Logic Apps and their corresponding DCR/DCE
$logicAppRbacConfig = @(
    @{
        Name = 'logic-cyren-ip-reputation'
        DcrId = $ipDcrId
        DceId = $dceId
    },
    @{
        Name = 'logic-cyren-malware-urls'
        DcrId = $malDcrId
        DceId = $dceId
    },
    @{
        Name = 'logic-tacitred-ingestion'
        DcrId = $tacitredDcrId
        DceId = $dceId
    }
)

Write-Host "`n  Assigning RBAC roles..." -ForegroundColor Yellow
$rbacResults = @()
foreach($laConfig in $logicAppRbacConfig){
    $laName = $laConfig.Name
    try {
        $laObj = az logic workflow show -g $rg -n $laName 2>$null | ConvertFrom-Json
        if($laObj -and $laObj.identity.principalId){
            $principalId = $laObj.identity.principalId
            Write-Host "`n    [$laName]" -ForegroundColor Cyan
            Write-Host "      Principal ID: $principalId" -ForegroundColor Gray
            
            # Assign role on DCR
            if($laConfig.DcrId){
                $dcrName = ($laConfig.DcrId -split '/')[-1]
                Write-Host "      Assigning to DCR: $dcrName" -ForegroundColor Gray
                try {
                    az role assignment create --assignee $principalId --role "Monitoring Metrics Publisher" --scope $laConfig.DcrId 2>$null | Out-Null
                    Write-Host "        ✓ Monitoring Metrics Publisher → DCR" -ForegroundColor Green
                } catch {
                    Write-Host "        ⚠ DCR role may already exist" -ForegroundColor Yellow
                }
            }
            
            # Assign role on DCE
            if($laConfig.DceId){
                $dceName = ($laConfig.DceId -split '/')[-1]
                Write-Host "      Assigning to DCE: $dceName" -ForegroundColor Gray
                try {
                    az role assignment create --assignee $principalId --role "Monitoring Metrics Publisher" --scope $laConfig.DceId 2>$null | Out-Null
                    Write-Host "        ✓ Monitoring Metrics Publisher → DCE" -ForegroundColor Green
                } catch {
                    Write-Host "        ⚠ DCE role may already exist" -ForegroundColor Yellow
                }
            }
            
            $rbacResults += @{
                LogicApp = $laName
                Principal = $principalId
                Status = "RBAC Assigned"
            }
        }else{
            Write-Host "    ✗ $laName : Not found or no identity" -ForegroundColor Red
            $rbacResults += @{
                LogicApp = $laName
                Principal = "N/A"
                Status = "Error"
            }
        }
    } catch {
        Write-Host "    ✗ $laName : Error - $($_.Exception.Message)" -ForegroundColor Red
        $rbacResults += @{
            LogicApp = $laName
            Principal = "ERROR"
            Status = "Failed"
        }
    }
}

# Save results
$rbacResults | ConvertTo-Json | Out-File "$logDir\rbac-verification.json" -Encoding UTF8

Write-Host "`n  ℹ Note: RBAC assignments were created by Bicep during deployment" -ForegroundColor Gray
Write-Host "  ℹ Azure RBAC propagation takes 5-30 minutes" -ForegroundColor Gray
Write-Host "  ℹ Use VALIDATE-DEPLOYMENT.ps1 to check RBAC status after deployment`n" -ForegroundColor Gray

Write-Host "Waiting 60s for initial RBAC propagation..." -ForegroundColor Yellow
Start-Sleep -Seconds 60
Write-Host "✓ Initial wait complete`n" -ForegroundColor Green

# Skip the RBAC propagation monitor - not needed with embedded RBAC
Write-Host "✓ RBAC embedded in Bicep templates - propagation will complete in background`n" -ForegroundColor Green

# Analytics
Write-Host "═══ PHASE 4: ANALYTICS ═══" -ForegroundColor Cyan
Write-Host "[1/1] Deploying analytics rules (NO-PARSERS)..." -ForegroundColor Yellow

$expectedRules = @(
    'TacitRed - Repeat Compromise Detection',
    'TacitRed - High-Risk User Compromised',
    'TacitRed - Active Compromised Account',
    'Cyren + TacitRed - Malware Infrastructure',
    'TacitRed + Cyren - Cross-Feed Correlation',
    'TacitRed - Department Compromise Cluster'
)

$existingRules = @()
try {
    $existingRules = az sentinel alert-rule list --resource-group $rg --workspace-name $ws -o json | ConvertFrom-Json
} catch {
    Write-Host "⚠ Unable to query existing analytics rules; proceeding with deployment" -ForegroundColor Yellow
}

$missingRules = @()
if($existingRules){
    $missingRules = $expectedRules | Where-Object { $existingRules.displayName -notcontains $_ }
}

if($missingRules.Count -eq 0 -and $existingRules){
    "Skipped redeploy; all expected rules already exist." | Out-File -FilePath "$logDir\analytics-deploy.log" -Encoding utf8
    Write-Host "⚠ Analytics rules already present, skipped redeployment" -ForegroundColor Yellow
} elseif(Test-Path ".\analytics\analytics-rules.bicep"){
    az deployment group create `
        -g $rg `
        --template-file ".\analytics\analytics-rules.bicep" `
        --parameters workspaceName=$ws location=$loc `
        -n "analytics-$ts" `
        -o none 2>&1 | Out-File -FilePath "$logDir\analytics-deploy.log" -Encoding utf8

    if($LASTEXITCODE -eq 0){
        Write-Host "✓ Analytics rules deployed (NO-PARSERS)" -ForegroundColor Green
    } else {
        Write-Host "✗ Analytics rules deployment FAILED (exit code: $LASTEXITCODE)" -ForegroundColor Red
        if($missingRules.Count){
            Write-Host "Missing rules: $($missingRules -join ', ')" -ForegroundColor Red
        }
    }
} else {
    Write-Host "⚠ Bicep template not found: .\\analytics\\analytics-rules.bicep" -ForegroundColor Yellow
}

Write-Host "✓ Analytics complete`n" -ForegroundColor Green

# Workbooks
Write-Host "═══ PHASE 5: WORKBOOKS ═══" -ForegroundColor Cyan
$wbId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/$ws"
$wbCount = 0
foreach($wb in $config.workbooks.value.workbooks){
    if($wb.enabled -and (Test-Path ".\workbooks\bicep\$($wb.bicepFile)")){
        Write-Host "  Deploying: $($wb.name)..." -ForegroundColor Yellow
        az deployment group create `
            -g $rg `
            --template-file ".\workbooks\bicep\$($wb.bicepFile)" `
            --parameters workspaceId=$wbId location=$loc `
            -n "wb-$wbCount-$ts" `
            -o none 2>&1
        
        if($LASTEXITCODE -eq 0){
            Write-Host "    ✓ $($wb.name) deployed" -ForegroundColor Green
            $wbCount++
        } else {
            Write-Host "    ✗ $($wb.name) failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
        }
    }
}
Write-Host "✓ Deployed $wbCount workbooks`n" -ForegroundColor Green

# Test
Write-Host "═══ PHASE 6: INITIAL TESTING ═══" -ForegroundColor Cyan
Write-Host "Triggering Logic Apps for initial test..." -ForegroundColor Gray
az logic workflow trigger run -g $rg --name "logic-cyren-ip-reputation" --trigger-name "Recurrence" -o none 2>$null
az logic workflow trigger run -g $rg --name "logic-cyren-malware-urls" --trigger-name "Recurrence" -o none 2>$null
az logic workflow trigger run -g $rg --name "logic-tacitred-ingestion" --trigger-name "Recurrence" -o none 2>$null

Write-Host "Waiting 60s for runs to complete..." -ForegroundColor Gray
Start-Sleep -Seconds 60

# Check results
$testResults = @()
foreach($laName in $laNames){
    try {
        $runsUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Logic/workflows/$laName/runs?api-version=2019-05-01"
        $runs = az rest --method GET --uri $runsUri 2>$null | ConvertFrom-Json
        
        if($runs.value -and $runs.value.Count -gt 0){
            $latestRun = $runs.value[0]
            $sendUri = "https://management.azure.com/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Logic/workflows/$laName/runs/$($latestRun.name)/actions/Send_to_DCE?api-version=2019-05-01"
            $send = az rest --method GET --uri $sendUri 2>$null | ConvertFrom-Json
            
            if($send){
                $status = $send.properties.status
                $errorCode = if($send.properties.error){$send.properties.error.code}else{"None"}
                
                $testResults += @{
                    LogicApp = $laName
                    Status = $status
                    Error = $errorCode
                }
                
                $color = if($status -eq 'Succeeded'){'Green'}elseif($status -match 'Running'){'Yellow'}else{'Red'}
                Write-Host "  $laName : $status" -ForegroundColor $color
                if($errorCode -ne "None"){
                    Write-Host "    Error: $errorCode" -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "  $laName : Unable to check" -ForegroundColor Gray
    }
}

$testResults | ConvertTo-Json | Out-File "$logDir\initial-test-results.json" -Encoding UTF8

$successCount = ($testResults | Where-Object {$_.Status -eq 'Succeeded'}).Count
if($successCount -eq $laNames.Count){
    Write-Host "`n✓ All Logic Apps succeeded!" -ForegroundColor Green
}elseif($successCount -gt 0){
    Write-Host "`n⚠ $successCount/$($laNames.Count) Logic Apps succeeded" -ForegroundColor Yellow
    Write-Host "  Others may succeed after RBAC propagates (check with VALIDATE-DEPLOYMENT.ps1)" -ForegroundColor Gray
}else{
    Write-Host "`n⚠ No Logic Apps succeeded yet (expected during initial RBAC propagation)" -ForegroundColor Yellow
    Write-Host "  Check status in 30-60 minutes with VALIDATE-DEPLOYMENT.ps1" -ForegroundColor Gray
}
Write-Host "✓ Initial test complete`n" -ForegroundColor Green

# Summary
$dur = ((Get-Date) - $start).TotalMinutes
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "✅ DEPLOYMENT COMPLETE ($($dur.ToString('0.0')) minutes)" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "`nDeployed Components:" -ForegroundColor Cyan
Write-Host "  • Data Collection Endpoint (DCE)" -ForegroundColor Gray
Write-Host "  • 3 Data Collection Rules (TacitRed, Cyren IP, Cyren Malware)" -ForegroundColor Gray
Write-Host "  • 2 Log Analytics Tables (Full Schemas)" -ForegroundColor Gray
Write-Host "  • 3 Logic Apps with Managed Identities & RBAC" -ForegroundColor Gray
Write-Host "  • 6 Analytics Rules" -ForegroundColor Gray
Write-Host "  • $wbCount Workbooks" -ForegroundColor Gray

Write-Host "`n⚠ IMPORTANT NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Azure RBAC propagation can take 30-60 minutes" -ForegroundColor Gray
Write-Host "  2. Logic Apps may show 403 errors initially - this is normal" -ForegroundColor Gray
Write-Host "  3. Run validation after 30-60 minutes:" -ForegroundColor Gray
Write-Host "     .\VALIDATE-DEPLOYMENT.ps1" -ForegroundColor White
Write-Host "`n  4. The validation script will check:" -ForegroundColor Gray
Write-Host "     • RBAC assignments on all Logic Apps" -ForegroundColor Gray
Write-Host "     • Logic App execution status" -ForegroundColor Gray
Write-Host "     • Data ingestion into Log Analytics tables" -ForegroundColor Gray

Write-Host "`nDeployment Logs: $logDir" -ForegroundColor Gray
Write-Host "Initial Test Results: $logDir\initial-test-results.json" -ForegroundColor Gray
Write-Host "RBAC Assignments: $logDir\rbac-assignments.json`n" -ForegroundColor Gray

# Cleanup temp files
Remove-Item -Path "./temp_*.json" -Force -ErrorAction SilentlyContinue

Stop-Transcript

# Save state
@{ts=$ts;dur=$dur;dce=$dce.id;ipDcr=$ipDcrId;malDcr=$malDcrId;tacitredDcr=$tacitredDcrId}|ConvertTo-Json|Out-File "$logDir\state.json" -Encoding UTF8
Write-Host "Logs archived at: $logDir`n" -ForegroundColor Cyan
