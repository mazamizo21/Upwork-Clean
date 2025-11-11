// =============================================================================
// Parameters for Sentinel CCF Solution Deployment
// Multi-tenant ready with customer-specific configuration
// =============================================================================

// ---- Workspace Configuration ----
@description('Target Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Workspace location')
param workspaceLocation string = resourceGroup().location

// ---- Cyren Configuration ----
@description('Cyren API base URL')
param cyrenApiBaseUrl string

@secure()
@description('Cyren API token (JWT)')
param cyrenApiToken string

@description('Immutable ID of Cyren DCR (Direct)')
param cyrenDcrId string = ''

// ---- TacitRed Configuration ----
@description('TacitRed API base URL')
param tacitRedApiBaseUrl string

@description('TacitRed OAuth2 token endpoint')
param tacitRedTokenUrl string

@description('TacitRed Client Id')
param tacitRedClientId string

@secure()
@description('TacitRed Client Secret')
param tacitRedClientSecret string

@description('Immutable ID of TacitRed DCR (Direct)')
param tacitRedDcrId string = ''

// ---- Polling Configuration ----
@description('Polling window in minutes (default: 360 = 6 hours)')
@minValue(60)
@maxValue(1440)
param pollIntervalMinutes int = 360

// ---- IP Enrichment Configuration ----
@description('Enable IP enrichment')
param enableIpEnrichment bool = true

@description('IP enrichment provider')
@allowed(['DefenderTI', 'ip-api', 'ipinfo', 'MaxMind'])
param enrichmentProvider string = 'DefenderTI'

@description('Optional: custom base URL for chosen provider')
param providerApiBaseUrl string = ''

@secure()
@description('Optional: API key/token for chosen provider')
param providerApiKey string = ''

@description('Batch size per enrichment call')
@minValue(1)
@maxValue(500)
param providerBatchSize int = 100

@description('Max calls per minute to respect rate limits')
@minValue(1)
@maxValue(100)
param providerRateLimitPerMin int = 40

@description('Re-enrich entries older than N days')
@minValue(1)
@maxValue(90)
param reEnrichDays int = 7

// ---- ServiceNow Configuration (Optional) ----
@description('Enable ServiceNow integration (default: false, Sentinel-only)')
param enableServiceNow bool = false

@description('ServiceNow instance URL (e.g., https://contoso.service-now.com)')
param serviceNowInstanceUrl string = ''

@secure()
@description('ServiceNow credential (API user/password or OAuth token)')
param serviceNowCredential string = ''

@description('Create new ticket for every incident (New) or reuse by correlation key (Upsert)')
@allowed(['New', 'Upsert'])
param serviceNowTicketMode string = 'Upsert'

@description('Optional: correlation field to reuse the same ticket')
param serviceNowCorrelationField string = 'CampaignId'

// ---- Playbook Configuration ----
@description('Gate containment with approval (true) or run auto')
param requireApproval bool = true

@description('Enable identity containment playbook')
param enableIdentityContainment bool = true

@description('Enable mailbox hygiene playbook')
param enableMailboxHygiene bool = true

@description('Enable threat hunting playbook')
param enableThreatHunting bool = true

@description('Enable notification playbook')
param enableNotification bool = true

// ---- Analytics Configuration ----
@description('Enable baseline analytics rules')
param enableAnalytics bool = true

@description('Analytics rule severity threshold')
@allowed(['Informational', 'Low', 'Medium', 'High'])
param analyticsDefaultSeverity string = 'Medium'

// ---- RBAC Configuration ----
@description('Enable table-level RBAC for TacitRed findings (SOC-only access)')
param enableTableLevelRbac bool = true

@description('AAD Group Object ID for SOC team (for RBAC)')
param socTeamGroupObjectId string = ''

// ---- Defender TI Integration ----
@description('Continue pushing IOCs to Defender TI (recommended)')
param enableDefenderTiIntegration bool = true

// ---- Tagging ----
@description('Tags to apply to all resources')
param resourceTags object = {
  Solution: 'Sentinel-ThreatIntel'
  ManagedBy: 'Bicep'
  Environment: 'Production'
}

// ---- Output Parameters ----
output workspaceId string = workspaceResourceId
output cyrenConnectorName string = 'ccf-cyren'
output tacitRedConnectorName string = 'ccf-tacitred'
output deploymentTimestamp string = utcNow()
