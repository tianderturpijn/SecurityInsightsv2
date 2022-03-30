#### New-AzSentinelAlertRule

#### SYNOPSIS
Creates or updates the alert rule.

#### SYNTAX

+ FusionMLTI (Default)
```powershell
New-AzSentinelAlertRule -ResourceGroupName <String> -WorkspaceName <String> -AlertRuleTemplate <String>
 -Kind <AlertRuleKind> [-RuleId <String>] [-SubscriptionId <String>] [-Disabled] [-Enabled]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftSecurityIncidentCreation
```powershell
New-AzSentinelAlertRule -ResourceGroupName <String> -WorkspaceName <String> -Kind <AlertRuleKind>
 -ProductFilter <MicrosoftSecurityProductName> [-RuleId <String>] [-SubscriptionId <String>]
 [-AlertRuleTemplateName <String>] [-Description <String>] [-Disabled] [-DisplayNamesExcludeFilter <String>]
 [-DisplayNamesFilter <String>] [-Enabled] [-SeveritiesFilter <AlertSeverity[]>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ NRT
```powershell
New-AzSentinelAlertRule -ResourceGroupName <String> -WorkspaceName <String> -DisplayName <String>
 -Kind <AlertRuleKind> -Query <String> -Severity <AlertSeverity> [-RuleId <String>] [-SubscriptionId <String>]
 [-AlertDetailOverrideAlertDescriptionFormat <String>] [-AlertDetailOverrideAlertDisplayNameFormat <String>]
 [-AlertDetailOverrideAlertSeverityColumnName <String>] [-AlertDetailOverrideAlertTacticsColumnName <String>]
 [-AlertRuleTemplateName <String>] [-Description <String>] [-Disabled] [-Enabled]
 [-EntityMapping <EntityMapping>] [-GroupingConfigurationEnabled]
 [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled]
 [-Tactic <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Scheduled
```powershell
New-AzSentinelAlertRule -ResourceGroupName <String> -WorkspaceName <String> -DisplayName <String>
 -Kind <AlertRuleKind> -Query <String> -QueryFrequency <TimeSpan> -QueryPeriod <TimeSpan>
 -Severity <AlertSeverity> -TriggerOperator <TriggerOperator> -TriggerThreshold <Int32> [-RuleId <String>]
 [-SubscriptionId <String>] [-AlertDetailOverrideAlertDescriptionFormat <String>]
 [-AlertDetailOverrideAlertDisplayNameFormat <String>] [-AlertDetailOverrideAlertSeverityColumnName <String>]
 [-AlertDetailOverrideAlertTacticsColumnName <String>] [-AlertRuleTemplateName <String>]
 [-Description <String>] [-Disabled] [-Enabled] [-EntityMapping <EntityMapping>]
 [-EventGroupingSettingAggregationKind <EventGroupingAggregationKind>] [-GroupingConfigurationEnabled]
 [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled]
 [-Tactic <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create the Fusion Alert rule
```powershell
PS C:\> $AlertRuleTemplateName = "f71aba3d-28fb-450b-b192-4e76a83015c8"
PS C:\> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Kind Fusion -Enabled -AlertRuleTemplateName $AlertRuleTemplateName

```

This command creates an Alert Rule of the Fusion kind based on the template "Advanced Multistage Attack Detection"

+ Example 2: Create the ML Behavior Analytics Alert Rule
```powershell
PS C:\> $AlertRuleTemplateName = "fa118b98-de46-4e94-87f9-8e6d5060b60b"
PS C:\> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Kind MLBehaviorAnalytics -Enabled -AlertRuleTemplateName $AlertRuleTemplateName

```

This command creates an Alert Rule of the MLBehaviorAnalytics kind based on the template "Anomalous SSH Login Detection"

+ Example 2: Create the Threat Intelligence Alert Rule
```powershell
PS C:\> $AlertRuleTemplateName = "0dd422ee-e6af-4204-b219-f59ac172e4c6"
PS C:\> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Kind ThreatIntelligence -Enabled -AlertRuleTemplateName $AlertRuleTemplateName

```

This command creates an Alert Rule of the ThreatIntelligence kind based on the template "Microsoft Threat Intelligence Analytics"

+ Example 3: Create a Microsoft Security Incident Creation Alert Rule
```powershell
PS C:\> $AlertRuleTemplateName = "a2e0eb51-1f11-461a-999b-cd0ebe5c7a72"
PS C:\> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Kind MicrosoftSecurityIncidentCreation -Enabled -AlertRuleTemplateName $AlertRuleTemplateName -DisplayName "Create incidents based on Microsoft Defender for IoT" -ProductFilter "Azure Security Center for IoT"


```

This command creates an Alert Rule of the MicrosoftSecurityIncidentCreation kind based on the template for Create incidents based on Azure Security Center for IoT alerts.

+ Example 4: Create a Scheduled Alert Rule
```powershell
PS C:> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Kind Scheduled -Enabled -DisplayName "Powershell Exection Alert (Several Times per Hour)" -Severity Low -Query "SecurityEvent | where EventId == 4688" -QueryFrequency (New-TimeSpan -Hours 1) -QueryPeriod (New-TimeSpan -Hours 1) -TriggerThreshold 10

```

This command creates an Alert Rule of the Scheduled kind.
Please note that that query (parameter -Query) needs to be on a single line as as string.

+ Example 5: Create a Near Realtime Alert Rule
```powershell
PS C:> New-AzSentinelAlertRule -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Kind NRT -Enabled -DisplayName "Break glass account accessed" -Severity High -Query "let Break_Glass_Account = _GetWatchlist('break_glass_account')\n|project UPN;\nSigninLogs\n| where UserPrincipalName in (Break_Glass_Account)"

```

This command creates an Alert Rule of the NRT kind.
Please note that that query (parameter -Query) needs to be on a single line as as string.


#### Get-AzSentinelAlertRule

#### SYNOPSIS
Gets the alert rule.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelAlertRule -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Alert Rules
```powershell
PS C:\> Get-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

AlertDisplayName : (Preview) TI map IP entity to SigninLogs
FriendlyName     : (Preview) TI map IP entity to SigninLogs
Description      : Identifies a match in SigninLogs from any IP IOC from TI
Kind             : SecurityAlert
Name             : d1e4d1dd-8d16-1aed-59bd-a256266d7244
ProductName      : Azure Sentinel
Status           : New
ProviderAlertId  : d6c7a42b-c0da-41ef-9629-b3d2d407b181
Tactic           : {Impact}
```

This command lists all Alert Rules under a Microsoft Sentinel workspace.

+ Example 2: Get an Alert Rule
```powershell
PS C:\> Get-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -RuleId "d6c7a42b-c0da-41ef-9629-b3d2d407b181"

AlertDisplayName : (Preview) TI map IP entity to SigninLogs
FriendlyName     : (Preview) TI map IP entity to SigninLogs
Description      : Identifies a match in SigninLogs from any IP IOC from TI
Kind             : SecurityAlert
Name             : d1e4d1dd-8d16-1aed-59bd-a256266d7244
ProductName      : Azure Sentinel
Status           : New
ProviderAlertId  : d6c7a42b-c0da-41ef-9629-b3d2d407b181
Tactic           : {Impact}
```

This command gets an Alert Rule.

+ Example 3: Get an Alert Rule by object Id
```powershell
PS C:\> $rules = Get-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"
PS C:\> $rules[0] | Get-AzSentinelAlertRule

AlertDisplayName : (Preview) TI map IP entity to SigninLogs
FriendlyName     : (Preview) TI map IP entity to SigninLogs
Description      : Identifies a match in SigninLogs from any IP IOC from TI
Kind             : SecurityAlert
Name             : d1e4d1dd-8d16-1aed-59bd-a256266d7244
ProductName      : Azure Sentinel
Status           : New
ProviderAlertId  : d6c7a42b-c0da-41ef-9629-b3d2d407b181
Tactic           : {Impact}
```

This command gets an Alert Rule by object


#### Remove-AzSentinelAlertRule

#### SYNOPSIS
Delete the alert rule.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>] [-PassThru]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove an alert rule
```powershell
PS C:\>Remove-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -RuleId 4a21e485-75ae-48b3-a7b9-e6a92bcfe434

```

The command removes a Sentinel alert rule


#### Update-AzSentinelAlertRule

#### SYNOPSIS
Updates the alert rule.

#### SYNTAX

+ UpdateScheduled (Default)
```powershell
Update-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AlertDetailOverrideAlertDescriptionFormat <String>]
 [-AlertDetailOverrideAlertDisplayNameFormat <String>] [-AlertDetailOverrideAlertSeverityColumnName <String>]
 [-AlertDetailOverrideAlertTacticsColumnName <String>] [-AlertRuleTemplateName <String>]
 [-Description <String>] [-Disabled] [-DisplayName <String>] [-Enabled] [-EntityMapping <EntityMapping>]
 [-EventGroupingSettingAggregationKind <EventGroupingAggregationKind>] [-GroupingConfigurationEnabled]
 [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-Query <String>] [-QueryFrequency <TimeSpan>]
 [-QueryPeriod <TimeSpan>] [-Severity <AlertSeverity>] [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled]
 [-Tactic <AttackTactic>] [-TriggerOperator <TriggerOperator>] [-TriggerThreshold <Int32>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Scheduled] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateFusionMLTI
```powershell
Update-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AlertRuleTemplateName <String>] [-Disabled] [-Enabled]
 [-DefaultProfile <PSObject>] [-AsJob] [-FusionMLorTI] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateMicrosoftSecurityIncidentCreation
```powershell
Update-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AlertRuleTemplateName <String>] [-Description <String>] [-Disabled]
 [-DisplayNamesExcludeFilter <String>] [-DisplayNamesFilter <String>] [-Enabled]
 [-ProductFilter <MicrosoftSecurityProductName>] [-SeveritiesFilter <AlertSeverity[]>]
 [-DefaultProfile <PSObject>] [-AsJob] [-MicrosoftSecurityIncidentCreation] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateNRT
```powershell
Update-AzSentinelAlertRule -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AlertDetailOverrideAlertDescriptionFormat <String>]
 [-AlertDetailOverrideAlertDisplayNameFormat <String>] [-AlertDetailOverrideAlertSeverityColumnName <String>]
 [-AlertDetailOverrideAlertTacticsColumnName <String>] [-AlertRuleTemplateName <String>]
 [-Description <String>] [-Disabled] [-DisplayName <String>] [-Enabled] [-EntityMapping <EntityMapping>]
 [-GroupingConfigurationEnabled] [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-Query <String>] [-Severity <AlertSeverity>]
 [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled] [-Tactic <AttackTactic>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-NRT] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityFusionMLTI
```powershell
Update-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity> [-AlertRuleTemplateName <String>]
 [-Disabled] [-Enabled] [-DefaultProfile <PSObject>] [-AsJob] [-FusionMLorTI] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityMicrosoftSecurityIncidentCreation
```powershell
Update-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity> [-AlertRuleTemplateName <String>]
 [-Description <String>] [-Disabled] [-DisplayNamesExcludeFilter <String>] [-DisplayNamesFilter <String>]
 [-Enabled] [-ProductFilter <MicrosoftSecurityProductName>] [-SeveritiesFilter <AlertSeverity[]>]
 [-DefaultProfile <PSObject>] [-AsJob] [-MicrosoftSecurityIncidentCreation] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityNRT
```powershell
Update-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity>
 [-AlertDetailOverrideAlertDescriptionFormat <String>] [-AlertDetailOverrideAlertDisplayNameFormat <String>]
 [-AlertDetailOverrideAlertSeverityColumnName <String>] [-AlertDetailOverrideAlertTacticsColumnName <String>]
 [-AlertRuleTemplateName <String>] [-Description <String>] [-Disabled] [-DisplayName <String>] [-Enabled]
 [-EntityMapping <EntityMapping>] [-GroupingConfigurationEnabled]
 [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-Query <String>] [-Severity <AlertSeverity>]
 [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled] [-Tactic <AttackTactic>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-NRT] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityUpdateScheduled
```powershell
Update-AzSentinelAlertRule -InputObject <ISecurityInsightsIdentity>
 [-AlertDetailOverrideAlertDescriptionFormat <String>] [-AlertDetailOverrideAlertDisplayNameFormat <String>]
 [-AlertDetailOverrideAlertSeverityColumnName <String>] [-AlertDetailOverrideAlertTacticsColumnName <String>]
 [-AlertRuleTemplateName <String>] [-Description <String>] [-Disabled] [-DisplayName <String>] [-Enabled]
 [-EntityMapping <EntityMapping>] [-EventGroupingSettingAggregationKind <EventGroupingAggregationKind>]
 [-GroupingConfigurationEnabled] [-GroupingConfigurationGroupByAlertDetail <AlertDetail>]
 [-GroupingConfigurationGroupByCustomDetail <String[]>]
 [-GroupingConfigurationGroupByEntity <EntityMappingType>] [-GroupingConfigurationLookbackDuration <TimeSpan>]
 [-GroupingConfigurationMatchingMethod <String>] [-GroupingConfigurationReOpenClosedIncident]
 [-IncidentConfigurationCreateIncident] [-Query <String>] [-QueryFrequency <TimeSpan>]
 [-QueryPeriod <TimeSpan>] [-Severity <AlertSeverity>] [-SuppressionDuration <TimeSpan>] [-SuppressionEnabled]
 [-Tactic <AttackTactic>] [-TriggerOperator <TriggerOperator>] [-TriggerThreshold <Int32>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Scheduled] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update an scheduled alert rule
```powershell
PS C:\>Update-AzSentinelAlertRule -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -ruleId "4a21e485-75ae-48b3-a7b9-e6a92bcfe434" -Query "SecurityAlert | take 2"

```

This command updates a scheduled alert rule


#### New-AzSentinelAlertRuleAction

#### SYNOPSIS
Creates or updates the action of alert rule.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelAlertRuleAction -Id <String> -ResourceGroupName <String> -RuleId <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-LogicAppResourceId <String>] [-TriggerUri <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelAlertRuleAction -Id <String> -ResourceGroupName <String> -RuleId <String>
 -WorkspaceName <String> -Action <IActionRequest> [-SubscriptionId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Add a Logic App Playbook as an action to an existing analytics rule
```powershell
PS C:\> $LogicAppResourceId = Get-AzLogicApp -ResourceGroupName "myLogicAppResourceGroupName" -Name "myLogicAppPlaybookName"
$LogicAppTriggerUri = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName "myLogicAppResourceGroupName" -Name $LogicAppResourceId.Name -TriggerName "When_a_response_to_an_Azure_Sentinel_alert_is_triggered"
New-AzSentinelAlertRuleAction -ResourceGroupName "mySentinelResourceGroupName" -workspaceName "myWorkspaceName" -RuleId "48bbf86d-540b-4a7b-9fee-2bd7d810dbed" -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value) -Id ((New-Guid).Guid)

```

This command adds an existing Logic App Playbook to an existing analytics rule


#### Get-AzSentinelAlertRuleAction

#### SYNOPSIS
Gets the action of alert rule.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelAlertRuleAction -ResourceGroupName <String> -RuleId <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelAlertRuleAction -Id <String> -ResourceGroupName <String> -RuleId <String>
 -WorkspaceName <String> [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelAlertRuleAction -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Actions for a given Alert Rule
```powershell
PS C:\> Get-AzSentinelAlertRuleAction -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -RuleId "myRuleId"

LogicAppResourceId : /subscriptions/174b1a81-c53c-4092-8d4a-7210f6a44a0c/resourceGroups/myResourceGroup/providers/Microsoft.Logic/workflows/A-Demo-1
Name               : f32239c5-cb9c-48da-a3f6-bd5bd3d924a4
WorkflowId         : 3c73d72560fa4cb6a72a0f10d3a80940

LogicAppResourceId : /subscriptions/274b1a41-c53c-4092-8d4a-7210f6a44a0c/resourceGroups/myResourceGroup/providers/Microsoft.Logic/workflows/EmptyPlaybook
Name               : cf815c77-bc65-4c02-946f-d81e15e9a100
WorkflowId         : 1ac8ccb8bd134253b4baf0c75fe3ecc6
```

This command lists all Actions for a given Alert Rule.


#### Remove-AzSentinelAlertRuleAction

#### SYNOPSIS
Delete the action of alert rule.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelAlertRuleAction -Id <String> -ResourceGroupName <String> -RuleId <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelAlertRuleAction -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Update-AzSentinelAlertRuleAction

#### SYNOPSIS
Creates or updates the action of alert rule.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelAlertRuleAction -Id <String> -ResourceGroupName <String> -RuleId <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-LogicAppResourceId <String>] [-TriggerUri <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelAlertRuleAction -InputObject <ISecurityInsightsIdentity> [-LogicAppResourceId <String>]
 [-TriggerUri <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelAlertRuleTemplate

#### SYNOPSIS
Gets the alert rule template.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelAlertRuleTemplate -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelAlertRuleTemplate -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelAlertRuleTemplate -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Alert Rule Templates
```powershell
PS C:\> Get-AzSentinelAlertRuleTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

DisplayName        : TI map IP entity to GitHub_CL
Description        : Identifies a match in GitHub_CL table from any IP IOC from TI
CreatedDateUtc     : 8/27/2019 12:00:00 AM
LastUpdatedDateUtc : 10/19/2021 12:00:00 AM
Kind               : Scheduled
Severity           : Medium
Name               : aac495a9-feb1-446d-b08e-a1164a539452

DisplayName        : Accessed files shared by temporary external user
Description        : This detection identifies an external user is added to a Team or Teams chat
                     and shares a files which is accessed by many users (>10) and the users is removed within short period of time. This might be
                     an indicator of suspicious activity.
CreatedDateUtc     : 8/18/2020 12:00:00 AM
LastUpdatedDateUtc : 1/3/2022 12:00:00 AM
Kind               : Scheduled
Severity           : Low
Name               : bff058b2-500e-4ae5-bb49-a5b1423cbd5b
```

This command lists all Alert Rule Templates under a Microsoft Sentinel workspace.

+ Example 2: Get an Alert Rule Template
```powershell
PS C:\> Get-AzSentinelAlertRuleTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "myRuaac495a9-feb1-446d-b08e-a1164a539452leTemplateId"

DisplayName        : TI map IP entity to GitHub_CL
Description        : Identifies a match in GitHub_CL table from any IP IOC from TI
CreatedDateUtc     : 8/27/2019 12:00:00 AM
LastUpdatedDateUtc : 10/19/2021 12:00:00 AM
Kind               : Scheduled
Severity           : Medium
Name               : aac495a9-feb1-446d-b08e-a1164a539452
```

This command gets an Alert Rule Template.


#### New-AzSentinelAutomationRule

#### SYNOPSIS
Creates or updates the automation rule.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelAutomationRule -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Action <IAutomationRuleAction[]>] [-DisplayName <String>] [-Order <Int32>]
 [-TriggeringLogicCondition <IAutomationRuleCondition[]>] [-TriggeringLogicExpirationTimeUtc <DateTime>]
 [-TriggeringLogicIsEnabled] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelAutomationRule -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 -AutomationRule <IAutomationRule> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelAutomationRule

#### SYNOPSIS
Gets the automation rule.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelAutomationRule -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelAutomationRule -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelAutomationRule -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Automation Rules
```powershell
PS C:\> Get-AzSentinelAutomationRule -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

DisplayName                 : VIP automation rule
CreatedByEmail              : luke@contoso.com
CreatedByUserPrincipalName  : luke@contoso.com
TriggeringLogicIsEnabled    : True
TriggeringLogicTriggersOn   : Incidents
TriggeringLogicTriggersWhen : Created
Name                       	: 2f32af32-ad13-4fbb-9fbc-e19e0e7ff767

```

This command lists all Automation Rules under a Microsoft Sentinel workspace.

+ Example 2: Get an Automation Rule
```powershell
PS C:\> Get-AzSentinelAutomationRule -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "2f32af32-ad13-4fbb-9fbc-e19e0e7ff767"

DisplayName                 : VIP automation rule
CreatedByEmail              : luke@contoso.com
CreatedByUserPrincipalName  : luke@contoso.com
TriggeringLogicIsEnabled    : True
TriggeringLogicTriggersOn   : Incidents
TriggeringLogicTriggersWhen : Created
Name                       	: 2f32af32-ad13-4fbb-9fbc-e19e0e7ff767
```

This command gets an Automation Rule.


#### Remove-AzSentinelAutomationRule

#### SYNOPSIS
Delete the automation rule.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelAutomationRule -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelAutomationRule -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Update-AzSentinelAutomationRule

#### SYNOPSIS
Creates or updates the automation rule.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelAutomationRule -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Action <IAutomationRuleAction[]>] [-DisplayName <String>] [-Order <Int32>]
 [-TriggeringLogicCondition <IAutomationRuleCondition[]>] [-TriggeringLogicExpirationTimeUtc <DateTime>]
 [-TriggeringLogicIsEnabled] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelAutomationRule -InputObject <ISecurityInsightsIdentity> [-Action <IAutomationRuleAction[]>]
 [-DisplayName <String>] [-Order <Int32>] [-TriggeringLogicCondition <IAutomationRuleCondition[]>]
 [-TriggeringLogicExpirationTimeUtc <DateTime>] [-TriggeringLogicIsEnabled] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### New-AzSentinelBookmark

#### SYNOPSIS
Creates or updates the bookmark.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelBookmark -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Created <DateTime>] [-CreatedByObjectId <String>] [-DisplayName <String>]
 [-EventTime <DateTime>] [-IncidentInfoIncidentId <String>] [-IncidentInfoRelationName <String>]
 [-IncidentInfoSeverity <IncidentSeverity>] [-IncidentInfoTitle <String>] [-Label <String[]>] [-Note <String>]
 [-Query <String>] [-QueryEndTime <DateTime>] [-QueryResult <String>] [-QueryStartTime <DateTime>]
 [-Updated <DateTime>] [-UpdatedByObjectId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelBookmark -Id <String> -ResourceGroupName <String> -WorkspaceName <String> -Bookmark <IBookmark>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create a Bookmark
```powershell
PS C:\> $queryStartTime = (get-date).AddDays(-1).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $queryEndTime = (get-date).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> New-AzSentinelBookmark -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id ((New-Guid).Guid) -DisplayName "Incident Evidence" -Query "SecurityEvent | take 1" -QueryStartTime $queryStartTime -QueryEndTime $queryEndTime -EventTime $queryEndTime

DisplayName    : Incident Evidence
CreatedByName  : John Contoso
CreatedByEmail : john@contoso.com
Name           : 6a8d6ea6-04d5-49d7-8169-ffca8b0ced59
Note           : my notes
```

This command creates a Bookmark.


#### Get-AzSentinelBookmark

#### SYNOPSIS
Gets a bookmark.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelBookmark -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelBookmark -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelBookmark -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Bookmarks
```powershell
PS C:\> Get-AzSentinelBookmark -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

DisplayName    	: SecurityAlert - 28b401e1e0c9
CreatedByEmail	: john@contoso.com
CreatedByName  	: John Contoso
Label          	: {}
Note           	: This needs further investigation
Name           	: 515fc035-2ed8-4fa1-ad7d-28b401e1e0c9

```

This command lists all Bookmarks under a Microsoft Sentinel workspace.

+ Example 2: Get a Bookmark
```powershell
PS C:\> Get-AzSentinelBookmark -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "515fc035-2ed8-4fa1-ad7d-28b401e1e0c9"

DisplayName    	: SecurityAlert - 28b401e1e0c9
CreatedByEmail	: john@contoso.com
CreatedByName  	: John Contoso
Label          	: {}
Note           	: This needs further investigation
Name           	: 515fc035-2ed8-4fa1-ad7d-28b401e1e0c9
```

This command gets a Bookmark.


#### Remove-AzSentinelBookmark

#### SYNOPSIS
Delete the bookmark.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelBookmark -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelBookmark -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>] [-PassThru]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove a Sentinel Bookmark
```powershell
PS C:\>Remove-AzSentinelBookmark -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id <bookMarkId> 

```

This command removes a bookmark


#### Update-AzSentinelBookmark

#### SYNOPSIS
Creates or updates the bookmark.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelBookmark -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Created <DateTime>] [-CreatedByObjectId <String>] [-DisplayName <String>]
 [-EventTime <DateTime>] [-IncidentInfoIncidentId <String>] [-IncidentInfoRelationName <String>]
 [-IncidentInfoSeverity <IncidentSeverity>] [-IncidentInfoTitle <String>] [-Label <String[]>] [-Note <String>]
 [-Query <String>] [-QueryEndTime <DateTime>] [-QueryResult <String>] [-QueryStartTime <DateTime>]
 [-Updated <DateTime>] [-UpdatedByObjectId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelBookmark -InputObject <ISecurityInsightsIdentity> [-Created <DateTime>]
 [-CreatedByObjectId <String>] [-DisplayName <String>] [-EventTime <DateTime>]
 [-IncidentInfoIncidentId <String>] [-IncidentInfoRelationName <String>]
 [-IncidentInfoSeverity <IncidentSeverity>] [-IncidentInfoTitle <String>] [-Label <String[]>] [-Note <String>]
 [-Query <String>] [-QueryEndTime <DateTime>] [-QueryResult <String>] [-QueryStartTime <DateTime>]
 [-Updated <DateTime>] [-UpdatedByObjectId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update Sentinel Bookmark
```powershell
PS C:\> $queryStartTime = (get-date).AddDays(-1).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $queryEndTime = (get-date).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> Update-AzSentinelBookmark -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id ((New-Guid).Guid) -DisplayName "Incident Evidence" -Query "SecurityEvent | take 1" -QueryStartTime $queryStartTime -QueryEndTime $queryEndTime -EventTime $queryEndTime

This command updates a bookmark
```




#### New-AzSentinelBookmarkRelation

#### SYNOPSIS
Creates the bookmark relation.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelBookmarkRelation -BookmarkId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-RelatedResourceId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelBookmarkRelation -BookmarkId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> -Relation <IRelation> [-SubscriptionId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create a Bookmark Relation
```powershell
PS C:\> $incident = Get-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id "myIncidentId"
PS C:\> $bookmarkRelation = New-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -BookmarkId "myBookmarkId" -RelationName ((New-Guid).Guid) -RelatedResourceId ($incident.Id)
```

This command creates a Bookmark Relation connecting the Incident to the Bookmark.


#### Get-AzSentinelBookmarkRelation

#### SYNOPSIS
Gets a bookmark relation.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelBookmarkRelation -BookmarkId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelBookmarkRelation -BookmarkId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelBookmarkRelation -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Bookmark Relations for a given Bookmark 
```powershell
PS C:\> Get-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -BookmarkId "myBookmarkId"

Name                : 83846045-d8dc-4d6b-abbe-7588219c474e
RelatedResourceName : 7cc984fe-61a2-43c2-a1a4-3583c8a89da2
RelatedResourceType : Microsoft.SecurityInsights/Incidents
```

This command lists all Bookmark Relations for a given Bookmark.

+ Example 2: Get a Bookmark Relation
```powershell
PS C:\> Get-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -BookmarkId "myBookmarkId"

Name                : 83846045-d8dc-4d6b-abbe-7588219c474e
RelatedResourceName : 7cc984fe-61a2-43c2-a1a4-3583c8a89da2
RelatedResourceType : Microsoft.SecurityInsights/Incidents
```

This command gets a Bookmark Relation.

+ Example 3: Get a Bookmark Relation by object Id
```powershell
PS C:\> $Bookmarkrelations = Get-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -BookmarkId "myBookmarkId"
PS C:\> $Bookmarkrelations[0] | Get-AzSentinelBookmarkRelation

Name                : 83846045-d8dc-4d6b-abbe-7588219c474e
RelatedResourceName : 7cc984fe-61a2-43c2-a1a4-3583c8a89da2
RelatedResourceType : Microsoft.SecurityInsights/Incidents
```

This command gets a Bookmark by object


#### Remove-AzSentinelBookmarkRelation

#### SYNOPSIS
Delete the bookmark relation.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelBookmarkRelation -BookmarkId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelBookmarkRelation -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove a bookmark relation
```powershell
PS C:\> Remove-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -BookmarkId 83846045-d8dc-4d6b-abbe-7588219c474e -RelationName 7cc984fe-61a2-43c2-a1a4-3583c8a89da2

```

This command removes a bookmarkrelation


#### Update-AzSentinelBookmarkRelation

#### SYNOPSIS
Creates the bookmark relation.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelBookmarkRelation -BookmarkId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-RelatedResourceId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelBookmarkRelation -InputObject <ISecurityInsightsIdentity> [-RelatedResourceId <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update a Bookmark relation
```powershell
PS C:\>Update-AzSentinelBookmarkRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -BookmarkId 6a8d6ea6-04d5-49d7-8169-ffca8b0ced59 -RelationName f185b6f8-1a0d-43eb-97de-67720839ac67 -RelatedResourceId f185b6f8-1a0d-43eb-97de-67720839ac67

```

This command updates a bookmark relation


#### New-AzSentinelDataConnector

#### SYNOPSIS
Creates or updates the data connector.

#### SYNTAX

+ AzureActiveDirectory (Default)
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AmazonWebServicesCloudTrail
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -AWSRoleArn <String>
 -Kind <DataConnectorKind> [-DataConnectorId <String>] [-SubscriptionId <String>] [-Logs <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AmazonWebServicesS3
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -AWSRoleArn <String>
 -DetinationTable <String> -Kind <DataConnectorKind> -Logs <String> -SQSURLs <String[]>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AzureAdvancedThreatProtection
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AzureSecurityCenter
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -ASCSubscriptionId <String>
 -Kind <DataConnectorKind> [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Dynamics365
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-CommonDataServiceActivities <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ GenericUI
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String>
 -AvailabilityIsPreview <Boolean> -ConnectorUiConfigConnectivityCriterion <ConnectivityCriteria[]>
 -ConnectorUiConfigDataType <LastDataReceivedDataType[]> -ConnectorUiConfigDescriptionMarkdown <String>
 -ConnectorUiConfigGraphQueriesTableName <String> -ConnectorUiConfigGraphQuery <GraphQueries[]>
 -ConnectorUiConfigInstructionStep <InstructionSteps[]> -ConnectorUiConfigPublisher <String>
 -ConnectorUiConfigSampleQuery <SampleQueries[]> -ConnectorUiConfigTitle <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-AvailabilityStatus <Int32>]
 [-ConnectorUiConfigCustomImage <String>] [-PermissionCustom <PermissionsCustomsItem[]>]
 [-PermissionResourceProvider <PermissionsResourceProviderItem[]>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftCloudAppSecurity
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-DiscoveryLogs <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ MicrosoftDefenderAdvancedThreatProtection
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftThreatIntelligence
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-BingSafetyPhishingURL <String>]
 [-BingSafetyPhishingUrlLookbackPeriod <String>] [-MicrosoftEmergingThreatFeed <String>]
 [-MicrosoftEmergingThreatFeedLookbackPeriod <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftThreatProtection
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Incidents <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Office365
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Exchange <String>] [-SharePoint <String>]
 [-Teams <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ OfficeATP
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ OfficeIRM
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ ThreatIntelligence
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -Kind <DataConnectorKind>
 [-DataConnectorId <String>] [-SubscriptionId <String>] [-Indicators <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ ThreatIntelligenceTaxii
```powershell
New-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> -APIRootURL <String>
 -CollectionId <String> -FriendlyName <String> -Kind <DataConnectorKind> -PollingFrequency <PollingFrequency>
 -WorkspaceId <String> [-DataConnectorId <String>] [-SubscriptionId <String>] [-Password <String>]
 [-TaxiiLookbackPeriod <String>] [-TenantId <String>] [-UserName <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelDataConnector

#### SYNOPSIS
Gets a data connector.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelDataConnector -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelDataConnector -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Data Connectors
```powershell
PS C:\> Get-AzSentinelDataConnector -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Kind : AzureActiveDirectory
Name : 8207e1f9-a793-4869-afb1-5ad4540d66d1

Kind : AzureAdvancedThreatProtection
Name : 1d75aada-a558-4461-986b-c6822182e81d

Kind : Office365
Name : 6323c716-83ae-4cfd-bf93-58235c8beb23

```

This command lists all DataConnectors under a Microsoft Sentinel workspace.

+ Example 2: Get a specific Data Connector
```powershell
PS C:\> Get-AzSentinelDataConnector -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" | Where-Object {$_.kind -eq "Office365"}

Kind                         : Office365
Name                         : 6323c716-83ae-4cfd-bf93-58235c8beb23
SharePointState              : enabled
```

This command gets a specific DataConnector based on kind


#### Remove-AzSentinelDataConnector

#### SYNOPSIS
Delete the data connector.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelDataConnector -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Removes Sentinel Data Connector
```powershell
PS C:\>Remove-AzSentinelDataConnector -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id 661b961f-53d8-4bd1-be97-24e808fd04f5

```

This command removes a data connector.


#### Update-AzSentinelDataConnector

#### SYNOPSIS
Updates the data connector.

#### SYNTAX

+ UpdateAzureActiveDirectory (Default)
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateAmazonWebServicesCloudTrail
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AWSRoleArn <String>] [-Logs <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateAmazonWebServicesS3
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-AWSRoleArn <String>] [-DetinationTable <String>] [-Logs <String>]
 [-SQSURLs <String[]>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateAzureAdvancedThreatProtection
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateAzureSecurityCenter
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-ASCSubscriptionId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateDynamics365
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-CommonDataServiceActivities <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateGenericUI
```powershell
Update-AzSentinelDataConnector [-AvailabilityIsPreview <Boolean>] [-AvailabilityStatus <Int32>]
 [-ConnectorUiConfigConnectivityCriterion <ConnectivityCriteria[]>] [-ConnectorUiConfigCustomImage <String>]
 [-ConnectorUiConfigDataType <LastDataReceivedDataType[]>] [-ConnectorUiConfigDescriptionMarkdown <String>]
 [-ConnectorUiConfigGraphQueriesTableName <String>] [-ConnectorUiConfigGraphQuery <GraphQueries[]>]
 [-ConnectorUiConfigInstructionStep <InstructionSteps[]>] [-ConnectorUiConfigPublisher <String>]
 [-ConnectorUiConfigSampleQuery <SampleQueries[]>] [-ConnectorUiConfigTitle <String>]
 [-PermissionCustom <PermissionsCustomsItem[]>]
 [-PermissionResourceProvider <PermissionsResourceProviderItem[]>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateMicrosoftCloudAppSecurity
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-DiscoveryLogs <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateMicrosoftDefenderAdvancedThreatProtection
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateMicrosoftThreatIntelligence
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-BingSafetyPhishingUrlLookbackPeriod <String>] [-BingSafetyPhishinURL <String>]
 [-MicrosoftEmergingThreatFeed <String>] [-MicrosoftEmergingThreatFeedLookbackPeriod <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateMicrosoftThreatProtection
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Incidents <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateOffice365
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Exchange <String>] [-SharePoint <String>] [-Teams <String>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateOfficeATP
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateOfficeIRM
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Alerts <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateThreatIntelligence
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Indicators <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateThreatIntelligenceTaxii
```powershell
Update-AzSentinelDataConnector -DataConnectorId <String> -ResourceGroupName <String> -WorkspaceName <String>
 -APIRootURL <String> [-SubscriptionId <String>] [-CollectionId <String>] [-FriendlyName <String>]
 [-Password <String>] [-PollingFrequency <PollingFrequency>] [-TaxiiLookbackPeriod <String>]
 [-TenantId <String>] [-UserName <String>] [-WorkspaceId <String>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityAmazonWebServicesCloudTrail
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-AWSRoleArn <String>]
 [-Logs <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityAmazonWebServicesS3
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-AWSRoleArn <String>]
 [-DetinationTable <String>] [-Logs <String>] [-SQSURLs <String[]>] [-TenantId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityAzureActiveDirectory
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityAzureAdvancedThreatProtection
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityAzureSecurityCenter
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-ASCSubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityDynamics365
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity>
 [-CommonDataServiceActivities <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityGenericUI
```powershell
Update-AzSentinelDataConnector [-AvailabilityIsPreview <Boolean>] [-AvailabilityStatus <Int32>]
 [-ConnectorUiConfigConnectivityCriterion <ConnectivityCriteria[]>] [-ConnectorUiConfigCustomImage <String>]
 [-ConnectorUiConfigDataType <LastDataReceivedDataType[]>] [-ConnectorUiConfigDescriptionMarkdown <String>]
 [-ConnectorUiConfigGraphQueriesTableName <String>] [-ConnectorUiConfigGraphQuery <GraphQueries[]>]
 [-ConnectorUiConfigInstructionStep <InstructionSteps[]>] [-ConnectorUiConfigPublisher <String>]
 [-ConnectorUiConfigSampleQuery <SampleQueries[]>] [-ConnectorUiConfigTitle <String>]
 [-PermissionCustom <PermissionsCustomsItem[]>]
 [-PermissionResourceProvider <PermissionsResourceProviderItem[]>] [-DefaultProfile <PSObject>] [-AsJob]
 [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityMicrosoftCloudAppSecurity
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-DiscoveryLogs <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityMicrosoftDefenderAdvancedThreatProtection
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityMicrosoftThreatIntelligence
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity>
 [-BingSafetyPhishingUrlLookbackPeriod <String>] [-BingSafetyPhishinURL <String>]
 [-MicrosoftEmergingThreatFeed <String>] [-MicrosoftEmergingThreatFeedLookbackPeriod <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityMicrosoftThreatProtection
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Incidents <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityOffice365
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Exchange <String>]
 [-SharePoint <String>] [-Teams <String>] [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityOfficeATP
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityOfficeIRM
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Alerts <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityThreatIntelligence
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-Indicators <String>]
 [-TenantId <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ UpdateViaIdentityThreatIntelligenceTaxii
```powershell
Update-AzSentinelDataConnector -InputObject <ISecurityInsightsIdentity> [-CollectionId <String>]
 [-FriendlyName <String>] [-Password <String>] [-PollingFrequency <PollingFrequency>]
 [-TaxiiLookbackPeriod <String>] [-TenantId <String>] [-UserName <String>] [-WorkspaceId <String>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update a Sentinel data connector
```powershell
PS C:\>Update-AzSentinelDataConnector -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -DataConnectorId  3bd6c555-1412-4103-9b9d-2b0b40cda6b6 -SharePoint "Enabled"

```

This command updates a Sentinel data connector


#### Invoke-AzSentinelDataConnectorsCheckRequirement

#### SYNOPSIS
Get requirements state for a data connector type.

#### SYNTAX

+ AzureActiveDirectory (Default)
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AzureAdvancedThreatProtection
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ AzureSecurityCenter
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -ASCSubscriptionId <String> -Kind <DataConnectorKind> [-SubscriptionId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Dynamics365
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftCloudAppSecurity
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftDefenderAdvancedThreatProtection
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftThreatIntelligence
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ MicrosoftThreatProtection
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ OfficeATP
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ OfficeIRM
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ ThreatIntelligence
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ ThreatIntelligenceTaxii
```powershell
Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName <String> -WorkspaceName <String>
 -Kind <DataConnectorKind> [-SubscriptionId <String>] [-TenantId <String>] [-DefaultProfile <PSObject>]
 [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Check requirements for a Data Connector
```powershell
PS C:\> Invoke-AzSentinelDataConnectorsCheckRequirement -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Kind OfficeATP -TenantId (Get-AzContext).Tenant.Id

AuthorizationState : Valid
LicenseState       : Valid
```

This example command checks the Data Connector Requirements for the Office 365 data connector.

Other -Kind values are:
AzureSecurityCenter
AzureActiveDirectory
AzureAdvancedThreatProtection
Dynamics365
MicrosoftCloudAppSecurity
MicrosoftDefenderAdvancedThreatProtection
MicrosoftThreatIntelligence
MicrosoftThreatProtection
OfficeATP
OfficeIRM
ThreatIntelligence
ThreatIntelligenceTaxii


#### Get-AzSentinelEnrichment

#### SYNOPSIS
Get geodata for a single IP address

#### SYNTAX

+ Get (Default)
```powershell
Get-AzSentinelEnrichment -ResourceGroupName <String> -IPAddress <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get1
```powershell
Get-AzSentinelEnrichment -ResourceGroupName <String> -Domain <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelEnrichment -InputObject <ISecurityInsightsIdentity> -IPAddress <String>
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity1
```powershell
Get-AzSentinelEnrichment -InputObject <ISecurityInsightsIdentity> -Domain <String>
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Get a Domain Enrichment
```powershell
PS C:\> Get-AzSentinelEnrichment -ResourceGroupName "myResourceGroupName" -Domain "microsoft.com

Created : 5/2/1991 12:00:00 AM
Domain  : microsoft.com
Expire  : 5/3/2022 12:00:00 AM
Server  : whois.markmonitor.com
Updated : 3/12/2021 12:00:00 AM
```

This command gets an enrichment for a domain.

+ Example 2: Get a IP Enrichment
```powershell
PS C:\> Get-AzSentinelEnrichment -ResourceGroupName "myResourceGroupName" IPAddress "1.1.1.1"

Asn              : 13335
Carrier          : cloudflare
City             : ringwood
CityCf           : 90
Continent        : oceania
Country          : australia
CountryCf        : 99
IPAddr           : 1.1.1.1
IPRoutingType    : fixed
Latitude         : -37.8143
Longitude        : 145.2274
Organization     : apnic and cloudflare dns resolver project
OrganizationType : Internet Hosting Services
Region           :
State            : victoria
StateCf          : 95
StateCode        :

```

This command an enrichment for an IP Address.


#### Get-AzSentinelEntity

#### SYNOPSIS
Gets an entity.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelEntity -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelEntity -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelEntity -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Entities
```powershell
PS C:\> Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

FriendlyName 	: WIN2019
Kind         	: Host
Name         	: 8d036a2d-f37d-e936-6cca-4e172687cb79

FriendlyName : 186.120.101.12
Kind         : Ip
Name         : bb590b07-5ef5-bf85-1c3e-2a04e1e137d2
```

This command lists all Entities under a Microsoft Sentinel workspace.

+ Example 2: Get an Entity
```powershell
PS C:\> Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "8d036a2d-f37d-e936-6cca-4e172687cb79"

FriendlyName 	: WIN2019
Kind         	: Host
Name         	: 8d036a2d-f37d-e936-6cca-4e172687cb79
```

This command gets an Entity.

+ Example 3: Get a Entity by object Id
```powershell
PS C:\> $Entitys = Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"
PS C:\> $Entitys[0] | Get-AzSentinelEntity

FriendlyName 	: WIN2019
Kind         	: Host
Name         	: 8d036a2d-f37d-e936-6cca-4e172687cb79
```

This command gets an Entity by object

+ Example 4: Get a Entity by kind
```powershell
PS C:\> Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" | Where-Object {$_.Kind -eq "CloudApplication"} 

FriendlyName : Office 365
Kind         : CloudApplication
Name         : 8fceb9c4-abe7-7174-aabf-f1dde96a945e
```

This command gets an Entity by kind


#### Get-AzSentinelEntityActivity

#### SYNOPSIS
Get Insights and Activities for an entity.

#### SYNTAX

```powershell
Get-AzSentinelEntityActivity -EntityId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Get Insights and Activities for an Entity
```powershell
PS C:\> Get-AzSentinelEntityAcivity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

FriendlyName : WIN2019
Kind         : Host
Name         : 8d036a2d-f37d-e936-6cca-4e172687cb79

FriendlyName : HackTool:Win32/Mimikatz.gen!H
Kind         : Malware
Name         : 876fda24-fe06-62b7-7dca-bced167a0ca3

FriendlyName : 52.166.111.66
Kind         : Ip
Name         : 4ebb68f3-a435-fac0-d3b6-94712d246f0a
```

This command gets insights and activities for an Entity.

+ Example 2: Get Insights and Activities for an Entity by Id
```powershell
PS C:\> $Entity = Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "4ebb68f3-a435-fac0-d3b6-94712d246f0a"
PS C:\> $Entity | Get-AzSentinelEntityActivity

```

This command gets insights and activies for an Entity by object


#### Get-AzSentinelEntityInsight

#### SYNOPSIS
Execute Insights for an entity.

#### SYNTAX

```powershell
Get-AzSentinelEntityInsight -EntityId <String> -ResourceGroupName <String> -WorkspaceName <String>
 -EndTime <DateTime> -StartTime <DateTime> [-SubscriptionId <String[]>] [-AddDefaultExtendedTimeRange]
 [-InsightQueryId <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Get Insights for an Entity for a given time range
```powershell
PS C:\> $startTime = (get-date).AddDays(-7).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $endTime = (get-date).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> Get-AzSentinelEntityInsight -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "myEntityId" -EndTime $endTime -StartTime $startTime

QueryId                    : 4191a4d7-e72b-4564-b2fb-25580630384b
QueryTimeIntervalEndTime   : 12/21/2021 10:00:00 AM
QueryTimeIntervalStartTime : 12/14/2021 10:00:00 AM
TableQueryResultColumn     : {Activity, expectedCount, actualCount, anomalyScore…}
TableQueryResultRow        : {4663 - An attempt was made to access an object. 0 3901 713.91 1 0}
```

This command gets insights for an Entity for a given time range.

+ Example 2: Get Insights for an Entity by entity Id for a given time range
```powershell
PS C:\> $startTime = (get-date).AddDays(-7).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $endTime = (get-date).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $Entity = Get-AzSentinelEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "8d036a2d-f37d-e936-6cca-4e172687cb79"
PS C:\> $Entity | Get-AzSentinelEntityInsight -EndTime $endTime -StartTime $startTime

QueryId                    : 4191a4d7-e72b-4564-b2fb-25580630384b
QueryTimeIntervalEndTime   : 12/21/2021 10:00:00 AM
QueryTimeIntervalStartTime : 12/14/2021 10:00:00 AM
TableQueryResultColumn     : {Activity, expectedCount, actualCount, anomalyScore…}
TableQueryResultRow        : {4663 - An attempt was made to access an object. 0 3901 713.91 1 0}
```

This command gets insights for an Entity by object for a given time range.


#### New-AzSentinelEntityQuery

#### SYNOPSIS
Creates or updates the entity query.

#### SYNTAX

```powershell
New-AzSentinelEntityQuery -ResourceGroupName <String> -WorkspaceName <String> -Content <String>
 -Description <String> -InputEntityType <EntityType> -Kind <Object> -QueryDefinitionQuery <String>
 -Title <String> [-EntityQueryId <String>] [-SubscriptionId <String>]
 [-EntitiesFilter <ActivityEntityQueriesPropertiesEntitiesFilter>] [-RequiredInputFieldsSet <String[]>]
 [-TemplateName <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create Entity Query
```powershell
PS C:\> $template = Get-AzSentinelEntityQueryTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "myEntityQueryTemplateId"
PS C:\> New-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" [-EntityQueryId <String>] -Kind Activity -Title ($template.title) -InputEntityType ($template.inputEntityType) -TemplateName ($template.Name)

Title              		: The user has created an account
Name                	: 6d37a904-d199-43ff-892b-53653b784122
Content            		: The user {{InitiatedByAccount}} has created the account {{TargetAccount}} {{Count}} time(s)
Description         	: This activity displays account creation events performed by the user
Enabled            		: True
Kind               		: Activity
CreatedTimeUtc      	: 12/22/2021 11:44:34 AM
LastModifiedTimeUtc 	: 12/22/2021 11:47:13 AM

```

This command creates an Entity Query by using a Template.

+ Example 2: Create Entity Query
```powershell
PS C:\> New-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityQueryId ((New-Guid).Guid) -Kind Activity -Title 'An account was deleted on this host' -InputEntityType 'Host' -Content "On '{{Computer}}' the account '{{TargetAccount}}' was deleted by '{{AddedBy}}'" -Description "Account deleted on host" -QueryDefinitionQuery 'let GetAccountActions = (v_Host_Name:string, v_Host_NTDomain:string, v_Host_DnsDomain:string, v_Host_AzureID:string, v_Host_OMSAgentID:string){\nSecurityEvent\n| where EventID in (4725, 4726, 4767, 4720, 4722, 4723, 4724)\n// parsing for Host to handle variety of conventions coming from data\n| extend Host_HostName = case(\nComputer has ''@'', tostring(split(Computer, ''@'')[0]),\nComputer has ''\\'', tostring(split(Computer, ''\\'')[1]),\nComputer has ''.'', tostring(split(Computer, ''.'')[0]),\nComputer\n)\n| extend Host_NTDomain = case(\nComputer has ''\\'', tostring(split(Computer, ''\\'')[0]), \nComputer has ''.'', tostring(split(Computer, ''.'')[-2]), \nComputer\n)\n| extend Host_DnsDomain = case(\nComputer has ''\\'', tostring(split(Computer, ''\\'')[0]), \nComputer has ''.'', strcat_array(array_slice(split(Computer,''.''),-2,-1),''.''), \nComputer\n)\n| where (Host_HostName =~ v_Host_Name and Host_NTDomain =~ v_Host_NTDomain) \nor (Host_HostName =~ v_Host_Name and Host_DnsDomain =~ v_Host_DnsDomain) \nor v_Host_AzureID =~ _ResourceId \nor v_Host_OMSAgentID == SourceComputerId\n| project TimeGenerated, EventID, Activity, Computer, TargetAccount, TargetUserName, TargetDomainName, TargetSid, SubjectUserName, SubjectUserSid, _ResourceId, SourceComputerId\n| extend AddedBy = SubjectUserName\n// Future support for Activities\n| extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity = TargetAccount\n};\nGetAccountActions(''{{Host_HostName}}'', ''{{Host_NTDomain}}'', ''{{Host_DnsDomain}}'', ''{{Host_AzureID}}'', ''{{Host_OMSAgentID}}'')\n \n| where EventID == 4726' -RequiredInputFieldsSet @(@("Host_HostName","Host_NTDomain"),@("Host_HostName","Host_DnsDomain"),@("Host_AzureID"),@("Host_OMSAgentID")) -EntitiesFilter @{"Host_OsFamily" = @("Windows")}

```

This command creates an Entity Query.


#### Get-AzSentinelEntityQuery

#### SYNOPSIS
Gets an entity query.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelEntityQuery -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-Kind <String>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelEntityQuery -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelEntityQuery -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Entity Queries
```powershell
PS C:\> Get-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

DisplayName     : Related entities
DataSource      : {SecurityAlert}
Name            : 98b974fd-cc64-48b8-9bd0-3a209f5b944b
InputEntityType : SecurityAlert

DisplayName     : Related alerts
DataSource      : {SecurityAlert}
Name            : 055a5692-555f-42bd-ac17-923a5a9994ed
InputEntityType : Host
```

This command lists all Entity Queries under a Microsoft Sentinel workspace.

+ Example 2: Get an Entity Query
```powershell
PS C:\> Get-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "myEntityQueryId"

DisplayName     : Related entities
DataSource      : {SecurityAlert}
Name            : 98b974fd-cc64-48b8-9bd0-3a209f5b944b
InputEntityType : SecurityAlert
QueryTemplate   : let GetAlertRelatedEntities = (v_SecurityAlert_SystemAlertId:string){
                                              SecurityAlert
                                              | where SystemAlertId == v_SecurityAlert_SystemAlertId
                                              | project entities = todynamic(Entities)
                                              | mv-expand entities
                                              | project-rename entity=entities};
                                              GetAlertRelatedEntities('<systemAlertId>')
```

This command gets an Entity Query.

+ Example 3: Get an Entity Query by object Id
```powershell
PS C:\> $EntityQueries = Get-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"
PS C:\> $EntityQueries[0] | Get-AzSentinelEntityQuery

DisplayName     : Related entities
DataSource      : {SecurityAlert}
Name            : 98b974fd-cc64-48b8-9bd0-3a209f5b944b
InputEntityType : SecurityAlert
QueryTemplate   : let GetAlertRelatedEntities = (v_SecurityAlert_SystemAlertId:string){
                                              SecurityAlert
                                              | where SystemAlertId == v_SecurityAlert_SystemAlertId
                                              | project entities = todynamic(Entities)
                                              | mv-expand entities
                                              | project-rename entity=entities};
                                              GetAlertRelatedEntities('<systemAlertId>')
```

This command gets a Entity Query by object.


#### Remove-AzSentinelEntityQuery

#### SYNOPSIS
Delete the entity query.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelEntityQuery -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelEntityQuery -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>] [-PassThru]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove Entity Query
```powershell
PS C:\> Remove-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "myEntityQueryTemplateId"

```

This command removes a specific entity query based on the entity query Id

+ Example 2: Remove an Entity Query based on the title
```powershell
PS C:\> $queryTemplateId = Get-AzSentinelEntityQueryTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" | Where-Object {$_.Title -eq "The user has created an account"}
Remove-AzSentinelEntityQuery -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id $queryTemplateId.Name

```

This command removes a specific entity query based on the title


#### Update-AzSentinelEntityQuery

#### SYNOPSIS
Updates the entity query.

#### SYNTAX

+ UpdateActivity (Default)
```powershell
Update-AzSentinelEntityQuery -EntityQueryId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Content <String>] [-Description <String>] [-Disabled] [-Enabled]
 [-EntitiesFilter <ActivityEntityQueriesPropertiesEntitiesFilter>] [-InputEntityType <EntityType>]
 [-QueryDefinitionQuery <String>] [-RequiredInputFieldsSet <String[]>] [-TemplateName <String>]
 [-Title <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityActivity
```powershell
Update-AzSentinelEntityQuery -InputObject <ISecurityInsightsIdentity> [-Content <String>]
 [-Description <String>] [-Disabled] [-Enabled]
 [-EntitiesFilter <ActivityEntityQueriesPropertiesEntitiesFilter>] [-InputEntityType <EntityType>]
 [-QueryDefinitionQuery <String>] [-RequiredInputFieldsSet <String[]>] [-TemplateName <String>]
 [-Title <String>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelEntityQueryTemplate

#### SYNOPSIS
Gets an entity query.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelEntityQueryTemplate -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Kind <String>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelEntityQueryTemplate -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelEntityQueryTemplate -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Entity Query Templates
```powershell
PS C:\> Get-AzSentinelEntityQueryTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Title           : The user has created an account
Description     : This activity displays account creation events performed by the user
InputEntityType : Account
Kind            : Activity
Name            : d6d08c94-455f-4ea5-8f76-fc6c0c442cfa

Title           : The user has deleted an account
Description     : This activity displays account deletion events performed by the user
InputEntityType : Account
Kind            : Activity
Name            : e0459780-ac9d-4b72-8bd4-fecf6b46a0a1
```

This command lists all Entity Query Templates under a Microsoft Sentinel workspace.

+ Example 2: Get an Entity Query Template
```powershell
PS C:\> Get-AzSentinelEntityQueryTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "d6d08c94-455f-4ea5-8f76-fc6c0c442cfa"

Description     : This activity displays account creation events performed by the user
InputEntityType : Account
Kind            : Activity
Name            : d6d08c94-455f-4ea5-8f76-fc6c0c442cfa
```

This command gets an Entity Query Template.

+ Example 3: Get an Entity Query Template by object Id
```powershell
PS C:\> $EntityQueryTemplates = Get-AzSentinelEntityQueryTemplate -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"
PS C:\> $EntityQueryTemplates[0] | Get-AzSentinelEntityQueryTemplate

Description     : This activity displays account creation events performed by the user
InputEntityType : Account
Kind            : Activity
Name            : d6d08c94-455f-4ea5-8f76-fc6c0c442cfa
```

This command gets a Entity Query Template by object.


#### Get-AzSentinelEntityRelation

#### SYNOPSIS
Gets an entity relation.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelEntityRelation -EntityId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelEntityRelation -EntityId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelEntityRelation -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Entity Relations for a given Entity 
```powershell
PS C:\> Get-AzSentinelEntityRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "myEntityId"
```

This command lists all Entity Relations for a given Entity.

+ Example 2: Get an Entity Relation
```powershell
PS C:\> Get-AzSentinelEntityRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "myEntityId" -Id "myEntityRelationId"
```

This command gets an Entity Relation for a given Entity.

+ Example 3: Get an Entity Relation by object Id
```powershell
PS C:\> $EntityRelations = Get-AzSentinelEntityRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "myEntityId"
PS C:\> $EntityRelations[0] | Get-AzSentinelEntityRelation

```

This command gets a Entity Relation by object


#### Get-AzSentinelEntityTimeline

#### SYNOPSIS
Timeline for an entity.

#### SYNTAX

```powershell
Get-AzSentinelEntityTimeline -EntityId <String> -ResourceGroupName <String> -WorkspaceName <String>
 -EndTime <DateTime> -StartTime <DateTime> [-SubscriptionId <String[]>] [-Kind <EntityTimelineKind[]>]
 [-NumberOfBucket <Int32>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Get Timeline for an Entity for a given time range
```powershell
PS C:\> $startTime = (get-date).AddDays(-7).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> $endTime = (get-date).ToUniversalTime() | Get-Date -Format "yyyy-MM-ddThh:00:00.000Z"
PS C:\> Get-AzSentinelEntityTime -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -EntityId "myEntityId" -EndTime $endTime -StartTime $startTime

DisplayName   : Suspicious process executed
Description   : Machine logs indicate that a suspicious process often associated with attacker attempts to access credentials was running on the host.
Kind          : SecurityAlert
ProductName   : Azure Security Center
Severity      : High
StartTimeUtc  : 12/20/2021 3:04:17 PM
EndTimeUtc    : 12/20/2021 3:04:17 PM
TimeGenerated : 12/20/2021 3:05:52 PM
```

This command gets the Timeline for an Entity for a given time range.


#### New-AzSentinelIncident

#### SYNOPSIS
Creates or updates the incident.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelIncident -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Classification <IncidentClassification>] [-ClassificationComment <String>]
 [-ClassificationReason <IncidentClassificationReason>] [-Description <String>]
 [-FirstActivityTimeUtc <DateTime>] [-Label <IIncidentLabel[]>] [-LastActivityTimeUtc <DateTime>]
 [-OwnerAssignedTo <String>] [-OwnerEmail <String>] [-OwnerObjectId <String>]
 [-OwnerUserPrincipalName <String>] [-ProviderIncidentId <String>] [-ProviderName <String>]
 [-Severity <IncidentSeverity>] [-Status <IncidentStatus>] [-Title <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelIncident -Id <String> -ResourceGroupName <String> -WorkspaceName <String> -Incident <IIncident>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create an Incident
```powershell
PS C:\> New-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id ((New-Guid).Guid) -Title "NewIncident" -Description "My Description" -Severity Low -Status New

Title          : NewIncident
Description    : My Description
Severity       : Low
Status         : New
Number         : 779
CreatedTimeUtc : 2/3/2022 7:47:03 PM
Name           : c831b5a7-5644-403f-9dc3-96d651e04c6d
Url            : https://portal.azure.com/####asset/Microsoft_Azure_Security_Insights/Incident/subscriptions/274b1a41-c53c-4092-8d4a-7210f6a44a0c/resourceGroups/cyber-soc/providers/Microsoft.OperationalInsights/workspaces/myworkspace/providers/Microsoft.SecurityInsights/Incidents/c831b5a7-5644-403f-9dc3-96d651e04c6d
```

This command creates an Incident.


#### Get-AzSentinelIncident

#### SYNOPSIS
Gets an incident.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelIncident -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>] [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelIncident -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelIncident -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Incidents
```powershell
PS C:\> Get-AzSentinelIncident -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Title        	: (Preview) TI map IP entity to AzureActivity
Description  	: Identifies a match in AzureActivity from any IP IOC from TI
Severity     	: Medium
Number      	: 754
Label        	: {}
ProviderName  : Azure Sentinel
Name         	: f5409f55-7dd8-4c73-9981-4627520b2db
```

This command lists all Incidents under a Microsoft Sentinel workspace.

+ Example 2: Get an Incident
```powershell
PS C:\> Get-AzSentinelIncident -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Id "f5409f55-7dd8-4c73-9981-4627520b2db"

Title        	: (Preview) TI map IP entity to AzureActivity
Description  	: Identifies a match in AzureActivity from any IP IOC from TI
Severity     	: Medium
Number      	: 754
Label        	: {}
ProviderName  : Azure Sentinel
Name         	: f5409f55-7dd8-4c73-9981-4627520b2db
```

This command gets an Incident.


#### Remove-AzSentinelIncident

#### SYNOPSIS
Delete the incident.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelIncident -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelIncident -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>] [-PassThru]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Removes an incident based on the incident Id
```powershell
PS C:\>Remove-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id <IncidentId>

```

This command removes an incident based on the incident id.

+ Example 2: Removes an incident based on the incident number
```powershell
PS C:\>$myIncident = Get-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id <IncidentId> | Where-Object {$_.Number -eq "780"}

```

The command removes an incident based on an incident number.


#### Update-AzSentinelIncident

#### SYNOPSIS
Creates or updates the incident.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelIncident -Id <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Classification <IncidentClassification>] [-ClassificationComment <String>]
 [-ClassificationReason <IncidentClassificationReason>] [-Description <String>]
 [-FirstActivityTimeUtc <DateTime>] [-Label <IIncidentLabel[]>] [-LastActivityTimeUtc <DateTime>]
 [-OwnerAssignedTo <String>] [-OwnerEmail <String>] [-OwnerObjectId <String>]
 [-OwnerUserPrincipalName <String>] [-ProviderIncidentId <String>] [-ProviderName <String>]
 [-Severity <IncidentSeverity>] [-Status <IncidentStatus>] [-Title <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelIncident -InputObject <ISecurityInsightsIdentity> [-Classification <IncidentClassification>]
 [-ClassificationComment <String>] [-ClassificationReason <IncidentClassificationReason>]
 [-Description <String>] [-FirstActivityTimeUtc <DateTime>] [-Label <IIncidentLabel[]>]
 [-LastActivityTimeUtc <DateTime>] [-OwnerAssignedTo <String>] [-OwnerEmail <String>]
 [-OwnerObjectId <String>] [-OwnerUserPrincipalName <String>] [-ProviderIncidentId <String>]
 [-ProviderName <String>] [-Severity <IncidentSeverity>] [-Status <IncidentStatus>] [-Title <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelIncidentAlert

#### SYNOPSIS
Gets all incident alerts.

#### SYNTAX

```powershell
Get-AzSentinelIncidentAlert -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Alerts for a given Incident
```powershell
PS C:\> Get-AzSentinelIncidentAlert -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "myIncidentId"

AlertDisplayName : (Preview) TI map IP entity to SigninLogs
FriendlyName     : (Preview) TI map IP entity to SigninLogs
Description      : Identifies a match in SigninLogs from any IP IOC from TI
Kind             : SecurityAlert
Name             : d1e4d1dd-8d16-1aed-59bd-a256266d7244
ProductName      : Azure Sentinel
Status           : New
ProviderAlertId  : d6c7a42b-c0da-41ef-9629-b3d2d407b181
Tactic           : {Impact}
```

This command lists all Alerts for a given Incident.


#### Get-AzSentinelIncidentBookmark

#### SYNOPSIS
Gets all incident bookmarks.

#### SYNTAX

```powershell
Get-AzSentinelIncidentBookmark -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Bookmarks for a given Incident
```powershell
PS C:\> Get-AzSentinelIncidentBookmark -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "7f40bbbc-e205-404b-bc2b-5d71cd1017a8"

DisplayName    : My 2021 Bookmark
FriendlyName   : My 2021 Bookmark
Label          : {my Tags}
Note           : my notes
                 2nd line notes
CreatedByEmail : luke@contoso.com
CreatedByName  : Luke
Name           : 4557d832-41f0-456f-977e-78a2e129b8d0 
```

This command lists all Bookmarks for a given Incident.


#### New-AzSentinelIncidentComment

#### SYNOPSIS
Creates or updates the incident comment.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelIncidentComment -Id <String> -IncidentId <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-Message <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelIncidentComment -Id <String> -IncidentId <String> -ResourceGroupName <String>
 -WorkspaceName <String> -IncidentComment <IIncidentComment> [-SubscriptionId <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create an Incident Comment
```powershell
PS C:\> New-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -IncidentId "myIncidentId" -Id ((New-Guid).Guid) -Message "IncidentCommentGoesHere"

```

This command creates an Incident Comment.


#### Get-AzSentinelIncidentComment

#### SYNOPSIS
Gets an incident comment.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelIncidentComment -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelIncidentComment -Id <String> -IncidentId <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelIncidentComment -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Incident Comments for a given Incident 
```powershell
PS C:\> Get-AzSentinelIncidentComment -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "7a4c27ea-d61a-496b-b5c3-246770c857c1"

AuthorEmail             : john@contoso.com
AuthorName              : John Contoso
AuthorUserPrincipalName : john@contoso.com
CreatedTimeUtc          : 1/6/2022 2:15:44 PM
Message                 : This is my comment
Name                    : da0957c9-2f1a-44a2-bc83-a2c0696b2bf1

```

This command lists all Incident Comments for a given Incident.

+ Example 2: Get an Incident Comment
```powershell
PS C:\> Get-AzSentinelIncidentComment -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "7a4c27ea-d61a-496b-b5c3-246770c857c1" -Id "da0957c9-2f1a-44a2-bc83-a2c0696b2bf1"

AuthorEmail             : john@contoso.com
AuthorName              : John Contoso
AuthorUserPrincipalName : john@contoso.com
CreatedTimeUtc          : 1/6/2022 2:15:44 PM
Message                 : This is my comment
Name                    : da0957c9-2f1a-44a2-bc83-a2c0696b2bf1
```

This command gets an Incident Comment.


#### Remove-AzSentinelIncidentComment

#### SYNOPSIS
Delete the incident comment.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelIncidentComment -Id <String> -IncidentId <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelIncidentComment -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove an incident comment
```powershell
PS C:\>Remove-AzSentinelIncidentComment -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId 7cc984fe-61a2-43c2-a1a4-3583c8a89da2 -Id 7a4c27ea-d61a-496b-b5c3-246770c857c1

This command removes an incident comment
```




#### Update-AzSentinelIncidentComment

#### SYNOPSIS
Creates or updates the incident comment.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelIncidentComment -Id <String> -IncidentId <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-Message <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelIncidentComment -InputObject <ISecurityInsightsIdentity> [-Message <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update incident comment
```powershell
PS C:\>Update-AzSentinelIncidentComment -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId 7cc984fe-61a2-43c2-a1a4-3583c8a89da2 -Id 8bb5c1eb-a3a9-4575-9451-cd2834be0e0a -Message "my comment"

```

This command updates an incident comment


#### Get-AzSentinelIncidentEntity

#### SYNOPSIS
Gets all incident related entities.

#### SYNTAX

```powershell
Get-AzSentinelIncidentEntity -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Entities for a given Incident
```powershell
PS C:\> Get-AzSentinelIncidentEntity -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "0ddb580f-efd0-4076-bb77-77e9aef8a187"

FriendlyName : win2019
Kind         : Host
Name         : cb577adf-0266-8873-84d7-accf4b45417b
```

This command lists all Entities for a given Incident.


#### New-AzSentinelIncidentRelation

#### SYNOPSIS
Creates or updates the incident relation.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelIncidentRelation -IncidentId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-RelatedResourceId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelIncidentRelation -IncidentId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> -Relation <IRelation> [-SubscriptionId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create a Incident Relation
```powershell
PS C:\> $bookmark = Get-AzSentinelBookmark -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id "myBookmarkId"
PS C:\> New-AzSentinelIncidentRelation -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -IncidentId "myIncidentId" -RelationName ((New-Guid).Guid) -RelatedResourceId ($bookmark.Id)

Name                : 4b112bd9-a6b5-44f6-b89d-8bcbf021fbdf
RelatedResourceName : a636a51c-471a-468d-89ed-d7f4b2a7a569
RelatedResourceKind :
RelatedResourceType : Microsoft.SecurityInsights/Bookmarks
```

This command creates a Incident Relation connecting the Bookmark to the Incident.


#### Get-AzSentinelIncidentRelation

#### SYNOPSIS
Gets an incident relation.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelIncidentRelation -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelIncidentRelation -IncidentId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelIncidentRelation -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Incident Relations for a given Incident 
```powershell
PS C:\> Get-AzSentinelIncidentRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "myIncidentId"

Name                : 8969f5ea-4e92-433a-9b67-2f9233d8113f_457a48b2-9dfc-7054-64a5-e8a9d17489d7
RelatedResourceName : 457a48b2-9dfc-7054-64a5-e8a9d17489d7
RelatedResourceKind : SecurityAlert
RelatedResourceType : Microsoft.SecurityInsights/entities

Name                : 076bda5c-7d94-b6d8-8ef4-b0b2a0830dac_df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceName : df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceKind : SecurityAlert
RelatedResourceType : Microsoft.SecurityInsights/entities
```

This command lists all Incident Relations for a given Incident.

+ Example 2: Get a Incident Relation
```powershell
PS C:\> Get-AzSentinelIncidentRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "myIncidentId" -Id "myIncidentRelationId"

Name                : 076bda5c-7d94-b6d8-8ef4-b0b2a0830dac_df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceName : df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceKind : SecurityAlert
RelatedResourceType : Microsoft.SecurityInsights/entities
```

This command gets a Incident Relation.

+ Example 3: Get a Incident Relation by object Id
```powershell
PS C:\> $Incidentrelations = Get-AzSentinelIncidentRelation -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -IncidentId "myIncidentId"
PS C:\> $Incidentrelations[0] | Get-AzSentinelIncidentRelation

Name                : 076bda5c-7d94-b6d8-8ef4-b0b2a0830dac_df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceName : df9493a7-4f2e-84da-1f41-4914e8c029ba
RelatedResourceKind : SecurityAlert
RelatedResourceType : Microsoft.SecurityInsights/entities
```

This command gets a Incident by object


#### Remove-AzSentinelIncidentRelation

#### SYNOPSIS
Delete the incident relation.

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelIncidentRelation -IncidentId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelIncidentRelation -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Update-AzSentinelIncidentRelation

#### SYNOPSIS
Creates or updates the incident relation.

#### SYNTAX

+ UpdateExpanded (Default)
```powershell
Update-AzSentinelIncidentRelation -IncidentId <String> -RelationName <String> -ResourceGroupName <String>
 -WorkspaceName <String> [-SubscriptionId <String>] [-RelatedResourceId <String>] [-DefaultProfile <PSObject>]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpanded
```powershell
Update-AzSentinelIncidentRelation -InputObject <ISecurityInsightsIdentity> [-RelatedResourceId <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update an incident relation
```powershell
PS C:\> $bookmark = Get-AzSentinelBookmark -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id "myBookmarkId"
PS C:\> Update-AzSentinelIncidentRelation -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -IncidentId "myIncidentId" -RelationName ((New-Guid).Guid) -RelatedResourceId ($bookmark.Id)

```

This command updates an incident relation


#### New-AzSentinelIncidentTeam

#### SYNOPSIS
Creates a Microsoft team to investigate the incident by sharing information and insights between participants.

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelIncidentTeam -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 -TeamName <String> [-SubscriptionId <String>] [-GroupId <String[]>] [-MemberId <String[]>]
 [-TeamDescription <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelIncidentTeam -IncidentId <String> -ResourceGroupName <String> -WorkspaceName <String>
 -TeamProperty <ITeamProperties> [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Create an Incident Teams Room
```powershell
PS C:\> $incident = Get-AzSentinelIncident -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -Id "myIncidentId"
PS C:\> New-AzSentinelIncidentTeam -ResourceGroupName "myResourceGroup" -WorkspaceName "myWorkspaceName" -IncidentId ($incident.Name) -TeamName ("Incident "+$incident.incidentNumber+": "+$incident.title)

Description         :
Name                : Incident : NewIncident3
PrimaryChannelUrl   : https://teams.microsoft.com/l/team/19:vYoGjeGlZmTEDmu0gTbrk9T_eDS4pKIkEU7UuM1IyZk1%40thread.tacv2/conversations?groupId=3c637cc5-caf1-46c7-93ac-069c6
                      4b05395&tenantId=8f21ced5-2eff-4f8d-aff1-4dbb4cee8e3d
TeamCreationTimeUtc : 2/4/2022 3:02:03 PM
TeamId              : 3c637cc5-caf1-46c7-93ac-069c64b05395
```

This command creates a Teams group for the Incident.


#### Get-AzSentinelMetadata

#### SYNOPSIS
Get a Metadata.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelMetadata -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-Filter <String>] [-Orderby <String>] [-Skip <Int32>] [-Top <Int32>] [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelMetadata -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelMetadata -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```


#### New-AzSentinelOnboardingState

#### SYNOPSIS
Create Sentinel onboarding state

#### SYNTAX

+ CreateExpanded (Default)
```powershell
New-AzSentinelOnboardingState -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-CustomerManagedKey] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```

+ Create
```powershell
New-AzSentinelOnboardingState -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 -SentinelOnboardingStateParameter <ISentinelOnboardingState> [-SubscriptionId <String>]
 [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Add Sentinel onboarding state
```powershell
PS C:\>AzSentinelOnboardingState -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Name "default"

```

This command configures the onboarding state of Sentinel


#### Get-AzSentinelOnboardingState

#### SYNOPSIS
Get Sentinel onboarding state

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelOnboardingState -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelOnboardingState -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelOnboardingState -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Onboarding States
```powershell
PS C:\> Get-AzSentinelOnboardingState -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Id   : /subscriptions/314b1a41-c53c-4092-8d4a-2810f6a44a0c/resourceGroups/myRG/providers/Microsoft.OperationalInsights/workspaces/cybersecurity/providers/Microsoft.SecurityInsights/onboardingStates/default
Name : default
```

This command lists all Onboarding States under a Microsoft Sentinel workspace.

+ Example 2: Get an Onboarding State
```powershell
PS C:\> Get-AzSentinelOnboardingState -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Name "default"

Id   : /subscriptions/314b1a41-c53c-4092-8d4a-2810f6a44a0c/resourceGroups/myRG/providers/Microsoft.OperationalInsights/workspaces/cybersecurity/providers/Microsoft.SecurityInsights/onboardingStates/default
Name : default
```

This command gets an Onboarding State.


#### Remove-AzSentinelOnboardingState

#### SYNOPSIS
Delete Sentinel onboarding state

#### SYNTAX

+ Delete (Default)
```powershell
Remove-AzSentinelOnboardingState -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-DefaultProfile <PSObject>] [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ DeleteViaIdentity
```powershell
Remove-AzSentinelOnboardingState -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [-PassThru] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Remove the Sentinel onboarding state
```powershell
PS C:\>Remove-AzSentinelOnboardingState -ResourceGroupName "myResourceGroupName" -WorkspaceName "myWorkspaceName" -Name "default"

```

This commands removes the Sentinel onboarding state


#### Get-AzSentinelSetting

#### SYNOPSIS
Gets a setting.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelSetting -ResourceGroupName <String> -WorkspaceName <String> [-SubscriptionId <String[]>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelSetting -ResourceGroupName <String> -SettingsName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelSetting -InputObject <ISecurityInsightsIdentity> [-DefaultProfile <PSObject>]
 [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Settings
```powershell
PS C:\> Get-AzSentinelSetting -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Kind      : EntityAnalytics
Name      : EntityAnalytics
IsEnabled : True

Kind      : EyesOn
Name      : EyesOn
IsEnabled : True

Kind : IPSyncer
Name : IPSyncer

Kind      : Anomalies
Name      : Anomalies
IsEnabled : True

Kind       : Ueba
Name       : Ueba
DataSource : {AuditLogs, AzureActivity, SecurityEvent, SigninLogs}
```

This command lists all Settings under a Microsoft Sentinel workspace.

+ Example 2: Get a Setting
```powershell
PS C:\> Get-AzSentinelSetting -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -SettingsName "Anomalies"

Kind      : Anomalies
Name      : Anomalies
IsEnabled : True
```

This command gets a Setting.

+ Example 3: Get a Setting by object Id
```powershell
PS C:\> $Settings = Get-AzSentinelSetting -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"
PS C:\> $Settings[0] | Get-AzSentinelSetting

Kind      : Anomalies
Name      : Anomalies
IsEnabled : True
```

This command gets a Setting by object


#### Update-AzSentinelSetting

#### SYNOPSIS
Updates setting.

#### SYNTAX

+ UpdateExpandedAnomaliesEyesOnEntityAnalytics (Default)
```powershell
Update-AzSentinelSetting -ResourceGroupName <String> -WorkspaceName <String> -SettingsName <String>
 [-SubscriptionId <String>] [-Disabled] [-Enabled] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm]
 [-WhatIf] [<CommonParameters>]
```

+ UpdateExpandedUeba
```powershell
Update-AzSentinelSetting -ResourceGroupName <String> -WorkspaceName <String> -SettingsName <String>
 [-SubscriptionId <String>] [-DataSource <UebaDataSources[]>] [-DefaultProfile <PSObject>] [-AsJob] [-NoWait]
 [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpandedAnomaliesEyesOnEntityAnalytics
```powershell
Update-AzSentinelSetting -InputObject <ISecurityInsightsIdentity> [-Disabled] [-Enabled]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

+ UpdateViaIdentityExpandedUeba
```powershell
Update-AzSentinelSetting -InputObject <ISecurityInsightsIdentity> [-DataSource <UebaDataSources[]>]
 [-DefaultProfile <PSObject>] [-AsJob] [-NoWait] [-Confirm] [-WhatIf] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Update the Anomalies setting
```powershell
PS C:\> Update-AzSentinelSetting -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -SettingsName 'Anomalies' -Enabled

```

This command updates the Anomalies setting, other settings are:
EyesOn, EntityAnalytics and Ueba


#### Get-AzSentinelSourceControlRepository

#### SYNOPSIS
Gets a list of repositories metadata.

#### SYNTAX

```powershell
Get-AzSentinelSourceControlRepository -ResourceGroupName <String> -WorkspaceName <String> -RepoType <RepoType>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf] [<CommonParameters>]
```


#### Get-AzSentinelThreatIntelligenceIndicator

#### SYNOPSIS
View a threat intelligence indicator by name.

#### SYNTAX

+ List (Default)
```powershell
Get-AzSentinelThreatIntelligenceIndicator -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-Filter <String>] [-Orderby <String>] [-SkipToken <String>] [-Top <Int32>]
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ Get
```powershell
Get-AzSentinelThreatIntelligenceIndicator -Name <String> -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

+ GetViaIdentity
```powershell
Get-AzSentinelThreatIntelligenceIndicator -InputObject <ISecurityInsightsIdentity>
 [-DefaultProfile <PSObject>] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: List all Threat Intelligence Indicators
```powershell
PS C:\> Get-AzSentinelThreatIntelligenceIndicator -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

Kind : indicator
Name : 8ff8f736-8f9b-a180-49a2-9a395cf088ca

Kind : indicator
Name : 8afa82a1-6c4a-dca2-595f-28239965882d
```

This command lists all Threat Intelligence Indicators under a Microsoft Sentinel workspace.

+ Example 2: Get a Threat Intelligence Indicator
```powershell
PS C:\> Get-AzSentinelThreatIntelligenceIndicator -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Name "514840ce-5582-f7a4-8562-7996e29dc07a"

Kind : indicator
Name : 514840ce-5582-f7a4-8562-7996e29dc07a
```

This command gets a Threat Intelligence Indicator by name (Id)

+ Example 3: Get the Threat Intelligence Indicator top 3
```powershell
PS C:\> $tiIndicators = Get-AzSentinelThreatIntelligenceIndicator -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName" -Top 3

Kind : indicator
Name : 8ff8f736-8f9b-a180-49a2-9a395cf088ca

Kind : indicator
Name : 8afa82a1-6c4a-dca2-595f-28239965882d

Kind : indicator
Name : 38ac867b-85f9-be4c-afd5-b3cffdcf69f1
```

This command gets a Threat Intelligence Indicator by object


#### Get-AzSentinelThreatIntelligenceIndicatorMetric

#### SYNOPSIS
Get threat intelligence indicators metrics (Indicators counts by Type, Threat Type, Source).

#### SYNTAX

```powershell
Get-AzSentinelThreatIntelligenceIndicatorMetric -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String[]>] [-DefaultProfile <PSObject>] [<CommonParameters>]
```

#### EXAMPLES

+ Example 1: Get all metrics for Threat Intelligence Indicators
```powershell
PS C:\> Get-AzSentinelThreatIntelligenceIndicatorMetric -ResourceGroupName "myResourceGroupName" -workspaceName "myWorkspaceName"

LastUpdatedTimeUtc : 2022-02-07T10:44:45.3919348Z
PatternTypeMetric  : {network-traffic, url, ipv4-addr, file}
SourceMetric       : {Microsoft Emerging Threat Feed, Bing Safety Phishing URL, Azure Sentinel, CyberCrime…}
ThreatTypeMetric   : {botnet, maliciousurl, phishing, malicious-activity…}
```

This command gets Threat Intelligence Indicator metrics.


#### Invoke-AzSentinelThreatIntelligenceIndicatorQuery

#### SYNOPSIS
Query threat intelligence indicators as per filtering criteria.

#### SYNTAX

```powershell
Invoke-AzSentinelThreatIntelligenceIndicatorQuery -ResourceGroupName <String> -WorkspaceName <String>
 [-SubscriptionId <String>] [-Id <String[]>] [-IncludeDisabled] [-Keyword <String[]>] [-MaxConfidence <Int32>]
 [-MaxValidUntil <String>] [-MinConfidence <Int32>] [-MinValidUntil <String>] [-PageSize <Int32>]
 [-PatternType <String[]>] [-SkipToken <String>] [-SortBy <IThreatIntelligenceSortingCriteria[]>]
 [-Source <String[]>] [-ThreatType <String[]>] [-DefaultProfile <PSObject>] [-Confirm] [-WhatIf]
 [<CommonParameters>]
```


