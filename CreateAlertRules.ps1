# Adds alerts to address Azure CIS 1.3 policies

[CmdletBinding()]
param (
    # These affect where the Action Group is created and where the Activity Log Alerts are created
    [Parameter(Mandatory = $true)][string]$agShortName,
    [Parameter(Mandatory = $true)][string[]]$agEmails,
    [Parameter(Mandatory = $true)][string]$rgLocation,
    [Parameter(Mandatory = $false)][hashtable]$tags
)

$ErrorActionPreference = 'Stop'

# List of policies and their operation names for which we need to create Alert Rules
$alertRules = @(
    [PSCustomObject]@{
        PolicyName         = "An activity log alert should exist for specific Administrative operations"
        PolicyDefinitionId = "b954148f-4c11-4c38-8221-be76711e194a"
        Category           = "Administrative"
        OperationNames     = @(
            "Microsoft.Sql/servers/firewallRules/write",
            "Microsoft.Sql/servers/firewallRules/delete",
            "Microsoft.Network/networkSecurityGroups/write",
            "Microsoft.Network/networkSecurityGroups/delete",
            "Microsoft.ClassicNetwork/networkSecurityGroups/write",
            "Microsoft.ClassicNetwork/networkSecurityGroups/delete",
            "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "Microsoft.Network/networkSecurityGroups/securityRules/delete",
            "Microsoft.ClassicNetwork/networkSecurityGroups/securityRules/write",
            "Microsoft.ClassicNetwork/networkSecurityGroups/securityRules/delete"
        )
    },
    [PSCustomObject]@{
        PolicyName         = "An activity log alert should exist for specific Policy operations"
        PolicyDefinitionId = "c5447c04-a4d7-4ba8-a263-c9ee321a6858"
        Category           = "Administrative"
        OperationNames     = @(
            "Microsoft.Authorization/policyAssignments/write",
            "Microsoft.Authorization/policyAssignments/delete"
        )
    },
    [PSCustomObject]@{
        PolicyName         = "An activity log alert should exist for specific Security operations"
        PolicyDefinitionId = "3b980d31-7904-4bb7-8575-5665739a8052"
        Category           = "Security"
        OperationNames     = @(
            "Microsoft.Security/policies/write",
            "Microsoft.Security/securitySolutions/write",
            "Microsoft.Security/securitySolutions/delete"
        )
    }
)

# Iterate through each subscription and create alerts
foreach ($sub in Get-AzSubscription) {
    $sub | Select-AzSubscription | Out-Null

    # Get the "abc123" from "abc123 subscription name blah"
    $subShortCode = $sub.Name.split(" ")[0]
    $agResourceGroupName = "$($subShortCode.ToLower())-$($agShortName.ToLower())-rg"
    $agName = "$($subShortCode.ToLower())-$($agShortName.ToLower())-ag"

    Write-Output "Creating $agName in $agResourceGroupName"

    # Create or update the resource group
    $rg = New-AzResourceGroup -Name $agResourceGroupName -Location $rgLocation -Tag $tags -Force

    # Create Action Group email receivers
    $agEmailReceivers = @()
    foreach ($email in $agEmails) {
        $agEmailReceivers += New-AzActionGroupEmailReceiverObject -Name $email.split('@')[0] -EmailAddress $email
    }

    # Create or update the Action Group
    $ag = New-AzActionGroup -Name $agName -ResourceGroup $agResourceGroupName -ShortName $agShortName -EmailReceiver $agEmailReceivers -Location Global -Tag $tags
    $agObject = New-AzActivityLogAlertActionGroupObject -Id $ag.Id

    # Create the Activity Log Alerts
    foreach ($alertRule in $alertRules) {
        $conditions = @()
        $conditions += New-AzActivityLogAlertAlertRuleLeafConditionObject -Field 'category' -Equal $alertRule.Category
        $conditions += New-AzActivityLogAlertAlertRuleAnyOfOrLeafConditionObject -AnyOf (
                $alertRule.OperationNames | ForEach-Object { 
                    New-AzActivityLogAlertAlertRuleLeafConditionObject -Field 'operationName' -Equal $_ 
                }
            )

        $alertRuleName = "Compliance with $($alertRule.PolicyDefinitionId)"
        New-AzActivityLogAlert -Location Global -Name $alertRuleName -ResourceGroupName $agResourceGroupName -Scope "/subscriptions/$($sub.Id)" -Action $agObject -Condition $conditions -Tag $tags

        Write-Output "Created alert rule: $alertRuleName"
    }
}

Write-Output "Activity log alert rules created successfully."
