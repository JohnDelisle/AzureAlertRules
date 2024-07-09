# Adds alerts to address Azure CIS 1.3 policies

[CmdletBinding()]
param (
    # these affect where the Action Group is created, and where the Activity Log Alerts are created
    [Parameter(Mandatory = $true)][string]$agSubscriptionId,
    [Parameter(Mandatory = $true)][string]$agResourceGroupName,
    [Parameter(Mandatory = $true)][string]$agName,
    [Parameter(Mandatory = $true)][string]$agShortName,
    [Parameter(Mandatory = $true)][string[]]$agEmails
)

# list of policies and their operation names we need to create Alert Rules for
$alertRules = @(
    [PSCustomObject]@{
        PolicyName = "An activity log alert should exist for specific Administrative operations"
        PolicyDefinitionId = "b954148f-4c11-4c38-8221-be76711e194a"
        OperationNames = @(
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
        PolicyName = "An activity log alert should exist for specific Policy operations"
        PolicyDefinitionId = "c5447c04-a4d7-4ba8-a263-c9ee321a6858"
        OperationNames = @(
            "Microsoft.Authorization/policyAssignments/write",
            "Microsoft.Authorization/policyAssignments/delete"
        )

    },
    [PSCustomObject]@{
        PolicyName = "An activity log alert should exist for specific Security operations"
        PolicyDefinitionId = "3b980d31-7904-4bb7-8575-5665739a8052"
        OperationNames = @(
            "Microsoft.Security/policies/write",
            "Microsoft.Security/securitySolutions/write",
            "Microsoft.Security/securitySolutions/delete"
        )
    }
)


#############################
###### create Action Group
#############################

# AG receivers
$agEmailReceivers = @()
foreach ($email in $agEmails) {
    $agEmailReceivers += New-AzActionGroupReceiver -Name $email.split('@')[-1] -EmailReceiver -EmailAddress $email
}

# create/ update the AG
Select-AzSubscription $agSubscriptionId | Out-Null
$ag = Set-AzActionGroup -Name $agName -ResourceGroup $agResourceGroupName -ShortName $agShortName -Receiver $agEmailReceivers



#############################
###### create Activity Log Alert for each sub
#############################

foreach ($sub in Get-AzSubscription) {
    foreach ($alertRule in $alertRules) {
        $conditions = @()
        # want to filter for Security category
        $conditions += New-AzActivityLogAlertCondition -Field 'category' -Equal 'Security'
        
        # add each of the operation names needed for this alert rule
        foreach ($operationName in $alertRule.OperationNames) {
            $conditions += New-AzActivityLogAlertCondition -Field 'operationName' -Equal $operationName
        }

        $alertRuleName = "Compliance with $($alertRule.PolicyDefinitionId) on sub $($sub.Id)"
        Set-AzActivityLogAlert -Location 'CanadaCentral' -Name $alertRuleName -ResourceGroupName $agResourceGroupName -Scope "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxxx/" -Action $ag.Id -Condition $conditions

    }
}
