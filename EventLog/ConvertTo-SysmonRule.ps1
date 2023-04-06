function ConvertTo-SysmonRule {
    <#
    .SYNOPSIS
        Turn Sysmon Event objects in to Rules or RuleGroups for use in configuration files.
    .DESCRIPTION
        Funtion for creationg Rules or RuleGroups depending on the number of properties from Sysmon Event Objects. When more than
        1 property select will be turned in to RuleGroups, if only one property is present they are turned in to Rules. RuleGroups
        have a Group Relation of 'and'.
    .EXAMPLE
        PS C:\> Get-SysmonProcessCreateEvent -Path C:\bootevents.evtx -Image "c:\windows\system32\svchost.exe" | select parentimage,commandline | ConvertTo-SysmonRule
        Create rule groups to filter on svchost.exe pararent process and command line.
    .INPUTS
        System.Management.Automation.PSCustomObject
        System.String
    .OUTPUTS
        System.String
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        # Sysmon Event Object
        [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [pscustomobject[]]
        $SysmonEvent,

        # Rule condition.
        [Parameter(Mandatory=$false)]
        [ValidateSet("is","is not","contains","contains any","is any","contains all",
            "excludes","excludes any","excludes all","begin with","not begin with",
            "end with","not end with","less than","more than","image")]
        [string]
        $Condition = "is"
    )
    
    begin {
        
    }
    process {

        foreach($event in $SysmonEvent) {
            $propCount = (Get-Member -InputObject $event -MemberType Properties).count
            if ($propCount -eq 1){
                $event.PSObject.Properties | ForEach-Object {
                    "<$($_.name) condition='$($Condition)'>$($_.value)</$($_.name)>"
                }

            } elseif ($propCount -gt 1) {
                $RuleGroup = "<Rule groupRelation=`"and`">`n"
                $event.PSObject.Properties | ForEach-Object {
                    $RuleGroup += "  <$($_.name) condition='$($Condition)'>$($_.value)</$($_.name)>`n"
                }
                $RuleGroup += "</Rule>"
                $RuleGroup
            }
        }
    }
    end {}
}