<#
.SYNOPSIS
    Converts a SDDL string from an EventLog to a more human readable format.
.DESCRIPTION
    Converts a SDDL string from an EventLog to a more human readable format providing EventLog specific permissions.
.EXAMPLE
    converfrom-EventlogSDDL -SddlString (get-winventlog -LogName Security).SecurityDescriptor
#>

function ConvertFrom-EventlogSDDL {
    [CmdletBinding()]
    param (
        # EventLog SDDL String
        [Parameter(Mandatory = $true)]
        [string]
        $SddlString
    )
    
    begin {}
    
    process {
        $sec = New-Object System.Security.AccessControl.DirectorySecurity
        $sec.SetSecurityDescriptorSddlForm($SddlString)
        $sec.Access | ForEach-Object {
            [System.Collections.ArrayList]$EventLogRights = @()
            $fileright = $_.FileSystemRights.value__
            if (($fileright -band 0x00000001) -eq 0x00000001) { $EventLogRights.Add("LogFileRead") | Out-Null }
            if (($fileright -band 0x00000002) -eq 0x00000002) { $EventLogRights.Add("LogFileWrite") | Out-Null }
            if (($fileright -band 0x00000004) -eq 0x00000004) { $EventLogRights.Add("LogFileClear") | Out-Null }
            if (($fileright -band 0x00010000) -eq 0x00010000) { $EventLogRights.Add("Delete") | Out-Null }
            if (($fileright -band 0x00020000) -eq 0x00020000) { $EventLogRights.Add("ReadControl") | Out-Null }
            if (($fileright -band 0x00040000) -eq 0x00040000) { $EventLogRights.Add("WriteDAC") | Out-Null }
            if (($fileright -band 0x00080000) -eq 0x00080000) { $EventLogRights.Add("WriteOwner") | Out-Null }
            if (($fileright -band 0x80000000) -eq 0x80000000) { $EventLogRights.Add("GenericRead") | Out-Null }
            if (($fileright -band 0x40000000) -eq 0x40000000) { $EventLogRights.Add("GenericWrite") | Out-Null }
            if (($fileright -band 0x20000000) -eq 0x20000000) { $EventLogRights.Add("GenericExecute") | Out-Null }
            if (($fileright -band 0x10000000) -eq 0x10000000) { $EventLogRights.Add("GenericAll") | Out-Null }
            if (($fileright -band 0x01000000) -eq 0x01000000) { $EventLogRights.Add("AccessSystemSecurity") | Out-Null }

            Add-Member -InputObject $_ -NotePropertyName "EventLogRights" -NotePropertyValue $EventLogRights
            $_
        }
    }
    
    end {}
}