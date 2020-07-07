function Get-EventSystemLogon {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        # Log name for where the events are stored.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string]
        $LogName = 'Security',

        # The type of logon which was performed. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet('Interactive', 'Network', 'Batch', 'Service', 
            'Unlock', 'NetworkCleartext', 'NewCredentials', 
            'RemoteInteractive', 'CachedInteractive')]
        [string[]]
        $EventLogonType,

        # The name of the authentication package which was used for the logon authentication process. 
        # Default packages loaded on LSA startup are located in �HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig� registry key. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $AuthenticationPackageName,

        # The name of the LAN Manager sub-package (NTLM-family protocol name) that was used during logon. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("NTLM V1", "NTLM V2", "LM")]
        [string[]]
        $LmPackageName,

        # IP address of machine from which logon attempt was performed.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $IpAddress,

        # Source port which was used for logon attempt from remote machine.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [int[]]
        $IpPort,

        # The name of the account for which logon was performed
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $UserName,

        # SID of account that reported information about successful logon or invokes it.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $UserSID,

        # Hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID, 
        # for example, 4672(S): Special privileges assigned to new logon.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TargetLinkedLogonId,

        # Hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID, 
        # for example, 4672(S): Special privileges assigned to new logon.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectLogonId,

        # GUID that can help you correlate this event with another event that can contain the same Logon GUID for Example 4769
        # A Kerberos service ticket was requested event on a domain controller. It also can be used for correlation between a 
        # 4624 event and several other events (on the same computer) that can contain the same Logon GUID, Example of this is 
        # “4648: A logon was attempted using explicit credentials” and “4964: Special groups have been assigned to a new logon.”
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $LogonGuid,

        # Subject's domain or computer name. Formats vary, and include the following:
        #
        # * Domain NETBIOS name example: CONTOSO
        # * Lowercase full domain name: contoso.local
        # * Uppercase full domain name: CONTOSO.LOCAL
        # * For some well-known security principals, such as LOCAL SERVICE or ANONYMOUS LOGON, the value of this field is �NT AUTHORITY�.
        # * For local user accounts, this field will contain the name of the computer or device that this account belongs to, for example: �Win81�.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $UserDomain,

        # Specifies the path to the event log files that this cmdlet get events from. Enter the paths to the log files in a comma-separated list, or use wildcard characters to create file path patterns. Function supports files with the .evtx file name extension. You can include events from different files and file types in the same command.
        [Parameter(Mandatory=$true,
                   Position=0,
                   ParameterSetName="file",
                   ValueFromPipelineByPropertyName=$true)]
        [Alias("FullName")]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string[]]
        $Path,


        # Gets events from the event logs on the specified computer. Type the NetBIOS name, an Internet Protocol (IP) address, or the fully qualified domain name of the computer.
        # The default value is the local computer.
        # To get events and event logs from remote computers, the firewall port for the event log service must be configured to allow remote access.
        [Parameter(Mandatory = $true,
                   ValueFromPipelineByPropertyName = $true,
                   ParameterSetName = 'Remote')]
        [string[]]
        $ComputerName,

        # Specifies a user account that has permission to perform this action.
        #
        # Type a user name, such as User01 or Domain01\User01. Or, enter a PSCredential object, such as one generated by the Get-Credential cmdlet. If you type a user name, you will
        # be prompted for a password. If you type only the parameter name, you will be prompted for both a user name and a password.
        [Parameter(Mandatory = $false,
                   ParameterSetName = 'Remote')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        # Specifies the maximum number of events that are returned. Enter an integer. The default is to return all the events in the logs or files.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [int64]
        $MaxEvents,

        # Stsrttime from where to pull events.
        [Parameter(Mandatory = $false)]
        [datetime]
        $StartTime,

        # Stsrttime from where to pull events.
        [Parameter(Mandatory = $false)]
        [datetime]
        $EndTime,

        # Changes the default logic for matching fields from 'and' to 'or'.
        [Parameter(Mandatory = $false)]
        [switch]
        $ChangeLogic,

        # Changes the query action from inclusion to exclusion when fields are matched.
        [Parameter(Mandatory = $false)]
        [switch]
        $Suppress
    )

    begin {

        $boolValues = @{
            '%%1842' = 'Yes'
            '%%1843' = 'No'
        }


        # Impersonation levels.
        $ImpLevels = @{
            '%%1831' = 'Anonymous'
            '%%1832' = 'Identify'
            '%%1833' = 'Impersonate'
            '%%1834' = 'Delegate'
        }

        $Params = $MyInvocation.BoundParameters
        if ($EventLogonType.Count -gt 0) {
            $LogonType = @()
            foreach($ltype in $EventLogonType) {
                switch ($ltype)
                {
                    'Interactive' {$LogonType += 2} 
                    'Network' {$LogonType += 3} 
                    'Batch' {$LogonType += 4}
                    'Service' {$LogonType += 5} 
                    'Unlock' {$LogonType += 7}
                    'NetworkCleartext' {$LogonType += 8}
                    'NewCredentials' {$LogonType += 9}
                    'RemoteInteractive' {$LogonType += 10}
                    'CachedInteractive' {$LogonType += 11}
                    Default {}
                }
            }
            $Params.Remove("EventLogonType")| Out-Null
            $Params.Add("LogonType",$LogonType) | Out-Null
        }

        if ($Params.Keys -contains "UserName") {
            $Params.Remove("UserName") | Out-Null
            $Params.Add('TargetUserName', $UserName) | Out-Null
        }

        if ($Params.Keys -contains "UserSID") {
            $Params.Remove("UserSID") | Out-Null
            $Params.Add('TargetUserSid', $UserSID) | Out-Null
        }

        if ($Params.Keys -contains "UserDomain") {
            $Params.Remove("UserDomain") | Out-Null
            $Params.Add('TargetDomainName', $UserDomain) | Out-Null
        }
    }

    process {
        Search-EventLogEventData -EventId 4624 -ParamHash $Params -Provider "Microsoft-Windows-Security-Auditing" -RecordType "SuccessFulLogon" | ForEach-Object {
            $_.VirtualAccount = $boolValues[$_.VirtualAccount]
            $_.ElevatedToken = $boolValues[$_.ElevatedToken]
            $_.ImpersonationLevel = $ImpLevels[$_.ImpersonationLevel]
            $_
        }

    }

    end {}
}
