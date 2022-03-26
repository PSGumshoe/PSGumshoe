function Get-EventProcessCreate {
    <#
    .SYNOPSIS
        Gets process create details from event 4688
    .DESCRIPTION
        Gets process create details from event 4688
    .EXAMPLE
        PS C:\> Get-EventProcessCreate -TokenElevationType "%%1937"
        Gets all processes started with a full token
    .EXAMPLE
        PS C:\> Get-EventProcessCreate -CommandLine "C:\windows\temp\evil.exe"
        Gets information about the process that executed the evil.exe file
    .EXAMPLE
        PS C:\> Get-EventProcessCreate -NewProcessName "C:\windows\system32\svchost.exe" | Sort-Object -Property CommandLine -Unique | ft CommandLine -AutoSize
        Gets all unique command line parameters for the svchost.exe process
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

        # SID of account that requested the "create process" operation. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectUserSid,

        # The name of the account that requested the "create process" operation.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectUserName,

        # Subjects domain or computer name. Formats vary, and include the following:
        # * Domain NETBIOS name example: CONTOSO
        # * Lowercase full domain name: contoso.local
        # * Uppercase full domain name: CONTOSO.LOCAL
        # * For some well-known security principals, such as LOCAL SERVICE or ANONYMOUS LOGON, the value of this field is "NT AUTHORITY".
        # * For local user accounts, this field will contain the name of the computer or device that this account belongs to, for example: "Win81".
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectDomainName,

        # Hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID, for example, "4624: An account was successfully logged on.""
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $SubjectLogonId,

        # SID of target account. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TargetUserSid,

        # The name of the target account.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TargetUserName,

        # Target account’s domain or computer name. 
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TargetDomainName,

        # Hexadecimal value that can help you correlate this event with recent events that might contain the same Logon ID
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TargetLogonId,

        # SID of integrity label which was assigned to the new process.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Untrusted", "Low_Integrity", "Medium_Integrity", "Medium_High_Integrity",
                     "High_Integrity", "System_Integrity", "Protected_Process")]
        [string[]]
        $MandatoryLabel,

        # Process to search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $NewProcessName,

        # ProcessID to search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $NewProcessID,

        # ParentProcess to Search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ParentProcessName,

        # ProcessID to Search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ProcessID,

        # CommandLine to Search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $CommandLine,

        # TokenElevationType to Search
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TokenElevationType,



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
        $Params = $MyInvocation.BoundParameters

        if ($MandatoryLabel.Count -gt 0) {
            $MandatoryLabels = @()
            foreach($ltype in $MandatoryLabel) {
                switch ($ltype)
                {

                    "Untrusted" {$MandatoryLabels + 'S-1-16-0'}
                    "Low_Integrity" {$MandatoryLabels + 'S-1-16-4096'}
                    "Medium_Integrity" {$MandatoryLabels + 'S-1-16-8192'}
                    "Medium_High_Integrity" {$MandatoryLabels + 'S-1-16-8448'}
                    "High_Integrity" {$MandatoryLabels + 'S-1-16-12288'}
                    "System_Integrity" {$MandatoryLabels + 'S-1-16-16384'}
                    "Protected_Process" {$MandatoryLabels + 'S-1-16-20480'}
                    Default {}
                }
            }
            $Params.Remove("MandatoryLabel")| Out-Null
            $Params.Add("MandatoryLabel",$MandatoryLabels) | Out-Null
        }
        
    }

    process {
        Search-EventLogEventData -EventId 4688 -ParamHash $Params -Provider "Microsoft-Windows-Security-Auditing" -RecordType "ProcessDetails"
    }

    end {}
}
