function Get-SysmonCreateNamedPipe {
    <#
    .SYNOPSIS
        Get Sysmon Named Pipe Creation events (EventId 17).
    .DESCRIPTION
        This event generates when a named pipe is created. Malware often uses named pipes for interprocess communication.
    .EXAMPLE
        PS C:\> Get-SysmonCreatePipe -ComputerName wec1.contoso.com -LogName "Forwarded Events"
        Query remote Windows Event Collector server for Named Pipe creation events.

    .EXAMPLE

        PS C:\> Get-SysmonCreateNamedPipe  -RuleName "PSExec Execution"

        EventId       : 17
        EventType     : CreatePipe
        Computer      : DESKTOP-3MD5SJ5
        EventRecordID : 1390
        RuleName      : PSExec Execution
        UtcTime       : 2019-07-26 21:29:58.188
        ProcessGuid   : {1FE293DA-70D6-5D3B-0000-00105413F501}
        ProcessId     : 1072
        PipeName      : \PSEXESVC-DESKTOP-3MD5SJ5-6620-stderr
        Image         : C:\Windows\PSEXESVC.exe

        EventId       : 17
        EventType     : CreatePipe
        Computer      : DESKTOP-3MD5SJ5
        EventRecordID : 1389
        RuleName      : PSExec Execution
        UtcTime       : 2019-07-26 21:29:58.187
        ProcessGuid   : {1FE293DA-70D6-5D3B-0000-00105413F501}
        ProcessId     : 1072
        PipeName      : \PSEXESVC-DESKTOP-3MD5SJ5-6620-stdout
        Image         : C:\Windows\PSEXESVC.exe

        EventId       : 17
        EventType     : CreatePipe
        Computer      : DESKTOP-3MD5SJ5
        EventRecordID : 1388
        RuleName      : PSExec Execution
        UtcTime       : 2019-07-26 21:29:58.187
        ProcessGuid   : {1FE293DA-70D6-5D3B-0000-00105413F501}
        ProcessId     : 1072
        PipeName      : \PSEXESVC-DESKTOP-3MD5SJ5-6620-stdin
        Image         : C:\Windows\PSEXESVC.exe

        EventId       : 17
        EventType     : CreatePipe
        Computer      : DESKTOP-3MD5SJ5
        EventRecordID : 1386
        RuleName      : PSExec Execution
        UtcTime       : 2019-07-26 21:29:58.058
        ProcessGuid   : {1FE293DA-70D6-5D3B-0000-00105413F501}
        ProcessId     : 1072
        PipeName      : \PSEXESVC
        Image         : C:\Windows\PSEXESVC.exe

        Find events for rule name "PSExec Execution"
    .INPUTS
        System.IO.FileInfo
        System.String
    .OUTPUTS
        Sysmon.EventRecord.PipeCreated
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        # Log name for where the events are stored.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string]
        $LogName = 'Microsoft-Windows-Sysmon/Operational',

        # Unique GUID for the process that created the named pipe.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ProcessGuid,

        # PID of process that created the named pipe.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ProcessId,

        # Full path of process image that created the named pipe.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Image,

        # Name given by the process to the named pipe.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $PipeName,

        # Rule Name for filter that generated the event.
        [Parameter(Mandatory = $false)]
        [string[]]
        $RuleName,

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

        # Changes the default logic for matching between fields from 'and' to 'or'.
        [Parameter(Mandatory = $false)]
        [switch]
        $ChangeLogic,

        # Changes the query action from inclusion to exclusion when fields are matched.
        [Parameter(Mandatory = $false)]
        [switch]
        $Suppress
    )

    begin {}

    process {
        Search-SysmonEvent -EventId 17 -ParamHash $MyInvocation.BoundParameters

    }

    end {}
}