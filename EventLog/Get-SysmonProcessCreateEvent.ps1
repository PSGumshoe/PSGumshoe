
function Get-SysmonProcessCreateEvent {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> $OfficeImages = @('C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE',
        'C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE',
        'C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE',
        'C:\Program Files\Microsoft Office\root\Office16\GRAPH.EXE',
        C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE')

        PS C:\> Get-SysmonProcessCreateEvent -ParentImage $OfficeImages

        Find all processes created by Office applications.
    .EXAMPLE
        PS C:\> Get-SysmonProcessCreateEvent -ProcessId 426128 | select "processguid","utctime","image"

        ProcessGuid                            UtcTime                 Image
        -----------                            -------                 -----
        {278123BE-DFF1-5A95-0000-00106E3B1639} 2018-02-27 22:47:13.439 C:\Program Files\Git\cmd\git.exe
        {278123BE-DE90-5A95-0000-0010648A0C39} 2018-02-27 22:41:20.318 C:\Program Files\Git\mingw64\bin\git.exe
        {278123BE-709D-5A95-0000-00100437E438} 2018-02-27 14:52:13.340 C:\Program Files\Git\mingw64\bin\git.exe

        Check for PID re-use.

    .EXAMPLE
        PS C:\> $grouped = Get-SysmonProcessCreateEvent -Image "C:\Windows\system32\rundll32.exe" | Group-Object -Property "commandline"
        PS C:\> $grouped | Select-Object -Property name

        Name
        ----
        "C:\WINDOWS\System32\rundll32.exe" "C:\WINDOWS\System32\winethc.dll",ForceProxyDetectionOnNextRun
        C:\WINDOWS\system32\rundll32.exe Startupscan.dll,SusRunTask
        rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh

        Check for unique commandline instances for a given image.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        Sysmon.EventRecord.ProcessCreate
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        # Log name for where the events are stored.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string]
        $LogName = 'Microsoft-Windows-Sysmon/Operational',

        # Process Id
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ProcessId,

        # Process Guid
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ProcessGuid,

        # Image of process full path.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Image,

        # Parent Image full path.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ParentImage,

        # Command Line.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $CommandLine,

        # Current Directory.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $CurrentDirectory,

        # User the process was ran under.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $User,

        # Logon GUID.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $LogonGuid,

        # Logon Id.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $LogonId,

        # Terminal session  Id.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $TerminalSessionId,

        # Process Integrity level.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $IntegrityLevel,

        # Imange hash.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Hashes,

        # Parent process GUID.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ParentProcessGuid,

        # Parant process Id.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ParentProcessId,

        # Parent process command line.
        [Parameter(Mandatory = $false,
                   ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $ParentCommandLine,

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
        $ChangeLogic
    )

    begin {}

    process {
        Search-SysmonEvent -EventId 1 -ParamHash $MyInvocation.BoundParameters

    }

    end {}
}