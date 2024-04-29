<#
.SYNOPSIS
    Retrieves filtered events from event logs or event log files.

.DESCRIPTION
    The Get-FilteredEvent function retrieves events from event logs or event log files based on specified filters.

.PARAMETER LogName
    Specifies the log name to filter on.

.PARAMETER ProviderName
    Specifies the provider name to filter on.

.PARAMETER Path
    Specifies the path of the EVT or EVTX file to query events from.

.PARAMETER Keywords
    Specifies the keywords of events to filter on.

.PARAMETER Id
    Specifies the EventId of events to filter on.

.PARAMETER Level
    Specifies the level of events to filter on.

.PARAMETER StartTime
    Specifies the StartTime of events to filter on, showing events after this date.

.PARAMETER EndTime
    Specifies the EndTime of events to filter on, showing events before this date.

.PARAMETER UserID
    Specifies the SID of the user to filter on.

.PARAMETER Data
    Specifies the element value under EventData or UserData to filter on.

.PARAMETER SuppressHashFilter
    Specifies a FilterHashtable of events to suppress from the output.

.PARAMETER NamedData
    Specifies the named data fields from UserData or EventData to filter on.

.PARAMETER ComputerName
    Specifies the computer name of hosts to query events from.

.PARAMETER Credential
    Specifies the credentials to use when connecting to remote computers.

.PARAMETER MaxEvents
    Specifies the maximum number of events to return.

.PARAMETER Oldest
    Specifies the oldest event to return.

.PARAMETER ParseData
    Specifies whether to parse the data from UserData or EventData turning named elements in to properties.

.EXAMPLE
    Get-FilteredEvent -LogName "System" -Level 2 -StartTime (Get-Date).AddDays(-1)

    Retrieves events from the "System" log with a level of 2 (Information) that occurred within the last 24 hours.
.EXAMPLE
    ls e:\*security*.evtx -recurse | Get-FilteredEvent -Id 4688 -ParseData

    Retrieves events from all files in the E:\ drive that contain "security" in the file name and returns events with an EventId of 4688.
.NOTES
    Author: Carlos Perez
    Date:   10/10/2021
#>
function Get-FilteredEvent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [String[]]
        $LogName,

        [Parameter(Mandatory=$false)]
        [String[]]
        $ProviderName,

        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [Alias("FullName")]
        [String[]]
        $Path,

        [Parameter(Mandatory=$false)]
        [Long[]]
        $Keywords,

        [Parameter(Mandatory=$false)]
        [Int32[]]
        $Id,

        [Parameter(Mandatory=$false)]
        [Int32[]]
        $Level,

        [Parameter(Mandatory=$false)]
        [DateTime]
        $StartTime,

        [Parameter(Mandatory=$false)]
        [DateTime]
        $EndTime,

        [Parameter(Mandatory=$false)]
        [System.Security.Principal.SecurityIdentifier]
        $UserID,

        [Parameter(Mandatory=$false)]
        [String[]]
        $Data,

        [Parameter(Mandatory=$false)]
        [Hashtable]
        $SuppressHashFilter,

        [Parameter(Mandatory=$false)]
        [Hashtable]
        $NamedData,

        [Parameter(Mandatory=$false)]
        [string]
        $ComputerName,

        [Parameter(Mandatory=$false)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$false)]
        [int32]
        $MaxEvents,

        [Parameter(Mandatory=$false)]
        [switch]
        $Oldest,

        [Parameter(Mandatory=$false)]
        [switch]
        $ParseData
    )

    begin{}
    process{
        $paramSplat = @{}
        $FilterHashTable = @{}
        $IndividualParams = @('ComputerName','Credential','Force','MaxEvens','Oldest', 'Verbose','debug','erroraction',
                            'warningaction','errorvariable','warningvariable','outvariable','outbuffer','pipelinevariable',
                            'whatif','confirm','ParseData')
        $psboundparameters.GetEnumerator() | ForEach-Object {
            if ($null -ne $_.Value -and $IndividualParams -notcontains $_.Key) {
                if ($_.Key -eq "NamedData" -and $_.Value.Count -gt 0) {
                    $namedDataHT = $_.Value
                    $namedDataHT.Keys | ForEach-Object {
                        $FilterHashTable[$_] = $namedDataHT[$_]
                    }
                } elseif ($_.Key -eq "Path") {
                    foreach ($p in $_.value){
                        $resolvedPaths = Resolve-Path -Path $p | Select-Object -ExpandProperty Path
                        $FilterHashTable['Path'] = $resolvedPaths
                    }
                }else {
                    $FilterHashTable[$_.Key] = $_.Value
                }
            } elseif ($null -ne $_.Value -and $IndividualParams -contains $_.Key) {
                if ($_.Key -ne "ParseData") {$paramSplat[$_.Key] = $_.Value}
            }
        }
        $paramSplat['FilterHashTable'] = $FilterHashTable
        if ($ParseData) {
            Get-WinEvent @paramSplat | convertFrom-EventLogRecord
        } else {
            Get-WinEvent @paramSplat
        }
    }
    end{

    }
}


