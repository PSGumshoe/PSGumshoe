<#
.SYNOPSIS
    Exports event log data to a CSV file.

.DESCRIPTION
    This function takes input objects representing event log entries and exports them to a CSV file.
    Each input object should have properties for 'Computer' and 'EventId'.

.PARAMETER InputObject
    Specifies the input objects representing event log entries.

.INPUTS
    PSObject
    You can pipe objects representing event log entries to this function.

.OUTPUTS
    None

.EXAMPLE
    Get-EventLog -LogName System | Export-EventLogToCSV

    This example gets event log entries from the 'System' log and exports them to a CSV file.

.NOTES
    Author: Carlos Perez
    Date:   10/10/2021
#>

function Export-EventLogToCSV {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [PSObject[]]$InputObject,

        [Parameter(Mandatory = $true, 
        HelpMessage = "Specify the path where to store the CSV files.")]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [string]$OutputPath
    )

    begin{
        $createdFiles = @()
    }
    process {
        foreach ($item in $InputObject) {
            $computerName = $item.Computer
            $eventId = $item.EventId

            $csvFileName = "EventLog_${computerName}_${eventId}.csv"
            $csvFilePath = Join-Path -Path $OutputPath -ChildPath $csvFileName
            if ($csvFilePath -notin $createdFiles) {
                Write-Verbose "Exporting events with Id $($eventId) for host $($computerName) to $csvFilePath"
                $createdFiles += $csvFilePath
            }
            $item | Export-Csv -Path $csvFilePath -NoTypeInformation -Append
        }
    }
}

