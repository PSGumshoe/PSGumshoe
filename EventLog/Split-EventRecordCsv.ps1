function Split-EventRecordCsv {
    <#
    .SYNOPSIS
        Splits Windows Event Log records into separate CSV files based on EventID and Provider.

    .DESCRIPTION
        Split-EventRecordCsv accepts EventLogRecord objects via pipeline and creates separate CSV files
        for each unique combination of EventID and Provider. Files are named using UTC timestamp,
        EventID, and Provider name. The function uses ConvertFrom-EventLogRecord to process each event
        before saving to CSV.

    .PARAMETER EventRecord
        The EventLogRecord object to process. Accepts pipeline input.

    .PARAMETER Path
        Optional. The output directory for CSV files. Defaults to current directory.

    .EXAMPLE
        Get-WinEvent -LogName System -MaxEvents 100 | Split-EventRecordCsv
        Creates CSV files in current directory for each unique EventID/Provider combination found in the last 100 System log events.

    .EXAMPLE
        Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddHours(-1)} | Split-EventRecordCsv -Path "C:\Logs"
        Processes all Application log events from the last hour, saving CSV files to C:\Logs.

    .EXAMPLE
        $events = Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 }
        $events | Split-EventRecordCsv -Path "D:\AuditLogs"
        Processes all successful logon events (ID 4624) from Security log, saving to D:\AuditLogs.

    .NOTES
        Filename format: yyyyMMdd_HHmmss_EventID_ProviderName.csv
        Special characters and spaces in provider names are replaced with underscores
         Author: Carlos Perez, carlos_perez[at]darkoperator.com
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$EventRecord,

        [Parameter(Mandatory=$false)]
        [string]$Path = (Get-Location).Path
    )

    begin {
        # Create UTC timestamp for file naming
        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
        
        # Hashtable to track unique combinations of EventID and Provider
        $fileHandlers = @{}
    }

    process {
        # Clean provider name by replacing special chars and spaces with underscore
        $cleanProvider = $EventRecord.ProviderName -replace '[\\/:*?"<>|\s]', '_'
        
        # Create unique filename
        $fileName = "{0}_{1}_{2}.csv" -f $EventRecord.Id, $cleanProvider, $timestamp
        $fullPath = Join-Path -Path $Path -ChildPath $fileName

        # Check if we've already created a file for this EventID/Provider combination
        if (-not $fileHandlers.ContainsKey($fullPath)) {
            # Add to tracking hashtable
            $fileHandlers[$fullPath] = $true
        }

        # Convert and export the record
        $EventRecord | ConvertFrom-EventLogRecord | Export-Csv -Path $fullPath -NoTypeInformation -Append
    }

    end {
        Write-Verbose "Processing complete. Created $($fileHandlers.Count) CSV files."
    }
}