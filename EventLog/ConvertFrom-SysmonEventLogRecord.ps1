function ConvertFrom-SysmonEventLogRecord {
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
    [CmdletBinding()]
    param (
        # Event Log Record Object
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
        $Event,

        # Sysmon Event Record Type
        [Parameter(Mandatory = $true)]
        [string]
        $RecordType
    )
    begin {}

    process {
        [xml]$evtxml = $Event.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $evtxml.Event.EventData.Data | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj.pstypenames[0] = "Sysmon.EventRecord.$( $RecordType )"
        $Obj
    }

    end {}
}