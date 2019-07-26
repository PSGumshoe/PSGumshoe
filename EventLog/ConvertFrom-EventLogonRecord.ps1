function ConvertFrom-EventLogonRecord {
    <#
    .SYNOPSIS
        Function to turn EventLog4624 successful logon event in to a flat object. 
    .DESCRIPTION
        Function to turn EventLog4624 successful logon event in to a flat object. 
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        PSObject
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        # Event Log Record Object
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
        $Event
    )
    begin {
        
    }

    process {
        [xml]$evtxml = $Event.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $ProcInfo['TimeCreated'] = [datetime]$evtXml.Event.System.TimeCreated.SystemTime
        $evtxml.Event.EventData.Data | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj.pstypenames[0] = 'Event.SuccessfulLogon'
        $Obj
    }

    end {}
}
