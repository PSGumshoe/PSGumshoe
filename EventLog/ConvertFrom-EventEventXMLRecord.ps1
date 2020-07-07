function ConvertFrom-EventEventXMLRecord {
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
        $evtxml.Event.UserData.EventXML.ChildNodes | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj
    }

    end {}
}