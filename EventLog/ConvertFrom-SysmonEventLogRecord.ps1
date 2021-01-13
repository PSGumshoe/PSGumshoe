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
        $Event
    )
    begin {
        $EventIdtoType = @{
            '1' = 'ProcessCreate'
            '2' = 'FileCreateTime'
            '3' = 'NetworkConnect'
            '5' = 'ProcessTerminate'
            '6' = 'DriverLoad'
            '7' = 'ImageLoad'
            '8' = 'CreateRemoteThread'
            '9' = 'RawAccessRead'
            '10' = 'ProcessAccess'
            '11' = 'FileCreate'
            '12' = 'RegistryAddOrDelete'
            '13' = 'RegistryValueSet'
            '14' = 'RegistryRename'
            '15' = 'FileCreateStreamHash'
            '16' = 'ConfigChange'
            '17' = 'PipeCreated'
            '18' = 'PipeConnected'
            '19' = 'WmiFilter'
            '20' = 'WmiConsumer'
            '21' = 'WmiBinding'
            '22' = 'DNSQuery'
            '23' = 'FileDelete'
            '24' = 'ClipboardChange '
            '25' = 'ProcessTamper'
            '255' = 'Error'
        }
    }

    process {
        [xml]$evtxml = $Event.toxml()
        $ProcInfo = [ordered]@{}
        $ProcInfo['EventId'] = $evtxml.Event.System.EventID
        $ProcInfo['EventType'] = "$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
        $ProcInfo['Computer'] = $evtxml.Event.System.Computer
        $ProcInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
        $evtxml.Event.EventData.Data | ForEach-Object {
            $ProcInfo[$_.name] = $_.'#text'
        }
        $Obj = New-Object psobject -Property $ProcInfo
        $Obj.pstypenames[0] = "Sysmon.EventRecord.$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
        $Obj
    }

    end {}
}