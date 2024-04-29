function ConvertFrom-EventLogRecord {
    <#
    .SYNOPSIS
        Function to turn an EventLog Record in to a flat object. 
    .DESCRIPTION
        Function to turn an EventLog Record in to a flat object. 
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        PSObject
    .NOTES
        Author: Carlos Perez, carlos_perez[at]darkoperator.com
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
        $EventInfo = [ordered]@{}
        $evtxml.Event.System.ChildNodes | foreach-object {
            if ($_.psobject.properties.name -match "#text"){
                $EventInfo[$_.name] = $_."#text"                
            }
        }
        $EventInfo['TimeCreated'] = [datetime]$evtXml.Event.System.TimeCreated.SystemTime
        $EventInfo['TimeCreatedUTC'] = $evtXml.Event.System.TimeCreated.SystemTime
        $EventInfo['ProviderName'] = $evtXml.Event.System.Provider.Name
        $EventInfo['ProviderGuid'] = $evtXml.Event.System.Provider.Guid

        if ($null -ne $evtxml.Event.EventData.Data) {
            $evtxml.Event.EventData.Data | ForEach-Object {
                $EventInfo[$_.name] = $_.'#text'
            }
        }

        if ($null -ne $evtxml.Event.UserData.Data) {
            $evtxml.Event.UserData.Data | ForEach-Object {
                $EventInfo[$_.name] = $_.'#text'
            }
        }
        $Obj = New-Object psobject -Property $EventInfo
        $Obj
    }

    end {}
}