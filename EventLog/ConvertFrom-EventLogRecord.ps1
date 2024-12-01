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
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
        $Event
    )
    begin {
        function Process-EventDataElement {
            param(
                [Parameter(Mandatory)]
                [System.Xml.XmlNode]$Node,
                
                [Parameter(Mandatory)]
                [System.Collections.Specialized.OrderedDictionary]$EventInfo
            )

            if ($Node.NodeType -eq 'Element') {
                #Write-Verbose "Processing element: $($Node.Name)"

                # Handle elements with Name attribute
                if ($Node.HasAttributes -and $null -ne $Node.Attributes['Name']) {
                    $key = $Node.Attributes['Name'].Value
                    $uniqueKey = $key
                    $counter = 1
                    while ($EventInfo.Contains($uniqueKey)) {
                        $uniqueKey = "${key}_$counter"
                        $counter++
                    }
                    #Write-Verbose "Adding named element '$uniqueKey' with value '$($Node.InnerText.Trim())'"
                    $EventInfo[$uniqueKey] = $Node.InnerText.Trim()
                }
                # Handle elements without Name attribute
                elseif ($Node.InnerText -and $Node.ChildNodes.Count -eq 1 -and $Node.ChildNodes[0].NodeType -eq 'Text') {
                    $key = $Node.Name
                    $uniqueKey = $key
                    $counter = 1
                    while ($EventInfo.Contains($uniqueKey)) {
                        $uniqueKey = "${key}_$counter"
                        $counter++
                    }
                    #Write-Verbose "Adding element '$uniqueKey' with value '$($Node.InnerText.Trim())'"
                    $EventInfo[$uniqueKey] = $Node.InnerText.Trim()
                }

                # Handle non-xmlns attributes for elements without Name attribute
                if ($Node.HasAttributes) {
                    foreach ($attr in $Node.Attributes) {
                        if ($attr.Name -notmatch '^xmlns' -and $attr.Name -ne 'Name') {
                            $key = $attr.Name
                            $uniqueKey = $key
                            $counter = 1
                            while ($EventInfo.Contains($uniqueKey)) {
                                $uniqueKey = "${key}_$counter"
                                $counter++
                            }
                            #Write-Verbose "Adding attribute '$uniqueKey' with value '$($attr.Value)'"
                            $EventInfo[$uniqueKey] = $attr.Value
                        }
                    }
                }

                # Process child elements
                foreach ($childNode in $Node.ChildNodes) {
                    if ($childNode.NodeType -eq 'Element') {
                        Process-EventDataElement -Node $childNode -EventInfo $EventInfo
                    }
                }
            }
        }
    }

    process {
        [xml]$evtxml = $Event.toxml()
        $EventInfo = New-Object System.Collections.Specialized.OrderedDictionary
        
        # Process System section
        $evtxml.Event.System.ChildNodes | ForEach-Object {
            if ($_.psobject.properties.name -match "#text") {
                $EventInfo[$_.name] = $_."#text"                
            }
        }
        
        # Add standard system fields
        $EventInfo['TimeCreated'] = [datetime]$evtXml.Event.System.TimeCreated.SystemTime
        $EventInfo['TimeCreatedUTC'] = $evtXml.Event.System.TimeCreated.SystemTime
        $EventInfo['ProviderName'] = $evtXml.Event.System.Provider.Name
        $EventInfo['ProviderGuid'] = $evtXml.Event.System.Provider.Guid
        $EventInfo['ProcessID'] = $evtXml.Event.System.Execution.ProcessID
        $EventInfo['ThreadID'] = $evtXml.Event.System.Execution.ThreadID
        $EventInfo['SecurityID'] = $evtxml.Event.System.Security.UserID

        # Process EventData recursively if present
        if ($null -ne $evtxml.Event.EventData) {
            foreach ($userDataChild in $evtxml.Event.EventData.ChildNodes) {
                if ($userDataChild.NodeType -eq 'Element') {
                    Process-EventDataElement -Node $userDataChild -EventInfo $EventInfo
                }
            }
        }

        # Process UserData recursively if present
        if ($null -ne $evtxml.Event.UserData) {
            #Write-Verbose "Processing UserData"
            #Write-Verbose "UserData children count: $($evtxml.Event.UserData.ChildNodes.Count)"
            foreach ($userDataChild in $evtxml.Event.UserData.ChildNodes) {
                if ($userDataChild.NodeType -eq 'Element') {
                    Process-EventDataElement -Node $userDataChild -EventInfo $EventInfo
                }
            }
        }

        #Write-Verbose "Final EventInfo keys:"
        #$EventInfo.Keys | ForEach-Object { Write-Verbose $_ }

        # Create and output the object
        $Obj = New-Object psobject -Property $EventInfo
        $Obj | Select-Object *
    }

    end {}
}