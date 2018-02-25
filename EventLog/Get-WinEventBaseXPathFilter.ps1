
function Get-WinEventBaseXPathFilter {
    <#
    .SYNOPSIS
        Generate xpath filters for fields on a specified Event Log Entry.
    .DESCRIPTION
        Parses Event Log Entries to make usable Windows Event log
        filtering xpath for Windows Event Filters and Windows Eventlog Forwarding
    .EXAMPLE
        PS C:\> Get-WinEventBaseXPathFilter -EventId 4624 -LogName security

        Parses the first event with id 4624 in the security eventlog.
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        Port of script Written 5/22/2015 – Kurt Falde
        Modified from original to have more accurate filtering on elements with attributes, plus other minor improvements.
    #>
    [CmdletBinding(DefaultParameterSetName='EventID')]
    [OutputType([String])]
    Param (
        # Event ID to create filter on. Will select first event found in the specified log
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName='EventId')]
        [int]
        $EventId,

        # The specific EventRecord ID to parse in the specified log.
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0,
                   ParameterSetName='EventRecordID')]
        [int]
        $EventRecordID,

        # Specify the log name to retrieve the event information from.
        [string]
        $LogName
    )

    Begin {
        switch ($PSCmdlet.ParameterSetName) {
            'EventID' { $xpath =  "*[System[EventID=$EventId]]" }
            'EventRecordID' { $xpath =  "*[System[EventRecordID=$EventRecordID]]" }
            Default {}
        }

    }
    Process
    {
        $xpath
        $EventToParse = Get-WinEvent -LogName "$($LogName)" -FilterXPath "$xpath" -ErrorAction stop -MaxEvents 1
        [xml]$EventToParsexml = $EventToParse.ToXml()
        $nodes = $EventToParsexml | Select-Xml -XPath './/*'
        Foreach ($node in $nodes){

            #Parse Nodes that are not empty, not null and do not have attributes
            if (($node.node.IsEmpty -eq $false) -and ($node.node.'#text' -ne $null) -and ($node.node.HasAttributes -eq $false)){

                $Ntext = $node.Node.'#text'
                #write-Host $Ntext
                $Ntext = $Ntext.Replace("`n", "&#xD;&#xA;").Replace("`t", "&#x09;")
                #write-host $Ntext
                $Nname = $node.Node.Name
                #write-host $Nname
                if($node.node.Parentnode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.Parentnode.name)[($Nname=$Ntext)]]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[($Nname=$Ntext)]]]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Parentnode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.Parentnode.name)[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[($Nname=$Ntext)]]]]"
                }
            }

            #Parses nodes that are not empty, not null and have attributes
            if (($node.node.IsEmpty -eq $false) -and ($node.node.'#text' -ne $null) -and ($node.node.HasAttributes -eq $true)){
                $Ntext = $node.Node.'#text'
                $Ntext = $Ntext.Replace("`n", "&#xD;&#xA;").Replace("`t", "&#x09;")
                $Nname = $node.Node.Name
                if($node.node.Parentnode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.Parentnode.name)[$($node.node.LocalName)[@Name='$Nname']='$Ntext']]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[($Nname=$Ntext)]]]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Parentnode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.Parentnode.name)[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[($Nname=$Ntext)]]]]"
                }
                }

            #Parses nodes that are empty/null but have attributes
            if (($node.node.IsEmpty -ne $false) -and ($node.node.'#text' -eq $null) -and ($node.node.HasAttributes -eq $true)){
                $AttributeText = ""
                $Attributes = $node.node.Attributes
                Foreach($Attribute in $Attributes){
                    $AttrName = $Attribute.Name
                    $AttrText = $Attribute.'#text'
                    $AttributeText += "@$AttrName='$AttrText' and "
                }
                $AttributeText = $AttributeText.TrimEnd(" and ")
                $Nname = $node.Node.Name
                if($node.node.Parentnode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.Parentnode.name)[$($node.node.LocalName)[$AttributeText]]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[$AttributeText]]]"
                }
                if($node.node.Parentnode.ParentNode.ParentNode.Parentnode.Name -eq "Event"){
                    "*[$($node.node.ParentNode.Parentnode.Parentnode.name)[$($node.node.ParentNode.Parentnode.name)[$($node.node.parentnode.name)[$AttributeText]]]]"
                }
            }
        }
        $StringOut
    }
    End { }
}