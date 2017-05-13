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
function Get-DSReplicationAttribute {
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        # Domain controller.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,
        
        # Credentials to use connection.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Alternate',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        # Object DistinguishedName to get replication attribute data for.
        [Parameter(Mandatory = $true)]
        [Alias('DistinguishedName')]
        [string]
        $ObjectDN,

        # Include linked members
        [Parameter(Mandatory = $false)]
        [switch]
        $IncludeMember
    )
    
    Begin {
    }
    
    Process {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -searchRoot $ObjectDN
            }
            'Alternate' {$objSearcher = Get-DSDirectorySearcher -Credential $Credential -searchRoot $ObjectDN}
            'Current' {$objSearcher = Get-DSDirectorySearcher -searchRoot $ObjectDN}
            Default {}
        }
        $objSearcher.Tombstone = $true
        $objSearcher.propertiestoload.add("*") | Out-Null
        $objSearcher.propertiestoload.add("msDS-ReplAttributeMetaData") | Out-Null
        $objSearcher.propertiestoload.add("msDS-ReplValueMetaData") | Out-Null
        $objSearcher.SecurityMasks = [DirectoryServices.SecurityMasks] @('Dacl',
                     'Group',
                     'Owner',
                     'Sacl')
        $obj = $objSearcher.findone()

        $xml = "<root>" + $obj.properties."msds-replattributemetadata" + "</root>"
        $xml = [xml]$xml
        foreach ($attrib in $xml.root.DS_REPL_ATTR_META_DATA) {
            switch ($attrib.pszAttributeName) {

                'objectClass' { $attribValue = $obj.properties["$($attrib.pszAttributeName)"][1] }
                'objectguid' { $attribValue = [guid]$obj.properties["$($attrib.pszAttributeName)"][0]}
                'objectsid' {$attribValue = "$(&{$sidobj = [byte[]]"$($obj.properties["$($attrib.pszAttributeName)"][0])".split(' ');
                    $sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; 
                    $sid.Value})"}
                'ntsecuritydescriptor' { 
                    $secds = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $Desc = $obj.Properties['ntsecuritydescriptor'][0]
                    $secds.SetSecurityDescriptorBinaryForm($Desc)
                    $attribValue = $secds
                }
                Default {$attribValue = $obj.properties["$($attrib.pszAttributeName)"][0] }
            }
            $objProps = [ordered]@{}
            $objProps['AttributeName'] = $attrib.pszAttributeName
            $objProps['AttributeValue'] = $attribValue
            $objProps['Version']= $attrib.dwVersion
            $objProps['FirstOriginatingCreateTime'] = if ($attrib.ftimeCreated) { [datetime]$attrib.ftimeCreated }
            $objProps['LastOriginatingChangeTime'] = if ($attrib.ftimeLastOriginatingChange) { [datetime]$attrib.ftimeLastOriginatingChange }
            $objProps['LastOriginatingDeleteTime']= if ($attrib.ftimeDeleted) { [datetime]$attrib.ftimeDeleted }
            $objProps['IsLinkValue'] = $false
            $objProps['LastOriginatingChangeDirectoryServerIdentity'] = $attrib.pszLastOriginatingDsaDN
            $objProps['LastOriginatingChangeDirectoryServerInvocationId'] = $attrib.uuidLastOriginatingDsaInvocationID
            $objProps['LastOriginatingChangeUsn']= $attrib.usnOriginatingChange
            $objProps['LocalChangeUsn']= $attrib.usnLocalChange
            $objProps['Object']= $ObjectDN
            $objProps['Server']= $ComputerName
            New-Object -TypeName psobject -Property $objProps
        }

        if ($IncludeMember) {
            Write-Verbose -Message 'Including Memeber information.'
            $xmlMember = "<root>" + ($obj.properties."msds-replvaluemetadata") + "</root>"
            $xmlMember = [xml]$xmlMember
            foreach ($attrib in $xmlMember.root.DS_REPL_VALUE_META_DATA) {
                $objProps = [ordered]@{}
                $objProps['AttributeName'] = $attrib.pszAttributeName
                $objProps['AttributeValue'] = $attrib.pszObjectDn
                $objProps['Version']= $attrib.dwVersion
                $objProps['FirstOriginatingCreateTime'] = if ($attrib.ftimeCreated) { [datetime]$attrib.ftimeCreated }
                $objProps['LastOriginatingChangeTime'] = if ($attrib.ftimeLastOriginatingChange) { [datetime]$attrib.ftimeLastOriginatingChange }
                $objProps['LastOriginatingDeleteTime']= if ($attrib.ftimeDeleted) { [datetime]$attrib.ftimeDeleted }
                $objProps['IsLinkValue'] = $true
                $objProps['LastOriginatingChangeDirectoryServerIdentity'] = $attrib.pszLastOriginatingDsaDN
                $objProps['LastOriginatingChangeDirectoryServerInvocationId'] = $attrib.uuidLastOriginatingDsaInvocationID
                $objProps['LastOriginatingChangeUsn']= $attrib.usnOriginatingChange
                $objProps['LocalChangeUsn']= $attrib.usnLocalChange
                $objProps['Object']= $ObjectDN
                $objProps['Server']= $ComputerName
                New-Object -TypeName psobject -Property $objProps
            }
        }
    }
    
    End {
    }
}