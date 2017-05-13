<#
.SYNOPSIS
    Get the security permissions for a given DN.
.DESCRIPTION
    Get the security permissions for a given DN.
.EXAMPLE
    PS C:\> Get-DSObjectAcl -DistinguishedName "DC=labcorp,DC=local" | where {$_.controlaccessname -eq 'DS-Replication-Synchronize'}
    Find all permissions on the root of the domain for DS-Replication-Synchronize permission.
.OUTPUTS
    System.DirectoryServices.ActiveDirectoryAccessRule
#>
function Get-DSObjectAcl {
    [CmdletBinding(DefaultParameterSetName='Current')]
    param (
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
        $Credential,

        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $false)]
        [Parameter(ParameterSetName = 'Alternate',
                   Mandatory = $false)]
        [Parameter(ParameterSetName = 'Current',
                   Mandatory = $false)]
        [Parameter(Mandatory=$false,
            HelpMessage='Specifies the available options for examining security information of a directory object')]
        [ValidateSet('Dacl',
                     'Group',
                     'Owner',
                     'Sacl')]
        [string[]]
        $SecurityMask = @('Dacl',
                     'Group',
                     'Owner',
                     'Sacl'),

        # Distinguished Name of AD object.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Alternate',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Current',
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [string]
        $DistinguishedName
    )
    
    begin {

    }
    
    process {
        $filter = "(distinguishedname=$($DistinguishedName))"
        switch ( $PSCmdlet.ParameterSetName ) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -SearchRoot $searchRoot -Credential $Credential -Filter $filter -SecurityMask $SecurityMask

                } else {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -Filter $filter -SecurityMask $SecurityMask
                }
            }
            'Alternate' {$objSearcher = Get-DSDirectorySearcher -Credential $Credential -Filter $filter -SecurityMask $SecurityMask}
            'Current' {$objSearcher = Get-DSDirectorySearcher -Filter $filter -SecurityMask $SecurityMask}
            Default {}
        }

        $objSearcher.findall() | ForEach-Object {
            $DN = $_.properties.distinguishedname[0]
            $secds = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $Desc = $_.Properties.ntsecuritydescriptor[0]
            $secds.SetSecurityDescriptorBinaryForm($Desc)
            $secds.Access | ForEach-Object {
                $_ | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $DN
                try {
                    $_ | Add-Member -MemberType NoteProperty -Name 'ControlAccessName' -Value $GuidMap["$($_.ObjectType)"]
                } catch {
                    $_ | Add-Member -MemberType NoteProperty -Name 'ControlAccessName' -Value ''
                }
                $_
            }

        }
    }
    
    end {
    }
}