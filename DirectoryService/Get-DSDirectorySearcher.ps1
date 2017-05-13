<#
.SYNOPSIS
    Get a diresctory searcher object fro a given domain.
.DESCRIPTION
    Get a diresctory searcher object fro a given domain.
.EXAMPLE
    C:\PS> $ADSearcher = Get-DSDirectorySearcher -Filter '(&(objectCategory=computer)(servicePrincipalName=MSSQLSvc*))'
    Create a DirectorySearcher object with a filter for searching for all computers with a servicePrincipalName for Microsoft SQL Server.
.OUTPUTS
    System.DirectoryServices.DirectorySearcher
#>
function Get-DSDirectorySearcher {
    [CmdletBinding(DefaultParameterSetName='Current')]
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
        $Credential,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]
        $Limit = 1000,
        
        [Parameter(Mandatory=$false)]
        [string]
        $SearchRoot,
        
        [Parameter(Mandatory=$false)]
        [string]
        $Filter,
        
        [Parameter(Mandatory=$false)]
        [int]
        $PageSize = 100,
        
        [Parameter(Mandatory=$false,
        HelpMessage='Scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree',
                     'OneLevel',
                     'Base')]
        [string]
        $SearchScope = 'Subtree',
        
        [Parameter(Mandatory=$false,
        HelpMessage='Specifies the available options for examining security information of a directory object')]
        [ValidateSet('None',
                     'Dacl',
                     'Group',
                     'Owner',
                     'Sacl')]
        [string[]]
        $SecurityMask = 'None',
        
        [Parameter(Mandatory=$false,
        HelpMessage='Whether the search should also return deleted objects that match the search filter.')]
        [switch]
        $TombStone
    )
    
    begin {
    }
    
    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot.Length -gt 0) {
                    $domObj = Get-DSDirectoryEntry -ComputerName $ComputerName -DistinguishedName $searchRoot -Credential $Credential

                } else {
                    $domObj = Get-DSDirectoryEntry -ComputerName $ComputerName -Credential $Credential
                }
                
             }
            'Alternate' {
                if ($searchRoot.Length -gt 0) {
                    $domObj = Get-DSDirectoryEntry -Credential $Credential -DistinguishedName $searchRoot
                } else {
                    $domObj = Get-DSDirectoryEntry -Credential $Credential
                }
            }
            'Current' {
                if ($searchRoot.Length -gt 0) {
                    $domObj = Get-DSDirectoryEntry -DistinguishedName $searchRoot
                } else {
                    $domObj = Get-DSDirectoryEntry
                }
            }
            Default {}
        }
        $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $domObj
        $objSearcher.SizeLimit = $Limit
        $objSearcher.PageSize = $PageSize
        $objSearcher.SearchScope = $SearchScope
        $objSearcher.Tombstone = $TombStone
        $objSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]$SecurityMask
        if ($Filter) {
            $objSearcher.Filter = $Filter
        }
        $objSearcher
    }
    
    end {
    }
}