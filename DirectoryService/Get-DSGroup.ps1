<#
.SYNOPSIS
    Get group objects in a given directory service.
.DESCRIPTION
    Get group objects in a given directory service.
.EXAMPLE
    C:\PS> <example usage>
    Explanation of what the example does
.NOTES
General notes
#>
function Get-DSGroup {
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
        $Credential = [Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
                HelpMessage='Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]
        $Limit = 1000,
        
        [Parameter(Mandatory=$false)]
        [string]
        $searchRoot = $null,
        
        [Parameter(Mandatory=$false)]
        [int]
        $PageSize = 100,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='scope of a search as either a base, one-level, or subtree search, default is subtree.')]
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
        $Deleted,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for groups mofied on or after this date.')]
        [datetime]
        $ModifiedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for groups mofied on or before this date.')]
        [datetime]
        $ModifiedBefore,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for groups created on or after this date.')]
        [datetime]
        $CreatedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for groups created on or after this date.')]
        [datetime]
        $CreatedBefore,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Name of group to match search on.')]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name = $null,

        [Parameter(Mandatory=$false,
                   HelpMessage='List of only the properties to retrieve from AD.')]
        [string[]]
        $Property = $(),

        [Parameter(Mandatory=$false,
                   HelpMessage='List only groups of a specific category, Security or Dristribution.')]
        [ValidateSet('Security','Distribution')]
        [string]
        $Category,

        # (admincount>=1)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for groups whose admincount field is not 0')]
        [switch]
        $AdminCount,

        [Parameter(Mandatory=$false,
                   HelpMessage='Changes the logic order of all attribute filtering from instead of matching on all criteria to match on any.')]
        [switch]
        $ChangeLogicOrder
        
    )
    
    begin {


        # Build filter
        $CompFilter = '(objectCategory=group)'
        $TempFilter = ''
        # Filter for modification time
        if ($ModifiedAfter -and $ModifiedBefore) {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"}
        elseif ($ModifiedAfter) {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))"}
        elseif ($ModifiedBefore) {
            $TempFilter = "$($TempFilter)(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"}

        # Fileter for creation time
        if ($CreatedAfter -and $CreatedBefore) {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"}
        elseif ($CreatedAfter) {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))"}
        elseif ($CreatedBefore) {
            $TempFilter = "$($TempFilter)(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"}

        if ($Name) {
            $TempFilter = "$($TempFilter)(name=$($Name))"}

        # Filter for groups who have an adcmicount filed higher than 0.
        if ($AdminCount) {
            $TempFilter = "$($TempFilter)(admincount>=1)"}

        # Filter by category
        if ($Category) {
            switch ($category) {
                'Distribution' {
                    $TempFilter = "$($TempFilter)(!(groupType:1.2.840.113556.1.4.803:=2147483648))"}
                'Security' {
                    $TempFilter = "$($TempFilter)(groupType:1.2.840.113556.1.4.803:=2147483648)"}
            }
        }

        # Change the logic order of the filters.
        if ($TempFilter.length -gt 0) {
            if ($ChangeLogicOrder) {
                $CompFilter = "(&$($CompFilter)(|$($TempFilter)))"}
            else {
                $CompFilter = "(&$($CompFilter)(&$($TempFilter)))"} 
         } else {
            $CompFilter = "(&$($CompFilter))"
         }
        $culture = Get-Culture

    }
    
    process {

        # Main properties for objects.
        $props = @('name',
                    'displayname',
                    'adspath',
                    'distinguishedname',
                    'objectguid',
                    'objectsid',
                    'samaccountname',
                    'whenchanged',
                    'whencreated',
                    'member',
                    'memberof',
                    'admincount',
                    'ntsecuritydescriptor',
                    'grouptype')

        

        write-verbose -message "Executing search with filter $CompFilter"
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -SearchRoot $searchRoot -Credential $Credential -Filter $CompFilter

                } else {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -Filter $CompFilter
                }
            }
            'Alternate' {$objSearcher = Get-DSDirectorySearcher -Credential $Credential -Filter $CompFilter}
            'Current' {$objSearcher = Get-DSDirectorySearcher -Filter $CompFilter}
            Default {}
        }
        $objSearcher.SizeLimit = $Limit
        $objSearcher.PageSize = $PageSize
        $objSearcher.SearchScope = $SearchScope
        $objSearcher.Tombstone = $Deleted
        $objSearcher.SecurityMasks = [DirectoryServices.SecurityMasks]$SecurityMask

        # If properties specified add those to the searcher
        if ($Property -contains '*' -or $Property.Count -ne 0) {
            foreach ($prop in $Property) {
                $objSearcher.PropertiesToLoad.Add($prop.ToLower()) | Out-Null
            }
        } else {
            Write-Verbose -Message 'No properties specified.'
            foreach ($prop in $props) {
                $objSearcher.PropertiesToLoad.Add($prop.ToLower()) | Out-Null
            }
        }

        $objSearcher.findall() | ForEach-Object -Process {
            #$userObj = [adsi]$_.path
            $objProps = [ordered]@{}
            [Collections.ArrayList]$currentProps = $_.Properties.PropertyNames
            foreach ($baseprop in $props) {
                if ($baseprop -in $currentprops) {
                    if ($baseprop -eq 'objectguid') {
                        $objProps['ObjectGuid'] = [guid]$_.properties."$($baseprop)"[0]
                        $currentProps.Remove($baseprop)
                    } elseif($baseprop -eq 'objectsid') {
                        $objProps['ObjectSid'] = "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})"
                        $currentProps.Remove($baseprop)
                    } elseif($baseprop -eq 'ntsecuritydescriptor') {
                        $secds = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $Desc = $_.Properties.ntsecuritydescriptor[0]
                        $secds.SetSecurityDescriptorBinaryForm($Desc)
                        $objProps['NTSecurityDescriptor'] = $secds
                        $currentProps.Remove($baseprop)
                    } elseif($baseprop -eq 'grouptype') {
                        
                        $groupType = $_.Properties.grouptype[0]
                        switch ($groupType)
                        {
                            2 {
                                $objProps['Category'] = 'Distribution'
                                $objProps['Scope'] = 'Global'}
                            4 {
                                $objProps['Category'] = 'Distribution'
                                $objProps['Scope'] = 'Local'}
                            8 {
                                $objProps['Category'] = 'Distribution'
                                $objProps['Scope'] = 'Universal'}
                            -2147483646 {
                                $objProps['Category'] = 'Security'
                                $objProps['Scope'] = 'Global'}
                            -2147483644 {
                                $objProps['Category'] = 'Security'
                                $objProps['Scope'] = 'Local'}
                            -2147483640 {
                                $objProps['Category'] = 'Security'
                                $objProps['Scope'] = 'Global'}
                            -2147483643 {
                                $objProps['Category'] = 'Security'
                                $objProps['Scope'] = 'Builtin'}
                            Default {
                                $objProps['Category'] = $null
                                $objProps['Scope'] = $null}
                        }
                        $objProps[$culture.TextInfo.ToTitleCase($baseprop)] = $_.properties."$($baseprop)"[0]
                    } else {
                        $objProps[$culture.TextInfo.ToTitleCase($baseprop)] = $_.properties."$($baseprop)"[0]
                    }

                    $currentProps.Remove($baseprop)
                }
            }
            foreach ($prop in $currentProps)
            {
                $objProps[$culture.TextInfo.ToTitleCase($prop)] = $_.properties."$($prop)"[0]
            }
            
            $grpObj = [PSCustomObject]$objProps
            $grpObj
        }
    }
    
    end {
    }
}
