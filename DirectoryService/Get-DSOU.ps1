<#
.Synopsis
   Get Organizational Units objects in a given directory service.
.DESCRIPTION
   Get Organizational Units objects in a given directory service.
.EXAMPLE
    Get-DSOU -GpoGuid '6AC1786C-016F-11D2-945F-00C04fB984F9'

    Get all OUs that have the specified GPO linked to them.
#>
function Get-DSOU
{
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
                   HelpMessage='Date to search for computers mofied on or after this date.')]
        [datetime]
        $ModifiedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for computers mofied on or before this date.')]
        [datetime]
        $ModifiedBefore,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for computers created on or after this date.')]
        [datetime]
        $CreatedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage='Date to search for computers created on or after this date.')]
        [datetime]
        $CreatedBefore,

        [Parameter(Mandatory=$false,
                   HelpMessage='Name of host to match search on.')]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name = $null,

        [Parameter(Mandatory=$false,
                   HelpMessage='List of only the properties to retrieve from AD.')]
        [string[]]
        $Property = $(),

        [Parameter(Mandatory=$false,
                   HelpMessage='Changes the logic order of all attribute filtering from instead of matching on all criteria to match on any.')]
        [switch]
        $ChangeLogicOrder,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Get only OU that have linked to them GPOs with the specified GUID.')]
        [string]
        $GpoGuid
    )

    Begin
    {
        # Build filter
        $OUFilter = '(objectCategory=organizationalUnit)'
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
            
        if ($GpoGuid) {
            $TempFilter = "$($TempFilter)(gplink=*$($GpoGuid)*)"}

        # Change the logic order of the filters.
        if ($TempFilter.length -gt 0) {
            if ($ChangeLogicOrder) {
                $OUFilter = "(&$($OUFilter)(|$($TempFilter)))"}
            else {
                $OUFilter = "(&$($OUFilter)(&$($TempFilter)))"} 
         } else {
            $OUFilter = "(&$($OUFilter))"
         }
        $culture = Get-Culture
    }
    Process
    {
        # Main properties for objects.
        $props = @('name',
                    'adspath',
                    'distinguishedname',
                    'objectguid',
                    'whenchanged',
                    'whencreated',
                    'ntsecuritydescriptor',
                    'gplink',
                    'Dscorepropagationdata')

        write-verbose -message "Executing search with filter $CompFilter"
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -SearchRoot $searchRoot -Credential $Credential -Filter $OUFilter

                } else {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -Filter $OUFilter
                }
            }
            'Alternate' {$objSearcher = Get-DSDirectorySearcher -Credential $Credential -Filter $OUFilter}
            'Current' {$objSearcher = Get-DSDirectorySearcher -Filter $OUFilter}
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
            $objProps = [ordered]@{}
            [Collections.ArrayList]$currentProps = $_.Properties.PropertyNames
            foreach ($baseprop in $props) {
                if ($baseprop -in $currentprops) {
                    if ($baseprop -eq 'objectguid') {
                        $objProps['ObjectGuid'] = [guid]$_.properties."$($baseprop)"[0]
                        $currentProps.Remove($baseprop)
                    } elseif($baseprop -eq 'lastlogontimestamp') {
                        $timeStamp = "$($_.Properties.lastlogontimestamp)"
                        $timeStampDate = [datetime]::FromFileTimeUtc($timeStamp)
                        $objProps['LastLogonTimeStamp'] = $timeStampDate
                        $currentProps.Remove($baseprop)
                    } elseif($baseprop -eq 'ntsecuritydescriptor') {
                        $secds = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $Desc = $_.Properties.ntsecuritydescriptor[0]
                        $secds.SetSecurityDescriptorBinaryForm($Desc)
                        $objProps['NTSecurityDescriptor'] = $secds
                        $currentProps.Remove($baseprop)
                    } elseif ($baseprop -eq 'accountexpires') {
                        Try
                        {
                            $exval = "$($_.properties.accountexpires[0])"
                            If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                            {
                                $objProps['AccountExpires'] = '<Never>'
                                $currentProps.Remove($baseprop)
                            }
                            Else
                            {
                                $Date = [DateTime]$exval
                                $objProps['AccountExpires'] = $Date.AddYears(1600).ToLocalTime()
                                $currentProps.Remove($baseprop)
                            }
                            
                        }
                        catch
                        {
                            $objProps['AccountExpires'] = '<Never>'
                            $currentProps.Remove($baseprop)
                        }
                    }
                   
                    else {
                      if ($_.properties."$($baseprop)") {
                        $objProps[$culture.TextInfo.ToTitleCase($baseprop)] = $_.properties."$($baseprop)"[0]
                      }
                    }

                    $currentProps.Remove($baseprop)
                }
            }
            foreach ($prop in $currentProps)
            {
                $objProps[$culture.TextInfo.ToTitleCase($prop)] = $_.properties."$($prop)"[0]
            }
            
            $OUObj = [PSCustomObject]$objProps
            $OUObj
        }
    }
    End
    {
    }
}