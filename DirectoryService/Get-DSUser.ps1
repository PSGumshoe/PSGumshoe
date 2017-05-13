<#
  .SYNOPSIS
    Get user objects in a given directory service.
  .DESCRIPTION
    Get user objects in a given directory service.
  .EXAMPLE
    C:\PS> <example usage>
    Explanation of what the example does
#>
function Get-DSUser {
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
                   HelpMessage='Date to search for computers that logged on or after this date.')]
        [datetime]
        $LogOnAfter,

        [Parameter(Mandatory=$false,
            HelpMessage='Date to search for computers that logged on or after this date.')]
        [datetime]
        $LogOnBefore,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Name of user to match search on.')]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name = $null,

        [Parameter(Mandatory=$false,
                   HelpMessage='List of only the properties to retrieve from AD.')]
        [string[]]
        $Property = $(),

        # (userAccountControl:1.2.840.113556.1.4.803:=1048574)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for accounts marked as sensitive and can not have their credentials delegated.')]
        [switch]
        $SensitiveNoDelegation,

        # (userAccountControl:1.2.840.113556.1.4.803:=32)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for accounts for wich no password is required.')]
        [switch]
        $NoPasswordRequired,
        
        # (|(accountExpires=0)(accountExpires=9223372036854775807))
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for accunts whos password does not expire.')]
        [switch]
        $PasswordNeverExpires,

        # (userAccountControl:1.2.840.113556.1.4.803:=2)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for disabled accounts.')]
        [switch]
        $Disabled,

        # (admincount>=1)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for accounts whose admincount field is not 0')]
        [switch]
        $AdminCount,

        # (servicePrincipalName=*)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for service accounts. Accounts with a Service Principal Field marked.')]
        [switch]
        $ServiceAccount,

        # (pwdLastSet=0)
        [Parameter(Mandatory=$false,
                   HelpMessage='Search for accounts that must change their password at next logon.')]
        [switch]
        $MustChangePassword,

        [Parameter(Mandatory=$false,
                   HelpMessage='Changes the logic order of all attribute filtering from instead of matching on all criteria to match on any.')]
        [switch]
        $ChangeLogicOrder
        
    )
    
    begin {

        $userAccountControlEnum = @{
            2 = 'ACCOUNT_DISABLED'
            16 = 'LOCKOUT'
            32 = 'PASSWD_NOTREQ'
            64 = 'PASSWD_CANT_CHANGE'
            128 = 'REVERSIBLE_ENCRYPTION'
            512 = 'NORMAL_ACCOUNT'
            65536 = 'DONT_EXPIRE_PASSWD'
            262144 = 'SMARTCARD_REQUIRED'
            524288 = 'TRUSTED_FOR_DELEGATION'
            1048576 = 'NOT_DELEGATED'
            2097152 = 'USE_DES_KEY_ONLY'
            4194304 = 'DONT_REQUIRE_PREAUTH'
            16777216 = 'TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION'
            33554432 = 'NO_AUTH_DATA_REQUIRED'
        }

        # Build filter
        $CompFilter = '(sAMAccountType=805306368)'
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
        
        # Fileter for loggon time
        if ($LogOnAfter -and $LogOnBefore) {
            $TempFilter = "$($TempFilter)(lastlogon>=$($LogOnAfter.ToFileTimeUTC()))(lastlogon<=$($LogOnBefore.ToFileTimeUTC()))"}
        elseif ($LogOnAfter) {
            $TempFilter = "$($TempFilter)(lastlogon>=$($LogOnAfter.ToFileTimeUTC()))"}
        elseif ($LogOnBefore) {
            $TempFilter = "$($TempFilter)(lastlogon<=$($LogOnBefore.ToFileTimeUTC()))"}

        if ($Name) {
            $TempFilter = "$($TempFilter)(name=$($Name))"}

        # Filter for hosts trusted for delegation.
        if ($TrustedForDelegation) {
            $TempFilter = "$($TempFilter)(userAccountControl:1.2.840.113556.1.4.803:=524288)"}

        # Filter for accounts that are marked as sensitive and can not be delegated.
        if ($SensitiveNoDelegation) {
            $TempFilter = "$($TempFilter)(userAccountControl:1.2.840.113556.1.4.803:=1048574)"}

        # Filter for accounts who do not requiere a password to logon.
        if ($NoPasswordRequired) {
            $TempFilter = "$($TempFilter)(userAccountControl:1.2.840.113556.1.4.803:=32)"}

        # Filter for accounts whose password does not expires.
        if ($PasswordNeverExpires) {
            $TempFilter = "$($TempFilter)(|(accountExpires=0)(accountExpires=9223372036854775807))"}

        # Filter for accounts that are disabled.
        if ($Disabled) {
            $TempFilter = "$($TempFilter)(userAccountControl:1.2.840.113556.1.4.803:=2)"}

        # Filter for accounts who have an adcmicount filed higher than 0.
        if ($AdminCount) {
            $TempFilter = "$($TempFilter)(admincount>=1)"}

        # Filter for accounts that have SPN set.
        if ($ServiceAccount) {
            $TempFilter = "$($TempFilter)(servicePrincipalName=*)"}

        # Filter whose users must change their passwords.
        if ($MustChangePassword) {
            $TempFilter = "$($TempFilter)(pwdLastSet=0)"}

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
                    'pwdLastSet',
                    'lastlogon',
                    'lastlogoff',
                    'badpasswordtime'
                    'sidhistory',
                    'serviceprincipalname',
                    'useraccountcontrol',
                    'memberof',
                    'ntsecuritydescriptor',
                    'accountexpires')

        write-verbose -message "Executing search with filter $CompFilter"
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -DistinguishedName $searchRoot -Credential $Credential -Filter $CompFilter

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
                    } elseif($baseprop -eq 'usercertificate') {
                        $certs = foreach ($cert in $_.Properties.usercertificate) {[Security.Cryptography.X509Certificates.X509Certificate2]$cert}
                        $objProps['UserCertificate'] = $certs
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
                    elseif ($baseprop -eq 'pwdlastset')
                    {
                        $objProps.Add('PwdLastSet', [dateTime]::FromFileTime($_.properties.pwdlastset[0]))
                        $currentProps.Remove($baseprop)
                    }
                    elseif ($baseprop -eq 'lastlogon')
                    {
                        $objProps.Add('LastLogon', [dateTime]::FromFileTime($_.properties.lastlogon[0]))
                        $currentProps.Remove($baseprop)
                    }
                    elseif ($baseprop -eq 'badpasswordtime')
                    {
                        $objProps.Add('BadPasswordTime', [dateTime]::FromFileTime($_.properties.badpasswordtime[0]))
                        $currentProps.Remove($baseprop)
                    }
                
                    elseif ($baseprop -eq 'Useraccountcontrol')
                    {
                        $uac = $_.properties."$($baseprop)"[0]
                        $uacSet = @()
                        foreach ($val in $userAccountControlEnum.keys) {
                            if ([int]$uac -band $val) {
                                $uacSet += $userAccountControlEnum[$val]
                            }
                        }
                        $objProps[$culture.TextInfo.ToTitleCase($baseprop)] = $uacSet
                        $currentProps.Remove($baseprop)
                    }
                    else {
                        $objProps[$culture.TextInfo.ToTitleCase($baseprop)] = $_.properties."$($baseprop)"[0]
                    }

                    $currentProps.Remove($baseprop)
                }
            }
            foreach ($prop in $currentProps)
            {
                $objProps[$culture.TextInfo.ToTitleCase($prop)] = $_.properties."$($prop)"[0]
            }
            
            $compObj = [PSCustomObject]$objProps
            $compObj
        }
    }
    
    end {
    }
}
 