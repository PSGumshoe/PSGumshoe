<#
.SYNOPSIS
     Get computer objects in a given directory service.
.DESCRIPTION
     Get computer objects in a given directory service.
.EXAMPLE
    C:\PS> Get-DSComputer -OperatingSystem "*windows 7*","*Windows 10*"
    Find all computers in the current domain that are running Windows 7 or Windows 10.
.EXAMPLE
    C:\PS> Get-DSComputer -LogOnBefore (Get-Date).AddMonths(-3)
    Find all computers that have not logged on to the domain in the last 3 months.
.EXAMPLE
    C:\PS> Get-DSComputer -SPN '*TERMSRV*'
    Find all computers with a service Principal Name.for TERMSRV. This machine are offering the Remote Desktop service.
#>
function Get-DSComputer {
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
        $searchRoot,
        
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
        $TombStone,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Only those trusted for delegation.')]
        [switch]
        $TrustedForDelegation,
        
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
            HelpMessage='Date to search for when the computer password was set after this date.')]
        [datetime]
        $PwSetAfter,

        [Parameter(Mandatory=$false,
            HelpMessage='Date to search for when the computer password was set before this date.')]
        [datetime]
        $PwSetBefore,

        [Parameter(Mandatory=$false,
                   HelpMessage='Filter by the specified operating systems.')]
        [SupportsWildcards()]
        [string[]]
        $OperatingSystem,

        [Parameter(Mandatory=$false,
                   HelpMessage='Filter by the specified Service Principal Names.')]
        [SupportsWildcards()]
        [string[]]
        $SPN,
        
        [Parameter(Mandatory=$false,
                   HelpMessage='Name of host to match search on.')]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        [Parameter(Mandatory=$false,
                   HelpMessage='List of only the properties to retrieve from AD.')]
        [string[]]
        $Property = $()
        
        
    )
    
    begin {
        # Build filter
        $CompFilter = '(objectCategory=Computer)'
        $TempFilter = ''
        # Filter for modification time
        if ($ModifiedAfter -and $ModifiedBefore) {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        } elseif ($ModifiedAfter) {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))"
        } elseif ($ModifiedBefore) {
            $TempFilter = "$($TempFilter)(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }

        # Fileter for creation time
        if ($CreatedAfter -and $CreatedBefore) {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        } elseif ($CreatedAfter) {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))"
        } elseif ($CreatedBefore) {
            $TempFilter = "$($TempFilter)(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }
        
        # Fileter for password last set
        if ($PwSetAfter -and $PwSetBefore) {
            $TempFilter = "$($TempFilter)(pwdlastset>=$($PwSetAfter.ToFileTimeUTC()))(pwdlastset<=$($PwSetBefore.ToFileTimeUTC()))"
        } elseif ($PwSetAfter) {
            $TempFilter = "$($TempFilter)(pwdlastset>=$($PwSetAfter.ToFileTimeUTC()))"
        } elseif ($PwSetBefore) {
            $TempFilter = "$($TempFilter)(pwdlastset<=$($PwSetBefore.ToFileTimeUTC()))"
        }

        # Fileter for loggon time
        if ($LogOnAfter -and $LogOnBefore) {
            $TempFilter = "$($TempFilter)(lastlogon>=$($LogOnAfter.ToFileTimeUTC()))(lastlogon<=$($LogOnBefore.ToFileTimeUTC()))"
        } elseif ($LogOnAfter) {
            $TempFilter = "$($TempFilter)(lastlogon>=$($LogOnAfter.ToFileTimeUTC()))"
        } elseif ($LogOnBefore) {
            $TempFilter = "$($TempFilter)(lastlogon<=$($LogOnBefore.ToFileTimeUTC()))"
        }

        if ($Name) {
            $TempFilter = "$($TempFilter)(name=$($Name))"
        }

        # Filter by Operating System
        if ($OperatingSystem) {
            $initialFilter = ''
            foreach ($os in $OperatingSystem) {
                $initialFilter += "(operatingSystem=$($os))"
            }
            $TempFilter += "(|$($initialFilter))"
        }

        # Filter by Service Principal Name
        if ($SPN) {
            $initialFilter = ''
            foreach ($sp in $SPN) {
                $initialFilter += "(servicePrincipalName=$($sp))"
            }
            $TempFilter += "(|$($initialFilter))"
        }

        # Filter for hosts trusted for delegation.
        if ($TrustedForDelegation) {
            $TempFilter = "$($TempFilter)(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        }

        $CompFilter = "(&$($CompFilter)$($TempFilter))"

        $culture = Get-Culture
        
        $StndProps = @(
            
        )

        $EncryptionTypes = @{
            1 = 'DES-CBC-CRC'
            2 = 'DES-CBC-MD5'
            4 = 'RC4-HMAC'
            8 = 'AES128-CTS-HMAC-SHA1-96'
            10 = 'AES256-CTS-HMAC-SHA1-96'}

<#            $enctype = 28
foreach ($enct in $EncryptionTypes.keys) {
    if ($enct -band $enctype)
    {
        $EncryptionTypes[$enct]
    }
}#>

    }
    
    process {
        write-verbose -message "Executing search with filter $CompFilter"
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -SearchRoot $searchRoot -Credential $Credential -Filter $CompFilter

                } else {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -Filter $CompFilter
                }
                
             }
            'Alternate' {
                $objSearcher = Get-DSDirectorySearcher -Credential $Credential -Filter $CompFilter
            }
            'Current' {
                $objSearcher = Get-DSDirectorySearcher -Filter $CompFilter
            }
            Default {}
        }
        $objSearcher.SizeLimit = $Limit
        $objSearcher.PageSize = $PageSize
        $objSearcher.SearchScope = $SearchScope
        $objSearcher.Tombstone = $TombStone
        $objSearcher.SecurityMasks = [DirectoryServices.SecurityMasks]$SecurityMask

        # If properties specified add those to the searcher
        if ($Property.count -ne 0 -or $Property -contains '*') {
            foreach ($prop in $Property) {
                $objSearcher.PropertiesToLoad.Add($prop.ToLower()) | Out-Null
            }
        }

        $objSearcher.findall() | ForEach-Object -Process {
            #$userObj = [adsi]$_.path
            $objProps = [ordered]@{}
            foreach ($prop in ($_.Properties.PropertyNames | Sort-Object))
            {
                if ($prop -eq 'objectguid') {
                    $objProps['Guid'] = [guid]$_.properties."$($prop)"[0]
                } elseif($prop -eq 'objectsid') {
                    $objProps['Sid'] = "$(&{$sidobj = [byte[]]"$($_.Properties.objectsid)".split(' ');$sid = new-object System.Security.Principal.SecurityIdentifier $sidobj, 0; $sid.Value})"
                } elseif($prop -eq 'lastlogontimestamp') {
                    $timeStamp = "$($_.Properties.lastlogontimestamp)"
                    $timeStampDate = [datetime]::FromFileTimeUtc($timeStamp)
                    $objProps['LastLogonTimeStamp'] = $timeStampDate
                } elseif($prop -eq 'ntsecuritydescriptor') {
                    $secds = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $Desc = $_.Properties.ntsecuritydescriptor[0]
                    $secds.SetSecurityDescriptorBinaryForm($Desc)
                    $objProps['NTSecurityDescriptor'] = $secds
                } elseif($prop -eq 'usercertificate') {
                    $certs = foreach ($cert in $_.Properties.usercertificate) {[Security.Cryptography.X509Certificates.X509Certificate2]$cert}
                    $objProps['UserCertificate'] = $certs
                } elseif ($prop -eq 'accountexpires') {
                    Try
                    {
                        $exval = "$($_.properties.accountexpires[0])"
                        If (($exval -eq 0) -or ($exval -gt [DateTime]::MaxValue.Ticks))
                        {
                            $objProps['AccountExpires'] = '<Never>'
                        }
                        Else
                        {
                            $Date = [DateTime]$exval
                            $objProps['AccountExpires'] = $Date.AddYears(1600).ToLocalTime()
                        }
                    }
                    catch
                    {
                        $objProps['AcctExpires'] = '<Never>'
                    }
                }
                elseif ($prop -eq 'pwdlastset')
                {
                    $objProps.Add('PwdLastSet', [dateTime]::FromFileTime($_.properties.pwdlastset[0]))
                }
                elseif ($prop -eq 'lastlogon')
                {
                    $objProps.Add('LastLogon', [dateTime]::FromFileTime($_.properties.lastlogon[0]))
                }
                elseif ($prop -eq 'badpasswordtime')
                {
                    $objProps.Add('BadPasswordTime', [dateTime]::FromFileTime($_.properties.badpasswordtime[0]))
                }
                else {
                    $objProps[$culture.TextInfo.ToTitleCase($prop)] = $_.properties."$($prop)"[0]
                }
            }
            if ($objProps['Dnshostname']) {
                $IPs = Get-ADIPAddress -ComputerName $objProps['Dnshostname']
                if ($IPs.count -ne 0)
                {
                    $objProps.Add('IPAddress',$IPs)
                }
                else
                {
                    $objProps.Add('IPAddress','')
                }
            }
            
            $compObj = [PSCustomObject]$objProps
            $compObj
        }
    }
    
    end {
    }
}
