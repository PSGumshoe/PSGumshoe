<#
.SYNOPSIS
    Get Active Directory Forest information.
.DESCRIPTION
    Gets Active Directory forest information for the forest the current host is a member of,
    a specified forest given it FQDN and supports the use of alternate credentials.
.PARAMETER ComputerName
    Fully Qualified Name of a remote domain controller to connect to.
.PARAMETER Credential
    Alternate credentials for retrieving forest information.
.PARAMETER Forest
    Fully Qualified Name of a forest to get information on when running from a host joined
    to the domain.
.EXAMPLE
    C:\PS> Get-DSForest
    Gets the forest for the domain the host is corrently joined to.
.EXAMPLE
    C:\PS> Get-DSForest -ComputerName dc01.acmelabs.com -Credential (Get-Credential user1)
    Connect to a remote domain controller and get the forest for domain it manages using the
    provided credentials.
.EXAMPLE
    C:\PS> Get-DSForest -ForestName frabrikan.com
    Gets the forest frabikan.com that the current domain has a trust relationship with.
.OUTPUTS
    System.DirectoryServices.ActiveDirectory.Forest
.NOTES
    This function is heavily dependent on DNS. The host running the function is highly
    recomended to be using the same DNS server as the domain whe are querying.
#>
function Get-DSForest {
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        # Domain controller to connect to when not in a domain.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,

        # Credentials to use for getting forest information.
        [Parameter(ParameterSetName = 'OtherForest',
                    Mandatory = $false)]
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        # Forest name.
        [Parameter(ParameterSetName = 'OtherForest',
                   Mandatory = $true)]
        [string]
        $ForestName
    )

    begin {
    }

    process {
        $sig = @"
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(string server,out IntPtr domain,out int status);
"@

        switch ($PSCmdlet.ParameterSetName) {
            'Current' {
                $type = Add-Type -MemberDefinition $sig -Name Win32Utils -Namespace NetGetJoinInformation -PassThru
                $ptr = [IntPtr]::Zero
                $joinstatus = 0
                $type::NetGetJoinInformation($null, [ref] $ptr, [ref]$joinstatus) |Out-Null

                if ($joinstatus -eq 3){
                    $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    
                    # Get sid for root domain.
                    if ($ForestObject -ne $null) {
                        $RootDN = "DC=$(($ForestObject.Name).replace('.',',DC='))"
                        $DEObj = Get-DSDirectoryEntry -DistinguishedName $RootDN
                        $Sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($DEObj.objectSid.value,0)).value
                         Add-Member -InputObject $ForestObject -MemberType NoteProperty -Name 'Sid' -Value $Sid
                    }
                } else {
                    throw 'This computer is not joined to a domain so no forest could be retrieved.'
                }
            }

            'Remote' {
                $cArgs = @(
                    'DirectoryServer',
                    $ComputerName,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )

                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $ForestObject = [DirectoryServices.ActiveDirectory.Forest]::GetForest($context)
                
                # Get sid for root domain.
                
                $RootDN = "DC=$(($ForestObject.Name).replace('.',',DC='))"
                $DEObj = Get-DSDirectoryEntry -DistinguishedName $RootDN -ComputerName $ComputerName -Credential $Credential
                $Sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($DEObj.objectSid.value,0)).value
                Add-Member -InputObject $ForestObject -MemberType NoteProperty -Name 'Sid' -Value $Sid
                
            }

            'OtherForest' {
                if ($Credential.UserName -ne $null){
                    # Arguments to get forest with alternate credentials
                    $cArgs = @(
                        'Forest',
                        $ForestName,
                        $Credential.UserName,
                        $Credential.GetNetworkCredential().Password
                    )
                } else {
                    # Arguments to only get forest with no alternate credentials
                    $cArgs = @(
                        'Forest',
                        $ForestName
                    )
                }
                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $ForestObject = [DirectoryServices.ActiveDirectory.Forest]::GetForest($context)
                
                $RootDN = "DC=$(($ForestObject.Name).replace('.',',DC='))"
                if ($Credential.UserName -ne $null){
                    $DEObj = Get-DSDirectoryEntry -DistinguishedName $RootDN -Credential $Credential
                } else {
                    $DEObj = Get-DSDirectoryEntry -DistinguishedName $RootDN
                }
                $Sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($DEObj.objectSid.value,0)).value
                Add-Member -InputObject $ForestObject -MemberType NoteProperty -Name 'Sid' -Value $Sid
                
            }
            Default {}
        }
        $ForestObject
    }

    end {
    }
}

