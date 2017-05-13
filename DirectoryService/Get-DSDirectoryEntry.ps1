<#
.SYNOPSIS
    Get a DirectoryEntry object for a specified distinguished name.
.DESCRIPTION
    Get a DirectoryEntry object for a specified distinguished name.
.PARAMETER ComputerName
    Fully Qualified Name of a remote domain controller to connect to.
.PARAMETER Credential
    Alternate credentials for retrieving forest information.
.PARAMETER DistinguishedName
    Distinguished Name of AD object we want to get.
.EXAMPLE
    C:\PS> Get-DSDirectoryEntry -DistinguishedName "CN=Domain Users,CN=Users,DC=acmelabs,DC=com"
    Get Domain Users group object.
.EXAMPLE
    C:\PS> Get-DSDirectoryEntry -DistinguishedName "<GUID=244dc73c2962a349a90fb7cd8bc88c80>"
    Get Domain Users group object by GUID.
.EXAMPLE
    C:\PS> Get-DSDirectoryEntry -DistinguishedName "<SID=S-1-5-32-545>"
    Get Users group object by known SID
.OUTPUTS
    System.DirectoryService.DirectoryEntry
#>
function Get-DSDirectoryEntry {
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
        $Credential,
        
        # Distinguished Name of AD object.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [string]
        $DistinguishedName,

        # Path type.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromPipeline = $true)]
        [ValidateSet('LDAP', 'GC')]
        [string]
        $PathType = 'LDAP'

    )

    begin {
        $sig = @"
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(string server,out IntPtr domain,out int status);
"@
        $type = Add-Type -MemberDefinition $sig -Name Win32Utils -Namespace NetGetJoinInformation -PassThru
        $ptr = [IntPtr]::Zero
        $joinstatus = 0
        $type::NetGetJoinInformation($null, [ref] $ptr, [ref]$joinstatus) |Out-Null
        
        # Manage id DN includes path type.
        if ($DistinguishedName.StartsWith('LDAP',$true,(Get-Culture)))
        {
            $PathType = 'LDAP'
            $DistinguishedName = $DistinguishedName.Split('://')[3]
            
        }

        if ($DistinguishedName.StartsWith('GC',$true,(Get-Culture)))
        {
            $PathType = 'GC'
            $DistinguishedName = $DistinguishedName.Split('://')[3]
        }
    }

    process {
        switch ( $PSCmdlet.ParameterSetName ) {
            'Current' {
                if ($joinstatus -eq 3) {
                    if ($DistinguishedName) {
                        [adsi]"$($PathType.ToUpper())://$($DistinguishedName)"
                    } else {
                        [adsi]''
                    }
                    
                } else {
                    throw 'Host is currently not joined to a domain.'
                }
            }

            'Remote' {
                if ($DistinguishedName){
                    $fullPath = "$($PathType.ToUpper())://$($ComputerName)/$($DistinguishedName)"
                } else {
                    $fullPath = "$($PathType.ToUpper())://$($ComputerName)"
                }
                New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList @($fullPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password) 
                
            }
            
            'Alternate' {
                $fullPath = "$($PathType.ToUpper())://$($DistinguishedName)"
                New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList @($fullPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password) 
            }    
        }
    }

    end{}
}
