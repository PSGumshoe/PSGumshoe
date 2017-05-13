function Get-DSGroupMember {
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

        [Parameter(Mandatory=$true)]
        $Identity
    )
    
    begin {
        $Recurse = $true
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        $sig = @"
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(string server,out IntPtr domain,out int status);
"@
    }
    
    process {
        
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                 $cArgs = @(
                    'DirectoryServer',
                    $ComputerName,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            'Alternate' {
                 $cArgs = @(
                    'Domain',
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password
                )
                $typeName = 'DirectoryServices.ActiveDirectory.DirectoryContext'
                $context = New-Object $typeName  $cArgs
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            'Current' {
                $Context = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $group=[System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context, $Identity)
            }

            Default {}
        }

        $group.GetMembers($Recurse)
    }
    
    end {
    }
}