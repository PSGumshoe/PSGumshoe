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
    [Parameter(Mandatory = $true)]
    [string]
    $DistinguishedName
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

$sig = @"
[DllImport("Netapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
public static extern int NetGetJoinInformation(string server,out IntPtr domain,out int status);
"@

Describe 'Get-DSDirectoryEntry' {
    switch ( $PSCmdlet.ParameterSetName ) {
        # Test getting path with current user creds and that it errors properly if not joined
        'Current' {
            $type = Add-Type -MemberDefinition $sig -Name Win32Utils -Namespace NetGetJoinInformation -PassThru
            $ptr = [IntPtr]::Zero
            $joinstatus = 0
            $type::NetGetJoinInformation($null, [ref] $ptr, [ref]$joinstatus) |Out-Null
            
            if ($joinstatus -eq 3) {
                It 'Gets a specified path using current credentials' {
                    $DEObject = Get-DSDirectoryEntry -DistinguishedName $DistinguishedName
                    ($DEObject -is [adsi]) | Should Be $true
                }
            } else {
                It 'Should throw since it is  not domain joined.' {
                    {Get-DSDirectoryEntry -DistinguishedName $DistinguishedName} | Should Throw 'Host is currently not joined to a domain.'
                }
            }
        }

        # Tests the use of alternate credentials
        'Alternate' {
            It 'Get a specified path with alternate credentials'{
                $DEObject = Get-DSDirectoryEntry -DistinguishedName $DistinguishedName -credential $credential
                ($DEObject -is [adsi]) | Should Be $true
            }
        }

        # Tests remote connection
        'Remote' {
            It 'Connects to remote DC and gets a specified path.' {
                $DEObject = Get-DSDirectoryEntry -DistinguishedName $DistinguishedName -credential $credential -ComputerName $computername
                ($DEObject -is [adsi]) | Should Be $true
            }
        }
    }
}

