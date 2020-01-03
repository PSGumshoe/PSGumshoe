function Get-PsgProcessLogonSession {
    <#
    .SYNOPSIS
        Query the CIM database for the logon session and account infor for a specific process.
    .DESCRIPTION
        Query the CIM database for the logon session and account infor for a specific process by specifying a process Id.
    .EXAMPLE
        PS C:\> Get-CimSession -Id 1 | Get-PsgProcessLogonSession -ProcessId 5588

        ProcessId             : 5588
        StartTime             : 12/21/2019 10:00:14 PM
        AuthenticationPackage : Kerberos
        LogonId               : 2921480
        LogonIdHex            : 0x2921480
        LogonType             : 2
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        ComputerName          : localhost

        Get the logon session that relates to a specified process byt their process Id.
    .INPUTS
        Microsoft.Management.Infrastructure.CimSession
    .OUTPUTS
        PSGumshoe.LogonSession
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        # ProcessId to query for.
        [Parameter(Mandatory=$true)]
        [int[]]
        $ProcessId,

        # CIMSession to perform query against
        [Parameter(ValueFromPipelineByPropertyName = $True,
            ValueFromPipeline = $true)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
    )
    
    begin {
    
    }
    
    process {
        # If no CIMSession is provided we create one for localhost.
        if ($null -eq $CimSession) {
            $sessop = New-CimSessionOption -Protocol Dcom
            $CimSession += New-CimSession -ComputerName localhost -SessionOption $sessop
        }

        foreach($p in $ProcessId) {
            $Wql = "Associators of {Win32_Process='$($p)'} Where Resultclass = Win32_LogonSession Assocclass = Win32_SessionProcess" 
            Get-CimInstance -Query $Wql -CimSession $CimSession | ForEach-Object {
                $objProps = [ordered]@{}
                $objProps.Add('ProcessId', $p)
                $objProps.Add('StartTime', $_.StartTime)
                $objProps.Add('AuthenticationPackage', $_.AuthenticationPackage)
                $objProps.Add('LogonId', $_.LogonId)
                $objProps.Add('LogonIdHex', "0x$("{0:x}" -f $_.LogonId)")
                $objProps.Add('LogonType', $_.LogonType)

                # Get the associated win32_account info.
                Get-CimInstance -Query "Associators of {Win32_logonsession.logonid=$($_.LogonId)} Where Resultclass = Win32_UserAccount" -CimSession $CimSession | ForEach-Object {
                    $objProps.Add('User', $_.Caption)
                    $objProps.Add('FullName', $_.FullName)
                    $objProps.Add('SID', $_.SID)
                    $objProps.Add('AccountType', $_.AccountType)
                    $objProps.Add('LocalAccount', $_.LocalAccount)
                    $objProps.Add('PasswordChangeable', $_.PasswordChangeable)
                    $objProps.Add('PasswordRequired', $_.PasswordRequired)
                    $objProps.Add('Lockout', $_.Lockout)
                    $objProps.Add('Disabled', $_.Disabled)
                    $objProps.Add('ComputerName', $CimSession.ComputerName)
                    $sessObj = [PSCustomObject]$objProps
                    $sessObj.pstypenames.insert(0,'PSGumshoe.LogonSession')
                    $sessObj
                }
            }
        }
    }
    
    end {
        
    }
}
