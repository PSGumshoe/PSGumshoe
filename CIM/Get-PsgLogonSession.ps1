function Get-PsgLogonSession {
    <#
    .SYNOPSIS
        Query the CIM Object database for a list of Logon Sessions and account related to session on a target host.
    .DESCRIPTION
        Query the CIM Object database for a list of Logon Sessions and account related to session on a target host.
    .EXAMPLE
        PS C:\> Get-PsgLogonSession -IncludeProcess                                            


        StartTime             : 12/21/2019 10:00:14 PM
        AuthenticationPackage : Kerberos
        LogonId               : 2921480
        LogonIdHex            : 0x2c9408
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
        Processes             : {@{ProcessId=2408; ParentProcessId=428; Name=sihost.exe; 
                                ExecutablePath=C:\WINDOWS\system32\sihost.exe; CommandLine=sihost.exe; CreationDate=12/21/2019 
                                10:00:15 PM; SessionId=1; ComputerName=localhost}, @{ProcessId=1568; ParentProcessId=632; 
                                Name=svchost.exe; ExecutablePath=C:\WINDOWS\system32\svchost.exe; 
                                CommandLine=C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup; CreationDate=12/21/2019
                                10:00:15 PM; SessionId=1; ComputerName=localhost}, @{ProcessId=4804; ParentProcessId=428; 
                                Name=taskhostw.exe; ExecutablePath=C:\WINDOWS\system32\taskhostw.exe; CommandLine=taskhostw.exe  
                                {222A245B-E637-4AE9-A93F-A59CA119A75E}; CreationDate=12/21/2019 10:00:15 PM; SessionId=1; 
                                ComputerName=localhost}, @{ProcessId=3460; ParentProcessId=4432; Name=explorer.exe;
                                ExecutablePath=C:\WINDOWS\Explorer.EXE; CommandLine=C:\WINDOWS\Explorer.EXE;
                                CreationDate=12/21/2019 10:00:16 PM; SessionId=1; ComputerName=localhost}...}

        StartTime             : 12/21/2019 10:00:14 PM
        AuthenticationPackage : Kerberos
        LogonId               : 2921444
        LogonIdHex            : 0x2c93e4
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
        Processes             : {}

        GetLogon sessions and include the processes for the sessions
    
    .EXAMPLE
        Get-CimSession | Get-PsgLogonSession


        StartTime             : 12/21/2019 10:00:14 PM
        AuthenticationPackage : Kerberos
        LogonId               : 2921480
        LogonIdHex            : 0x2c9408
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
        Processes             :
        ComputerName          : localhost

        StartTime             : 12/21/2019 10:00:14 PM
        AuthenticationPackage : Kerberos
        LogonId               : 2921444
        LogonIdHex            : 0x2c93e4
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
        Processes             : 
        ComputerName          : localhost

        StartTime             : 1/3/2020 4:05:21 PM
        AuthenticationPackage : Kerberos
        LogonId               : 328440214
        LogonIdHex            : 0x13939996
        LogonType             : 3
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             :
        ComputerName          : dc1

        StartTime             : 1/3/2020 4:03:01 PM
        AuthenticationPackage : Kerberos
        LogonId               : 328411060
        LogonIdHex            : 0x139327b4
        LogonType             : 3
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             :
        ComputerName          : dc1

        StartTime             : 1/3/2020 4:03:01 PM
        AuthenticationPackage : Kerberos
        LogonId               : 328410548
        LogonIdHex            : 0x139325b4
        LogonType             : 3
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             :
        ComputerName          : dc1

        StartTime             : 1/3/2020 3:58:56 PM
        AuthenticationPackage : Kerberos
        LogonId               : 328367485
        LogonIdHex            : 0x13927d7d
        LogonType             : 3
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             : 
        ComputerName          : dc1

        StartTime             : 1/3/2020 4:05:20 PM
        AuthenticationPackage : Kerberos
        LogonId               : 328439765
        LogonIdHex            : 0x139397d5
        LogonType             : 3
        User                  : ACMELABS\cperez
        FullName              : Carlos Perez
        SID                   : S-1-5-21-3150103098-694922503-2167627182-1618
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             :
        ComputerName          : dc1

        StartTime             : 8/16/2019 11:57:22 PM
        AuthenticationPackage : Kerberos
        LogonId               : 628229
        LogonIdHex            : 0x99605
        LogonType             : 2
        User                  : ACMELABS\Administrator
        FullName              :
        SID                   : S-1-5-21-3150103098-694922503-2167627182-500
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             : 
        ComputerName          : dc1

        StartTime             : 8/16/2019 11:27:19 PM
        AuthenticationPackage : Kerberos
        LogonId               : 385611
        LogonIdHex            : 0x5e24b
        LogonType             : 3
        User                  : ACMELABS\Administrator
        FullName              :
        SID                   : S-1-5-21-3150103098-694922503-2167627182-500
        AccountType           : 512
        LocalAccount          : False
        PasswordChangeable    : True
        PasswordRequired      : True
        Lockout               : False
        Disabled              : False
        Processes             : 
        ComputerName          : dc1

        Get session information for all CIM Sessions.
    .INPUTS
        Microsoft.Management.Infrastructure.CimSession
    .OUTPUTS
        LogonSession
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        # CIMSession to perform query against
        [Parameter(ValueFromPipelineByPropertyName = $True,
            ValueFromPipeline = $true)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        # Include Processes for each logon session.
        [Parameter(Mandatory=$false)]
        [switch]
        $IncludeProcess
    )
    
    begin {
    
    }
    
    process {
        # If no CIMSession is provided we create one for localhost.
        if ($null -eq $CimSession -or $CimSession.Count -eq 0) {
            $sessop = New-CimSessionOption -Protocol Dcom
            $CimSession += New-CimSession -ComputerName localhost -SessionOption $sessop
        }

        foreach($s in $CimSession) {
            $Wql = "SELECT * FROM Win32_LogonSession" 
            Get-CimInstance -Query $Wql -CimSession $s | ForEach-Object {
                $objProps = [ordered]@{}
                $objProps.Add('StartTime', $_.StartTime)
                $objProps.Add('AuthenticationPackage', $_.AuthenticationPackage)
                $objProps.Add('LogonId', $_.LogonId)
                $lidHex = "{0:x}" -f [int]$objProps.LogonId
                $objProps.Add('LogonIdHex', "0x$($lidHex)")
                $objProps.Add('LogonType', $_.LogonType)

                # Get the associated win32_account info.
                Get-CimInstance -Query "Associators of {Win32_logonsession.logonid=$($_.LogonId)} Where Resultclass = Win32_UserAccount" -CimSession $s | ForEach-Object {
                    $objProps.Add('User', $_.Caption)
                    $objProps.Add('FullName', $_.FullName)
                    $objProps.Add('SID', $_.SID)
                    $objProps.Add('AccountType', $_.AccountType)
                    $objProps.Add('LocalAccount', $_.LocalAccount)
                    $objProps.Add('PasswordChangeable', $_.PasswordChangeable)
                    $objProps.Add('PasswordRequired', $_.PasswordRequired)
                    $objProps.Add('Lockout', $_.Lockout)
                    $objProps.Add('Disabled', $_.Disabled)
                    if ($IncludeProcess) {
                        $processes = @()
                        Get-CimInstance -Query "Associators of {Win32_logonsession.logonid=$($objProps.LogonId)} Where Resultclass = Win32_Process" -CimSession $s | ForEach-Object {
                            $Property = @('ProcessId', 'ParentProcessId', 'Name', 'ExecutablePath', 'CommandLine', 'CreationDate', 'SessionId')
                            $objectProps = [ordered]@{}
                            foreach($p in $Property) {
                                $objectProps.Add($p, $_."$($p)")
                            }
                            $objectProps.Add('ComputerName', $s.ComputerName)
                            $obj = [PSCustomObject]$objectProps
                            $obj.pstypenames.insert(0,'PSGumshoe.Process')
                            $processes += $obj
                        }
                        $objProps.Add('Processes',$processes)
                    } else {
                        $objProps.Add('Processes',"")
                    }
                    $objProps.Add('ComputerName', $s.ComputerName)
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
