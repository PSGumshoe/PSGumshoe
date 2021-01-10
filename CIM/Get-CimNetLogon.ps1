function Get-CimNetLogon {
    <#
    .SYNOPSIS
        Get Netlogon cached information entries for Windows 8/2012 or above systems leveraging CIM.
    .DESCRIPTION
        Get Netlogon cached information entries for Windows 8/2012 or above systems leveraging CIM. When ran
        elevated or remotely as an adminitrator y provides all cached netlogon entries if not it will return
        information for the System account and the cuser executing the query.
    .EXAMPLE
        PS C:\> Get-CimNetLogon

        Name            : NT AUTHORITY\SYSTEM
        Caption         : NT AUTHORITY\SYSTEM
        LastLogon       : 
        Comment         : 
        NumberOfLogons  : 
        Privileges      : 
        PrimaryGroupId  : 
        ScriptPath      : 
        PasswordExpires : 
        PasswordAge     : 
        UserId          : 
        Flags           : {}

        Name            : ACMELABS\cperez
        Caption         : cperez
        LastLogon       : 1/9/2021 3:32:14 PM
        Comment         : 
        NumberOfLogons  : 487
        Privileges      : Administrator
        PrimaryGroupId  : 513
        ScriptPath      : 
        PasswordExpires :
        PasswordAge     : 2.13:07:50
        UserId          : 1618
        Flags           : {PasswordNotExpires, NormalAccount}


        Running localy in a none elevated window. 

    .EXAMPLE

    PS C:\> Get-CimNetLogon


    Name            : NT AUTHORITY\SYSTEM
    Caption         : NT AUTHORITY\SYSTEM
    LastLogon       :
    Comment         :
    NumberOfLogons  :
    Privileges      :
    PrimaryGroupId  :
    ScriptPath      :
    PasswordExpires :
    PasswordAge     :
    UserId          :
    Flags           : {}

    Name            : NT AUTHORITY\LOCAL SERVICE
    Caption         : NT AUTHORITY\LOCAL SERVICE
    LastLogon       :
    Comment         :
    NumberOfLogons  :
    Privileges      :
    PrimaryGroupId  :
    ScriptPath      :
    PasswordExpires :
    PasswordAge     :
    UserId          :
    Flags           : {}

    Name            : NT AUTHORITY\NETWORK SERVICE
    Caption         : NT AUTHORITY\NETWORK SERVICE
    LastLogon       :
    Comment         :
    NumberOfLogons  :
    Privileges      :
    PrimaryGroupId  :
    ScriptPath      :
    PasswordExpires :
    PasswordAge     :
    UserId          :
    Flags           : {}

    Name            : CL01\admin
    Caption         : admin
    LastLogon       : 8/25/2019 4:12:47 PM
    Comment         :
    NumberOfLogons  : 16
    Privileges      : Administrator
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 512.07:32:33
    UserId          : 1000
    Flags           : {NormalAccount}

    Name            : ACMELABS\Distle
    Caption         : Distle
    LastLogon       : 5/26/2019 2:22:45 AM
    Comment         :
    NumberOfLogons  : 9
    Privileges      : User
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 624.22:27:06
    UserId          : 1164
    Flags           : {PasswordNotExpires, NormalAccount}

    Name            : ACMELABS\rubenb
    Caption         : rubenb
    LastLogon       : 9/8/2020 2:41:03 PM
    Comment         :
    NumberOfLogons  : 2
    Privileges      : User
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 123.06:39:12
    UserId          : 1298
    Flags           : {PasswordNotExpires, NormalAccount}

    Name            : ACMELABS\thomasb
    Caption         : thomasb
    LastLogon       : 1/8/2021 4:46:15 PM
    Comment         :
    NumberOfLogons  : 11
    Privileges      : User
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 549.07:31:24
    UserId          : 1314
    Flags           : {PasswordNotExpires, NormalAccount}

    Name            : ACMELABS\Stlece
    Caption         : Stlece
    LastLogon       : 4/10/2019 7:37:45 PM
    Comment         :
    NumberOfLogons  : 10
    Privileges      : User
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 652.10:16:24
    UserId          : 1590
    Flags           : {PasswordNotExpires, NormalAccount}

    Name            : ACMELABS\cperez
    Caption         : cperez
    LastLogon       : 1/9/2021 3:32:14 PM
    Comment         :
    NumberOfLogons  : 487
    Privileges      : Administrator
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 2.13:13:41
    UserId          : 1618
    Flags           : {PasswordNotExpires, NormalAccount}

    Name            : ACMELABS\Administrator
    Caption         : Administrator
    LastLogon       : 1/9/2021 6:24:34 PM
    Comment         : Darkoperator.com
    NumberOfLogons  : 782
    Privileges      : Administrator
    PrimaryGroupId  : 513
    ScriptPath      :
    PasswordExpires :
    PasswordAge     : 512.07:24:30
    UserId          : 500
    Flags           : {NormalAccount}
    
    Running the function from an elevated prompt. 
    #>
    [CmdletBinding()]
    param (
        # CIMSession to perform query against
        [Parameter(ValueFromPipelineByPropertyName = $True,
            ValueFromPipeline = $true)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession
    )
    
    begin {
         # If no CIMSession is provided we create one for localhost.
         if ($null -eq $CimSession -or $CimSession.Count -eq 0) {
            $sessop = New-CimSessionOption -Protocol Dcom
            $CimSession += New-CimSession -ComputerName $env:COMPUTERNAME -SessionOption $sessop
        }

        $flags = @{
            "Disabled"= 2
            "LockedOut"= 16
            "NoPassword"= 32
            "CanNotChangePass"= 64
            "NormalAccount"= 512
            "InterDomTrustAcc"= 2048
            "WrkStTrustAcc"= 4096
            "ServerTrustAcc"= 8192
            "PasswordNotExpires"= 65536
            "MNS"= 131072
            "SmartCard"= 262144
            "Trusted4Delegation"= 524288
            "NoDelegate"= 1048576
            "DESOnly"= 2097152
            "NoPreAuth"= 4194304
            "PasswordExpired"= 8388608
        }
    }
    
    process {
        $wql = "select Name, Caption, LastLogon, Comment, NumberOfLogons, Privileges, PrimaryGroupId, ScriptPath, PasswordExpires, PasswordAge, UserId, Flags from Win32_NetworkLoginProfile"
        foreach($s in $CimSession) {
            Get-CimInstance -Query $Wql -CimSession $s | ForEach-Object {
                $objProps = [ordered]@{}
                $objprops.add('Name', $_.Name)
                $objprops.add('Caption', $_.Caption)
                $objprops.add('LastLogon', $_.LastLogon)
                $objprops.add('Comment', $_.Comment)
                $objprops.add('NumberOfLogons', $_.NumberOfLogons)
                if ($null -eq $_.privileges) {
                    $objprops.add('Privileges',"")
                } elseif (1 -eq $_.privileges) {
                    $objprops.add('Privileges', "User")
                } elseif (2 -eq $_.privileges) {
                    $objprops.add('Privileges', "Administrator")
                }
                
                $objprops.add('PrimaryGroupId', $_.PrimaryGroupId)
                $objprops.add('ScriptPath', $_.ScriptPath)
                $objprops.add('PasswordExpires', $_.PasswordExpires)
                $objprops.add('PasswordAge', $_.PasswordAge)
                $objprops.add('UserId', $_.UserId)
                $flag_values = @()
                foreach($m in $flags.keys){
                    if($flags[$m] -band  $_.flags){
                        $flag_values += $m
                    }
                } 
                $objprops.add('Flags', $flag_values)
                $obj = [PSCustomObject]$objProps
                $obj.pstypenames.insert(0,'PSGumshoe.NetLogonHistory')
                $obj
            }
        }
    }
    
    end {
        
    }
}