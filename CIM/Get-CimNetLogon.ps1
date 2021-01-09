function Get-CimNetLogon {
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

        $privs = @{ 
            0 ="Guess"
            1 = "User"
            2 = "Administrator" 
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