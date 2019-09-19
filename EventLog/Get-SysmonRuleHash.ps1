function Get-SysmonRuleHash {
    <#
    .SYNOPSIS
        Get a hash for the currently configured Sysmon rules on a host.
    .DESCRIPTION
        Get a hash for the currently configured Sysmon rules on a host. The hash is generated from
        the binary value found under the driver configuration.
    .EXAMPLE
        PS C:\> Get-SysmonRuleHash -HashAlgorithm SHA1

        ComputerName    DriverName Hash
        ------------    ---------- ----
        DESKTOP-4TVLVMD SysmonDrv  5FCE2EA1583DBBD5B141EFD04BA36209F5AFE1FC

        Generate a SHA1 for the ruleset on the current host.
    .INPUTS
        String
    .OUTPUTS
        PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding( DefaultParameterSetName = "UseComputer")]
    param (
        # Name of Sysmon driver.
        [Parameter(ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)]
        [string]
        $DriverName = "SysmonDrv",

        # Computer name, IP or FQDN of host to connect against using CIM.
        [parameter(ValueFromPipeline = $true,            
            ValueFromPipelineByPropertyName = $true)]            
        [parameter(ParameterSetName = "UseComputer")]             
        [string]
        $ComputerName = "$env:COMPUTERNAME",            
                    
        # CIM Session to remote host.
        [parameter(ValueFromPipeline = $true,            
            ValueFromPipelineByPropertyName = $true)]            
        [parameter(ParameterSetName = "UseCIMSession")]             
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession,

        # Hash Algorithm to use when generating the hash.
        [Parameter(ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]
    	$HashAlgorithm = "SHA256"
        
    )
    
    begin {
        [uint32]$hdkey = 2147483650
        $hashType = [Type] "System.Security.Cryptography.$HashAlgorithm"
		$hasher = $hashType::Create()
    }
    
    process {
        $arglist = @{
            hDefKey = $hdkey
            sSubKeyName = "SYSTEM\CurrentControlSet\Services\$($DriverName)\Parameters"
            sValueName = "Rules"}

        switch ($psCmdlet.ParameterSetName) {            
            "UseComputer"    {
                if ($ComputerName -eq $env:COMPUTERNAME) {
                    $result = Invoke-CimMethod -Namespace "root\cimv2" -ClassName StdRegProv -MethodName "GetBinaryValue"  -Arguments $arglist
                } else {
                    $result = Invoke-CimMethod -Namespace "root\cimv2" -ClassName StdRegProv -MethodName "GetBinaryValue"  -Arguments $arglist -ComputerName $ComputerName
                }
            }            
            "UseCIMSession"  {$result = Invoke-CimMethod -Namespace "root\cimv2" -ClassName StdRegProv -MethodName "GetBinaryValue"  -Arguments $arglist -CimSession $CimSession }            
            default {}            
           }   

           if ($result.returnValue -eq 0) {
                $objProps = [ordered]@{
                    'ComputerName' = $ComputerName
                    'DriverName' = $DriverName
                    'Hash' = ([System.BitConverter]::ToString($hasher.ComputeHash($result.uValue))).Replace("-",'')
                } 
                
                [PSCustomObject]$objProps
            } else {
                Write-Error -Message "No ruleset found in $($ComputerName) for driver $( $DriverName )"
            }
    }
    
    end {
    }
}