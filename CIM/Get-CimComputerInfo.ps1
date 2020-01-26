function Get-CimComputerInfo {
    <#
    .SYNOPSIS
        Queries via CIM computer and operating system information.
    .DESCRIPTION
        Queries via CIM computer and operating system information. Information is pulled form the Win32_OperatingSystem and Win32_ComputerSystem classes.
    .EXAMPLE
        PS C:\>  Get-CimComputerInfo


        ComputerName              : DESKTOP-4TVLVMD
        OS                        : Microsoft Windows 10 Enterprise
        Version                   : 10.0.17134
        InstallDate               : 6/4/2018 10:00:22 PM
        LastBootUpTime            : 1/3/2020 7:09:50 PM
        BootupState               : Normal boot
        LocalDateTime             : 1/8/2020 5:12:38 PM
        OSArchitecture            : 64-bit
        OSLanguage                : 1033
        MUILanguages              : {en-US}
        SystemDevice              : \Device\HarddiskVolume2
        SystemDirectory           : C:\WINDOWS\system32
        SystemDrive               : C:
        BootDevice                : \Device\HarddiskVolume1
        WindowsDirectory          : C:\WINDOWS
        Roles                     : {LM_Workstation, LM_Server, NT, Potential_Browser...}
        CurrentTimeZone           : -240
        EnableDaylightSavingsTime : True
        HypervisorPresent         : True
        Manufacturer              : VMware, Inc.
        Model                     : VMware Virtual Platform
        Domain                    : WORKGROUP
        Workgroup                 : WORKGROUP
        NumberOfProcessors        : 1
        NumberOfLogicalProcessors : 4
        TotalPhysicalMemory       : 8589398016
        Explanation of what the example does
    .INPUTS
        Microsoft.Management.Infrastructure.CimSession[]
    .OUTPUTS
        PSGumshoe.OSInfo
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
        $CimSession
    )
    
    begin {
         # If no CIMSession is provided we create one for localhost.
         if ($null -eq $CimSession -or $CimSession.Count -eq 0) {
            $sessop = New-CimSessionOption -Protocol Dcom
            $CimSession += New-CimSession -ComputerName $env:COMPUTERNAME -SessionOption $sessop
        }

        
    }
    
    process {
        foreach($s in $CimSession) {
            $Wql = "SELECT CSName, Caption, InstallDate, BootDevice, LastBootUpTime,CurrentTimeZone, LocalDateTime, OSArchitecture, OSLanguage, Version, MUILanguages, SystemDevice, SystemDirectory, SystemDrive, WindowsDirectory FROM win32_operatingsystem" 
            $osInfo = Get-CimInstance -Query $Wql -CimSession $s
            $Cwql = "SELECT BootupState, Roles, EnableDaylightSavingsTime, HypervisorPresent,Manufacturer, Model, Domain, Workgroup,NumberOfProcessors,NumberOfLogicalProcessors,TotalPhysicalMemory FROM win32_computersystem"
            $compInfo = Get-CimInstance -Query $Cwql -CimSession $s
            $objprops = [ordered]@{}
            $objprops.add('ComputerName', $osinfo.CSName)
            $objprops.add('OS', $osinfo.Caption)
            $objprops.add('Version', $osinfo.Version)
            $objprops.add('InstallDate', $osinfo.InstallDate)
            $objprops.add('LastBootUpTime', $osinfo.LastBootUpTime)
            $objprops.add('BootupState', $compInfo.BootupState)
            $objprops.add('LocalDateTime', $osinfo.LocalDateTime)
            $objprops.add('OSArchitecture', $osinfo.OSArchitecture)
            $objprops.add('OSLanguage', $osinfo.OSLanguage)
            $objprops.add('MUILanguages', $osinfo.MUILanguages)
            $objprops.add('SystemDevice', $osinfo.SystemDevice)
            $objprops.add('SystemDirectory', $osinfo.SystemDirectory)
            $objprops.add('SystemDrive', $osinfo.SystemDrive)
            $objprops.add('BootDevice', $osinfo.BootDevice)
            $objprops.add('WindowsDirectory', $osinfo.WindowsDirectory)
            $objprops.add('Roles', $compInfo.Roles),
            $objprops.add('CurrentTimeZone', $osinfo.CurrentTimeZone),
            $objprops.add('EnableDaylightSavingsTime', $compInfo.EnableDaylightSavingsTime)
            $objprops.add('HypervisorPresent', $compInfo.HypervisorPresent),
            $objprops.add('Manufacturer', $compInfo.Manufacturer),
            $objprops.add('Model', $compInfo.Model),
            $objprops.add('Domain', $compInfo.Domain),
            $objprops.add('Workgroup', $compInfo.Workgroup),
            $objprops.add('NumberOfProcessors', $compInfo.NumberOfProcessors),
            $objprops.add('NumberOfLogicalProcessors', $compInfo.NumberOfLogicalProcessors),
            $objprops.add('TotalPhysicalMemory', $compInfo.TotalPhysicalMemory)
            $obj = [PSCustomObject]$objProps
            $obj.pstypenames.insert(0,'PSGumshoe.OSInfo')
            $obj
        }
    }
    
    end {
        
    }
}