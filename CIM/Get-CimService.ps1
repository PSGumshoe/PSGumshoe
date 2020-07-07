function Get-CimService {
    <#
    .SYNOPSIS
         Queries via CIM Windows Service Information.
    .DESCRIPTION
        Queries via CIM Windows Service Information.
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [String[]]
        $Name,

        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [String[]]
        $DisplayName,

        [Parameter(mandatory=$false)]
        [String]
        [ValidateSet('Stopped', 'Start Pending', 'Stop Pending', 
            'Running', 'Continue Pending', 'Pause Pending', 'Paused', 
            'Unknown')]
        $State,

        [Parameter(mandatory=$false)]
        [String]
        [ValidateSet('Boot', 'System', 'Auto', 'Manual', 'Disabled')]
        $StartMode,

        [Parameter(mandatory=$false)]
        [String]
        [ValidateSet('Kernel Driver', 'File System Driver', 'Adapter', 
            'Recognizer Driver', 'Own Process', 'Share Process', 
            'Interactive Process')]
        $ServiceType,

        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [String[]]
        $PathName,

        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [String[]]
        $Description,

        # Type of service.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Driver', 'UserMode')]
        [string]
        $Type = 'UserMode',

        [Parameter(mandatory=$false)]
        [String[]]
        [ValidateSet(
            'AcceptPause',
            'AcceptStop',
            'Caption',
            'CreationClassName',
            'Description',
            'DesktopInteract',
            'DisplayName',
            'ErrorControl',
            'ExitCode',
            'InstallDate',
            'Name',
            'PathName',
            'ServiceSpecificExitCode',
            'ServiceType',
            'Started',
            'StartMode',
            'StartName',
            'State',
            'Status',
            'SystemCreationClassName',
            'SystemName',
            'TagId')]
        $Property = @('Name', 'DisplayName', 'Description', 'State', 'ServiceType', 'PathName'),

        [Parameter(mandatory=$false)]
        [Switch]
        $IncludeFileInfo,

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

        # Build WQL Query
        $PassedParams = $PSBoundParameters.Keys
        $filter = @()
        switch ($PassedParams) {
            "Name" {
                $nFilter = @()
                foreach($n in $name){
                    if ($n -match "\*") {
                       $nfilter += "Name LIKE '$($n.Replace('*','%'))'"
                    } else {
                       $nfilter += "Name = '$($n)'"
                    }  
                }
                $filter += "($($nfilter -join " OR "))"
            }

            "DisplayName" {
                $dnFilter = @()
                foreach($n in $DisplayName){
                    if ($n -match "\*") {
                       $dnFilter += "DisplayName LIKE '$($n.Replace('*','%'))'"
                    } else {
                       $dnFilter += "DisplayName = '$($n)'"
                    }  
                }
                $filter += "($($dnFilter -join " OR "))"
            }

            "Description" {
                $dFilter = @()
                foreach($d in $Description){
                    if ($d -match "\*") {
                       $dFilter += "Description LIKE '$($d.Replace('*','%'))'"
                    } else {
                       $dFilter += "Description = '$($d)'"
                    }  
                }
                $filter += "($($dFilter -join " OR "))"
            }

            "PathName" {
                $pFilter = @()
                foreach($p in $PathName){
                    if ($p -match "\*") {
                       $pFilter += "PathName LIKE '$($p.Replace('*','%'))'"
                    } else {
                       $pFilter += "PathName = '$($p)'"
                    }  
                }
                $filter += "($($pFilter -join " OR "))"
            }

            "State"  { 
                $eFilter = @()
                foreach($e in $ExecutablePath){
                    $efilter += "State = '($e)'"  
                }
                $filter += "($($efilter -join " OR "))"
            }
            "ServiceType" { 
                $srvTypeFilter = @()
                foreach($st in $ServiceType){
                    $srvTypeFilter += "ServiceType = $($st)"  
                }
                $filter += "($($srvTypeFilter -join " OR "))"
            }

             "StartMode" { 
                $smFilter = @()
                foreach($sm in $StartMode){
                    $smFilter += "StartMode = $($sm)"  
                }
                $filter += "($($smFilter -join " OR "))"
            }

            Default {}
        }
        
        $filterLogic =  ''
        if ($InvertLogic) {
            $filterLogic = "NOT"
        }
        if ($Type -eq "UserMode"){
            if ($filter.Length -eq 0) {
                $Wql = "SELECT $( $Property -join ',' ) FROM Win32_Service"
            } else {
                $Wql = "SELECT $( $Property -join ',' ) FROM Win32_Service WHERE $($filterLogic) $($filter -join " AND " )"
            }
        }

        if ($Type -eq "Driver"){
            if ($filter.Length -eq 0) {
                $Wql = "SELECT $( $Property -join ',' ) FROM Win32_SystemDriver"
            } else {
                $Wql = "SELECT $( $Property -join ',' ) FROM Win32_SystemDriver WHERE $($filterLogic) $($filter -join " AND " )"
            }
        }
    }
    
    process {
        Get-CimInstance -Query $Wql -CimSession $CimSession
    }
    
    end {
        
    }
}