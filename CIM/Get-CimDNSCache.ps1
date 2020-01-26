function Get-CimDnsCache {
    <#
    .SYNOPSIS
        Get DNS Cache entries for Windows 8/2012 or above systems leveraging CIM.
    .DESCRIPTION
        Get DNS Cache entries for Windows 8/2012 or above systems leveraging CIM.
    .EXAMPLE
        PS C:\> Get-CimDNSCache -Name *acmelabs* -Type A

        Name         : dc1.acmelabs.pvt
        Entry        : dc1.acmelabs.pvt
        Data         : 10.120.120.2
        DataLength   : 4
        Section      : Answer
        Status       : Success
        TimeToLive   : 1774
        Type         : A
        ComputerName : CL01

        Get DNSCache entries where the name contains the string acmelabs and are for DNS record type A.
    .INPUTS
        Microsoft.Management.Infrastructure.CimSession
    .OUTPUTS
        PSGumshoe.Process
    #>
    [CmdletBinding()]
    param (
        # CIMSession to perform query against
        [Parameter(ValueFromPipelineByPropertyName = $True,
            ValueFromPipeline = $true)]
        [Alias('Session')]
        [Microsoft.Management.Infrastructure.CimSession[]]
        $CimSession,

        # Name of the record. This tends to be the FQDN requested.
        [Parameter(Mandatory =$false)]
        [SupportsWildcards()]
        [string[]]
        $Name,

        # Status of the cached query, if it was a successful one or if it failed why it did.
        [Parameter(Mandatory = $false)]
        [ValidateSet('Success', 'NotExist', 'NoRecords')]
        [string[]]
        $Status,

        # Type of record cached.
        [Parameter(Mandatory = $false)]
        [ValidateSet('A', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'AAAA', 'SRV')]
        [string[]]
        $Type,

        # Data what was the result retured. Example for A and AAAA it would be the IP and for CNAME a hostname. 
        [Parameter(Mandatory = $false)]
        [SupportsWildcards()]
        [string[]]
        $Data,

        # Invert the logic for matching record, entries that match the query will be excluded.
        [Parameter(Mandatory =  $false)]
        [switch]
        $InvertLogic
    )
    
    begin {

        $Record2Type = @{
            'A' = 1
            'NS' = 2 
            'CNAME' = 5 
            'SOA' = 6 
            'PTR' = 12 
            'MX' = 15 
            'AAAA' = 28 
            'SRV' = 33
        }

        $Type2Record = @{
            '1' = 'A'
            '2' = 'NS' 
            '5' = 'CNAME'
            '6' = 'SOA'
            '12' = 'PTR' 
            '15' = 'MX'
            '28' = 'AAAA' 
            '33' = 'SRV'
        }

        $Status2Val = @{
            'Success' = 0 
            'NotExist' = 9003 
            'NoRecords' = 9701
        }

        $Val2Status = @{
            '0' = 'Success'
            '9003' = 'NotExist'
            '9701' = 'NoRecords'
        }

        $Section = @{
            '1' = 'Answer' 
            '2' = 'Authority' 
            '3' = 'Additional'
        }

        # If no CIMSession is provided we create one for localhost.
        if ($null -eq $CimSession -or $CimSession.Count -eq 0) {
            $sessop = New-CimSessionOption -Protocol Dcom
            $CimSession += New-CimSession -ComputerName $Env:Computername -SessionOption $sessop
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
 
             "Data" { 
                 $dataFilter = @()
                 foreach($d in $Data){
                    if ($n -match "\*") {
                        $dataFilter += "Data LIKE '$($d.Replace('*','%'))'"
                     } else {
                        $dataFilter += "Data = '$($d)'"
                     }  
                 }
                 $filter += "($($dataFilter -join " OR "))"
             }
 
             "Status"  { 
                 $sFilter = @()
                 foreach($s in $Status){
                     $sFilter += "Status = $($Status2Val."$($s)")"  
                 }
                 $filter += "($($sFilter -join " OR "))"
             }
 
             "Type"  { 
                $tFilter = @()
                foreach($t in $Type){
                    $tFilter += "Type = $($Record2Type."$($t)")"  
                }
                $filter += "($($tFilter -join " OR "))"
            }
 
             Default {}
         }
         
         $filterLogic =  ''
         if ($InvertLogic) {
             $filterLogic = "NOT"
         }

         if ($filter.Length -eq 0) {
            $Wql = "SELECT * FROM MSFT_DNSClientCache"
        } else {
            $Wql = "SELECT * FROM MSFT_DNSClientCache WHERE $($filterLogic) $($filter -join " AND " )"
        }
        Write-Verbose -Message "Using WQL - $($Wql)"
        
    }
    
    process {

        Get-CimInstance -Namespace root/StandardCimv2 -Query $Wql -CimSession $CimSession | ForEach-Object {
            $objprops = [ordered]@{}
            $objprops.add('Name',$_.name)
            $objprops.add('Entry',$_.Entry)
            $objprops.add('Data',$_.Data)
            $objprops.add('DataLength',$_.DataLength)
            $objprops.add('Section',$Section."$($_.Section)")
            $objprops.add('Status', $Val2Status["$($_.Status)"])
            $objprops.add('TimeToLive',$_.TimeToLive)
            $objprops.add('Type', $Type2Record["$($_.Type)"])
            $objprops.add('ComputerName',$_.PSComputerName)
            $obj = [PSCustomObject]$objProps
            $obj.pstypenames.insert(0,'PSGumshoe.DNSCacheEntry')
            $obj
        }
    }
    
    end {
        
    }
}