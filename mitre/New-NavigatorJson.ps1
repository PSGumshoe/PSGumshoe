<#
.SYNOPSIS
    Tunrs a list of ID or Objects passed via the pipeline in to a MITRE Attack Navigator JSON file.
.DESCRIPTION
    Tunrs a list of ID or Objects passed via the pipeline in to a MITRE Attack Navigator JSON file.
    Main purpose is when working with a CSV file where one enters Technique/Tactic ID's,
    Comments and a Score to then pipe in to the cmmdlet to turn in to a JSON that can be used by the
    MITRE Attck Navigator for displaying the information in a layer.
.NOTES
    Information or caveats about the function e.g. 'This function is not supported in Linux'
.EXAMPLE
    Import-Csv .\Desktop\Lockbit3.csv | New-NavigatorJson -Path .\Desktop\lockbit.json 
    Turns a CSV with the fields Id for the techniqueID and comment in to a MITRE Attck Navigator Json file.
.EXAMPLE
    New-NavigatorJson -Name "Pentest Daily Technique D3" -path .\dayly3.json -Id @('T1134','T1612','T1548.001') -Color Purple -Comment "actions of day 3"
    Maually generate a a layer using a list of Technique IDs. 
#>
function New-NavigatorJson {
    [CmdletBinding()]
    param (
        # MITRE Attack Navigator Version
        [Parameter(mandatory=$false)]
        [string]
        $Version = "4.4",

        # Name of the layer.
        [Parameter(Mandatory=$false)]
        [string]
        $Name = "Technique Heatmap",

        # Description for the layer.
        [Parameter(Mandatory=$false)]
        [string]
        $Description = "",

        # Domain, default is mitre-enterprise
        [Parameter(mandatory=$false)]
        [ValidateSet("mitre-enterprise","mitre-mobile")]
        [string]
        $Domain = "mitre-enterprise",

        # Filter Platform to show.
        [Parameter(Mandatory=$false)]
        [ValidateSet("Linux",
                     "macOS",
                     "Windows",
                     "Network",
                     "PRE",
                     "Containers",
                     "Office 365",
                     "SaaS",
                     "Google Workspace",
                     "IaaS",
                     "Azure AD")]
        [string[]]
        $Platform = @("Linux",
                    "macOS",
                    "Windows",
                    "Network",
                    "PRE",
                    "Containers",
                    "Office 365",
                    "SaaS",
                    "Google Workspace",
                    "IaaS",
                    "Azure AD"),

        # MITRE Technique Id.
        [Parameter(Mandatory=$true,
            ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Id,

        # Score for the Technique.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [int]
        $Score,

        # Comment for the technique.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true)]
        [String]
        $Comment,

        # Color for the Technique and Tactic.
        [Parameter(Mandatory=$false)]
        [ValidateSet("Red","Blue","Orange","Green","Yellow","Brown","Purple")]
        [string]
        $Color,

        # Specifies a path to one or more locations.
        [Parameter(Mandatory=$true,
                   Position=0,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Path
    )
    
    begin {

        $BaseStructure = [ordered]@{
            'version'= $Version
            'name' = $Name
            'description' =  $Description
            'domain' = $Domain
            'filters' = @{'platforms'=$Platform}
        }

        $Colors = @{
            "Red" = "E53731"
            "Blue" = "#0E61C2"
            "Orange" = "#FA8F01"
            "Green" = "#3FB24D"
            "Yellow" = "#FDEC00"
            "Brown" = "#9A4C01"
            "Purple" = "#9312AC"
        }

        $techniques = @()
        
    }
    
    process {

        $Id | foreach-object {
            Write-Verbose -Message "Adding techinique $_"
            $Technique = @{'techniqueID'=$_}

            if ($PSBoundParameters.ContainsKey('score')) {
                $Technique.Add('score',$Score)
            }

            if ($PSBoundParameters.ContainsKey('comment')) {
                $Technique.Add('comment',$Comment)
            }

            if ($PSBoundParameters.ContainsKey('color')) {
                $Technique.Add('color',$Colors[$Color])
            }
            $techniques += $technique
        }
    }
    
    end {
        $BaseStructure.Add('techniques',$techniques)
        convertto-Json -InputObject $BaseStructure | Set-Content -Path $Path
    }
}