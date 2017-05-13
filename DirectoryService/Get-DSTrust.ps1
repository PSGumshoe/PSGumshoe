<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.EXAMPLE
    PS C:\> <example usage>
    Explanation of what the example does
#>
function Get-DSTrust {
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        # Domain controller to connect to when not in a domain.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,

        # Credentials to use for getting forest information.
        [Parameter(ParameterSetName = 'OtherForest',
                    Mandatory = $false)]
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        # Forest name.
        [Parameter(ParameterSetName = 'OtherForest',
                   Mandatory = $true)]
        [string]
        $ForestName,

        # Trust type (Forest or all Domains)
        [Parameter(Mandatory=$false)]
        [ValidateSet('Domain','Forest')]
        [String]
        $TrustType = 'Domain'
    )

    begin {
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            'Current' { 
                $forest = Get-DSForest
            }
            'Remote' { 
                $forest = Get-DSForest -ComputerName $ComputerName -Credential $Credential
            }
            'OtherForest' {
                $forest = Get-DSForest -ComputerName $ComputerName -Credential $Credential -ForestName $ForestName
            }
            Default {}
        }


        switch ($TrustType) {
            'Domain' { $forest.Domains | ForEach-Object {$_.GetAllTrustRelationships()} }
            'Forest' { $forest.GetAllTrustRelationships()}
            Default { }
        }		
    }

    end {}

}