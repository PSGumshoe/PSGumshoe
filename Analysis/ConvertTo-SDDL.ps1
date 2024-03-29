<#
.SYNOPSIS
    Function to parse a SDDL string into a RawSecurityDescriptor object.

.DESCRIPTION
    Function to parse a SDDL string into a RawSecurityDescriptor object.

.PARAMETER SDDL
    String representation of a SDDL.

.INPUTS
    string

.OUTPUTS
    RawSecurityDescriptor

.EXAMPLE
    ConvertTo-SDDL -SDDL "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-32-544)"
 
#>
function ConvertTo-SDDL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SDDL
    )

    $acl = New-Object System.Security.AccessControl.RawSecurityDescriptor($sddl)
    $acl
}