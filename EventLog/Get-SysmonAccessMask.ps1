function Get-SysmonAccessMask {
    <#
    .SYNOPSIS
        Get the list of privileges for a given Sysmon Process Access Mask or get a mask for a given list.
    .DESCRIPTION
        Get the list of privileges for a given Sysmon Process Access Mask or get a mask for a given list.
    .EXAMPLE
        PS C:\> Get-SysmonAccessMask -AccessMask 0x418                                                              
        PROCESS_QUERY_INFORMATION
        PROCESS_VM_OPERATION
        PROCESS_VM_READ
        For a given access mask return a list of access rights.
    .EXAMPLE
        PS C:\> Get-SysmonAccessMask -AccessRight PROCESS_VM_READ,PROCESS_VM_OPERATION,PROCESS_QUERY_INFORMATION
        0x418
        For a list of access rights return an access mask for use in Sysmon filtering.
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        String
        String[]
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName = 'Mask')]
    param (
        # Acces mask names.
        [Parameter(Mandatory=$true,
            ParameterSetName='Access')]
        [ValidateSet("PROCESS_CREATE_PROCESS", "PROCESS_CREATE_THREAD", "PROCESS_DUP_HANDLE","PROCESS_SET_INFORMATION",
        "PROCESS_SET_QUOTA", "PROCESS_QUERY_LIMITED_INFORMATION", "PROCESS_QUERY_INFORMATION", "PROCESS_SUSPEND_RESUME",
        "PROCESS_TERMINATE", "PROCESS_VM_OPERATION", "PROCESS_VM_READ", "PROCESS_VM_WRITE", "SYNCHRONIZE")]
        [string[]]
        $AccessRight,

        # Access mask 
        [Parameter(Mandatory = $true,
        ParameterSetName = 'Mask')]
        [Int32]
        $AccessMask
        
    )
    
    begin {
        $ProcessPermissions = @{
            "PROCESS_CREATE_PROCESS" = 0x0080
            "PROCESS_CREATE_THREAD" = 0x0002
            "PROCESS_DUP_HANDLE" = 0x0040
            "PROCESS_SET_INFORMATION" = 0x0200
            "PROCESS_SET_QUOTA" = 0x0100
            "PROCESS_QUERY_LIMITED_INFORMATION" = 0x1000
            "PROCESS_QUERY_INFORMATION" = 0x0400
            "PROCESS_SUSPEND_RESUME" = 0x0800
            "PROCESS_TERMINATE" = 0x0001
            "PROCESS_VM_OPERATION" = 0x0008
            "PROCESS_VM_READ" = 0x0010
            "PROCESS_VM_WRITE" = 0x0020
            "SYNCHRONIZE" = 0x00100000
        }
    }
    
    process {
        switch ($pscmdlet.ParameterSetName) {
            'Mask' { 
                $mask_values = @()
                foreach($m in $ProcessPermissions.keys){
                    if($ProcessPermissions[$m] -band  $AccessMask){
                        $mask_values += $m
                    }
                }
                $mask_values 
            }

            'Access' {
                $mask = 0
                foreach($access in $AccessRight) {
                    $mask = $mask -bor $ProcessPermissions[$access]
                }
                "0x$([Convert]::ToString($mask, 16))"
            }
        }
    }
    
    end {
    }
}