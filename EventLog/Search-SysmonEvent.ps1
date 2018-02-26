function Search-SysmonEvent {
    <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
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
        # Parameters of cmdlet using this helper function.
        $ParamHash,

        # Sysmon Event Id to filter on
        [int[]]
        $EventId,

        # Record type to output.
        [string]
        $RecordType
    )

    begin {

        # Get paramters for use in creating the filter.
        #$Params = $MyInvocation.BoundParameters.Keys
        $Params = $ParamHash.keys
        $CommonParams = ([System.Management.Automation.Cmdlet]::CommonParameters) + @('Credential', 'ComputerName', 'MaxEvents', 'StartTime', 'EndTime', 'Path', 'ChangeLogic')

        $FinalParams = @()
        foreach ($p in $Params) {
            if ($p -notin $CommonParams) {
                $FinalParams += $p
            }
        }
        # Build filters based on options available.
        if ($EventId.Length -gt 1) {
            $IdFilterCount = 0
            foreach($id in $EventId) {
                if ($IdFilterCount -eq 0) {
                   $idFilter =  "(System/EventID=$($id))"
                } else {
                    $idFilter += " or (System/EventID=$($id))"
                }
                $IdFilterCount++
            }
            $filter = "`n*[System/Provider[@Name='microsoft-windows-sysmon'] and ($($idFilter))] "
        } else {
            $filter = "`n*[System/Provider[@Name='microsoft-windows-sysmon'] and (System/EventID=$($EventId))] "
        }


        # Manage change in Logic
        $logicOperator = 'and'
        if ($ChangeLogic) {
           $logicOperator = 'or'
        }

        $FilterCount = 0
        foreach ($Param in $FinalParams) {
            if ($param -notin $CommonParams) {
               $FieldValue = $ParamHash["$($param)"]
               foreach($val in $FieldValue) {
                   if ($FilterCount -gt 0) {
                       $filter = $filter + "`n $( $logicOperator ) *[EventData[Data[@Name='$($Param)']='$($val)']]"
                   } else {
                       $filter = $filter + "`n and (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                   }
                   $FilterCount += 1
               }
            }
        }

        if ($StartTime -ne $null) {
            $StartTime = $StartTime.ToUniversalTime()
            $StartTimeFormatted = $StartTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($StartTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + "`n and *[System/TimeCreated[@SystemTime&gt;='$( $StartTimeFormatted )']]"
        }

        if ($EndTime -ne $null) {
            $EndTime = $EndTime.ToUniversalTime()
            $EndTimeFormatted = $EndTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($EndTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + "`n and *[System/TimeCreated[@SystemTime&lt;='$( $EndTimeFormatted )']]"
        }

        # Concatenate all the filters in to one single XML Filter.
        if ($Params -contains 'Path') {
            # Initiate variable that will be used for the Query Id for each in the QueryList.
            $QueryId = 0
            $Querys = ''

            # Resolve all paths provided and process each.
            (Resolve-Path -Path $ParamHash['Path']).Path | ForEach-Object {
                if ($FilterCount -eq 0) {
                    $Querys += "`n<Query Id='$($QueryId)' Path='file://$($_)'>`n<Select>$($filter)`n</Select>`n</Query>"
                } else {
                    $Querys += "`n<Query Id='$($QueryId)' Path='file://$($_)'>`n<Select>$($filter))`n</Select>`n</Query>"
                }
                $QueryId++
            }
            $BaseFilter = "<QueryList>`n$($Querys)`n</QueryList>"
        } else {
            if ($FilterCount -eq 0) {
               $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($filter)`n</Select>`n</Query>`n</QueryList>"
            } else {
                $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($filter))`n</Select>`n</Query>`n</QueryList>"
            }

        }

        Write-Verbose -Message $BaseFilter
   }

   process {

       # Perform query and turn results in to a more easy to parse object.
       switch ($PSCmdlet.ParameterSetName) {
           'Remote' {
               $ComputerName | ForEach-Object {
                   if ($Credential -eq $null) {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ | ConvertFrom-SysmonEventLogRecord  -RecordType $RecordType
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_| ConvertFrom-SysmonEventLogRecord  -RecordType $RecordType
                       }
                   } else {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -Credential $Credential | ConvertFrom-SysmonEventLogRecord -RecordType $RecordType
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -Credential $Credential | ConvertFrom-SysmonEventLogRecord -RecordType $RecordType
                       }
                   }
               }
           }
           Default {
               if ($MaxEvents -gt 0) {
                   Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents | ConvertFrom-SysmonEventLogRecord -RecordType $RecordType
               } else {
                   Get-WinEvent -FilterXml $BaseFilter | ConvertFrom-SysmonEventLogRecord -RecordType $RecordType
               }
           }
       }
   }

    end {
    }
}