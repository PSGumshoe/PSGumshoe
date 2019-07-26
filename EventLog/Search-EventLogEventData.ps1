function Search-EventLogEventData {
    <#
    .SYNOPSIS
        Internal funtion for searching events with a keyed flat Event Data structure.
    .DESCRIPTION
        Internal funtion for searching events with a keyed flat Event Data structure.
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

        # Event Id to filter on
        [int[]]
        $EventId,

        # Record type to output.
        [string]
        $RecordType,

        # Event Log Provider.
        [string]
        $Provider
    )

    begin {

        # Get paramters for use in creating the filter.
        #$Params = $MyInvocation.BoundParameters.Keys
        $Params = $ParamHash.keys
        $CommonParams = ([System.Management.Automation.Cmdlet]::CommonParameters) + @('Credential', 'ComputerName', 'MaxEvents', 'StartTime', 'EndTime', 'Path', 'ChangeLogic','ActivityType','Suppress')

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
            $SelectFilter = " *[System/Provider[@Name='$($Provider)'] and ($($idFilter))] "
        } else {
            $SelectFilter = " (*[System/Provider[@Name='$($Provider)'] and (System/EventID=$($EventId))])"
        }


        $filter = " "
        # Manage change in Logic
        $logicOperator = 'and'
        if ($ParamHash['ChangeLogic']) {
            Write-Verbose -Message 'Logic per field has been inverted.'
           $logicOperator = 'or'
        }
        $filterBlockCount = 0
        foreach ($Param in $FinalParams) {
            if ($param -notin $CommonParams) {
               $FieldValue = $ParamHash["$($param)"]
               $FilterCount = 0
               foreach($val in $FieldValue) {
                    if ($FilterCount -gt 0) {
                       $filter = $filter + " or *[EventData[Data[@Name='$($Param)']='$($val)']]"
                    } else {
                        if ($Params -contains 'Suppress') {
                            $filter = $filter + " (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                        } else {
                            if ($filterBlockCount -gt 0) {
                                $filter = $filter + " $( $logicOperator ) (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                            } else {
                                $filter = $filter + " and (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                                $filterBlockCount += 1
                            }
                        }
                    }
                   $FilterCount += 1
               }
               $filter += ") "
            }
        }

        if ($null -eq $StartTime) {
            $StartTime = $StartTime.ToUniversalTime()
            $StartTimeFormatted = $StartTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($StartTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + " and *[System/TimeCreated[@SystemTime&gt;='$( $StartTimeFormatted )']]"
        }

        if ($null -eq $EndTime) {
            $EndTime = $EndTime.ToUniversalTime()
            $EndTimeFormatted = $EndTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($EndTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + " and *[System/TimeCreated[@SystemTime&lt;='$( $EndTimeFormatted )']]"
        }

        # Concatenate all the filters in to one single XML Filter.
        if ($Params -contains 'Path') {
            # Initiate variable that will be used for the Query Id for each in the QueryList.
            $QueryId = 0
            $Querys = ''

            # Resolve all paths provided and process each.
            (Resolve-Path -Path $ParamHash['Path']).Path | ForEach-Object {
                if ($FilterCount -eq 0) {
                    $Querys += "<Query Id='$($QueryId)' Path='file://$($_)'><Select>$($SelectFilter + $filter)</Select></Query>"
                } else {
                     if ($Params -contains 'Suppress') {
                        $Querys = "<Query Id='0' Path=`"file://$($_)`">"
                        $Querys += "<Select Path=`"file://$($_)`">$($SelectFilter)</Select>"
                        $Querys += "<Suppress Path=`"file://$($_)`">$($filter)</Suppress>"
                        $Querys += "</Query>" #>

                    } else {
                       $Querys += "<Query Id=`"$($QueryId)`" Path=`"file://$($_)`"><Select Path=`"file://$($_)`">$($SelectFilter + $filter)</Select></Query>"
                    }
                }
                $QueryId++
            }
            $BaseFilter = "<QueryList>$($Querys)</QueryList>"
        } else {
            if ($FilterCount -eq 0) {
               $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($SelectFilter + $filter)`n</Select>`n</Query>`n</QueryList>"
            } else {
                if ($Params -contains 'Suppress') {
                    $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n"
                    $BaseFilter += "<Select Path='$($LogName)'>$($SelectFilter)`n</Select>`n"
                    $BaseFilter += "<Suppress Path='$($LogName)'>$($filter)`n</Suppress>`n"
                    $BaseFilter += "</Query>`n</QueryList>"
                } else {
                    $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($SelectFilter + $filter)`n</Select>`n</Query>`n</QueryList>"
                }
            }

        }

        Write-Verbose -Message $BaseFilter
   }

   process {

       # Perform query and turn results in to a more easy to parse object.
       switch ($PSCmdlet.ParameterSetName) {
           'Remote' {
               $ComputerName | ForEach-Object {
                   if ($null -eq $Credential) {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                       }
                   } else {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                       }
                   }
               }
           }
           Default {
               if ($MaxEvents -gt 0) {
                   Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue | ConvertFrom-EventLogonRecord
               } else {
                   Get-WinEvent -FilterXml $BaseFilter -ErrorAction SilentlyContinue | ConvertFrom-EventLogonRecord
               }
           }
       }
   }

    end {
    }
}
