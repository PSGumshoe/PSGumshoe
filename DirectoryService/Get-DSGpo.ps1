<#
.Synopsis
   Get GPO objects.
.DESCRIPTION
   Get all GPO objects or those that match the specified properties.
.EXAMPLE
   PS C:\> Get-DSGpo -ModifiedAfter (Get-Date).AddMonths(-1)
   Find all GPO Objects mofied in the last 30 days. 
.EXAMPLE
   PS C:\> Get-DSGpo -ModifiedAfter (Get-Date).AddMonths(-1) -UserExtension "*35378EAC-683F-11D2-A89A-00C04FBBCFA2*"
   Find GPOs with the specified User Extension GUID.
#>
function Get-DSGpo
{
    [CmdletBinding()]
    Param
    (
         # Domain controller.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [string]
        $ComputerName,
        
        # Credentials to use connection.
        [Parameter(ParameterSetName = 'Remote',
                   Mandatory = $true)]
        [Parameter(ParameterSetName = 'Alternate',
                   Mandatory = $true)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,
        
        [Parameter(Mandatory=$false)]
        [string]
        $searchRoot,
        
        [Parameter(Mandatory=$false)]
        [int]
        $PageSize = 100,
        
        [Parameter(Mandatory=$false,
                   HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]
        $SearchScope = "Subtree",
        
        [Parameter(Mandatory=$false,
                   HelpMessage="Specifies the available options for examining security information of a directory object")]
        [ValidateSet("None","Dacl","Group","Owner","Sacl")]
        [string[]]
        $SecurityMask = "None",
        
        
        [Parameter(Mandatory=$false,
                   HelpMessage="Date to search for GPO mofied on or after this date.")]
        [datetime]
        $ModifiedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage="Date to search for GPO mofied on or before this date.")]
        [datetime]
        $ModifiedBefore,

        [Parameter(Mandatory=$false,
                   HelpMessage="Date to search for GPO created on or after this date.")]
        [datetime]
        $CreatedAfter,

        [Parameter(Mandatory=$false,
                   HelpMessage="Date to search for GPO created on or after this date.")]
        [datetime]
        $CreatedBefore,
        
        
        [Parameter(Mandatory=$false,
                   HelpMessage="Name of GPO to match search on.")]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $Name,

        [Parameter(Mandatory=$false,
                   HelpMessage="Display name of the GPO to match search on.")]
        [ValidateNotNullOrEmpty()]
        [SupportsWildcards()]
        [string]
        $DisplayName,

        # User extension GUIDs to filter on."
        [Parameter(Mandatory=$false)]
        [string[]]
        $UserExtension,

        # Machine extension GUIDs to filter on."
        [Parameter(Mandatory=$false)]
        [string[]]
        $MachineExtension
    )

    Begin
    {
        $gpoFilter = '(objectClass=groupPolicyContainer)'
        $TempFilter = ""

        # Filter for modification time
        if ($ModifiedAfter -and $ModifiedBefore)
        {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }
        elseif ($ModifiedAfter)
        {
            $TempFilter = "$($TempFilter)(whenChanged>=$($ModifiedAfter.ToString('yyyyMMddhhmmss.sZ')))"
        }
        elseif ($ModifiedBefore)
        {
            $TempFilter = "$($TempFilter)(whenChanged<=$($ModifiedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }

        # Fileter for creation time
        if ($CreatedAfter -and $CreatedBefore)
        {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }
        elseif ($CreatedAfter)
        {
            $TempFilter = "$($TempFilter)(whencreated>=$($CreatedAfter.ToString('yyyyMMddhhmmss.sZ')))"
        }
        elseif ($CreatedBefore)
        {
            $TempFilter = "$($TempFilter)(whencreated<=$($CreatedBefore.ToString('yyyyMMddhhmmss.sZ')))"
        }

        if ($Name)
        {
            $TempFilter = "$($TempFilter)(name=$($Name))"
        }

        if ($DisplayName)
        {
            $TempFilter = "$($TempFilter)(displayname=$($DisplayName))"
        }

        # Filter on User Extension GUID.
        if ($UserExtension) {
            $initialFilter = ''
            foreach ($uext in $UserExtension) {
                $initialFilter += "(gpcuserextensionnames=*$($uext)*)"
            }
            $TempFilter += "(|$($initialFilter))"
        }

        # Filter on Machine Extension Filter.
        if ($MachineExtension) {
            $initialFilter = ''
            foreach ($uext in $MachineExtension) {
                $initialFilter += "(gpcmachineextensionnames=*$($uext)*)"
            }
            $TempFilter += "(|$($initialFilter))"
        }

        $GpoGuidRef = @{
            '{b05566ac-fe9c-4368-be01-7a4cbb6cba11}' = 'WindowsFirewall'
            '{0ACDD40C-75AC-47ab-BAA0-BF6DE7E7FE63}' = 'Wireless Group Policy'
            '{16be69fa-4209-4250-88cb-716cf41954e0}' = 'Central Access Policy Configuration'
            '{346193F5-F2FD-4DBD-860C-B88843475FD3}' = 'ConfigMgr User State Management Extension'
            '{426031c0-0b47-4852-b0ca-ac3d37bfcb39}' = 'QoS Packet Scheduler'
            '{4bcd6cde-777b-48b6-9804-43568e23545d}' = 'Remote Desktop USB Redirection'
            '{4d968b55-cac2-4ff5-983f-0a54603781a3}' = 'Work Folders'
            '{728EE579-943C-4519-9EF7-AB56765798ED}' = 'Group Policy Data Sources'
            '{7933F41E-56F8-41d6-A31C-4148A711EE93}' = 'Windows Search Group Policy Extension'
            '{BA649533-0AAC-4E04-B9BC-4DBAE0325B12}' = 'Windows To Go Startup Options'
            '{C34B2751-1CF4-44F5-9262-C3FC39666591}' = 'Windows To Go Hibernate Options'
            '{c6dc5466-785a-11d2-84d0-00c04fb169f7}' = 'Software Installation (appmgmts.dll)'
            '{e437bc1c-aa7d-11d2-a382-00c04f991e27}' = 'IP Security'
            '{fbf687e6-f063-4d9f-9f4f-fd9a26acdd5f}' = 'CP (gptext.dll)'
            '{D76B9641-3288-4f75-942D-087DE603E3EA}' = 'AdmPwd (LAPS)'
            '{40B6664F-4972-11D1-A7CA-0000F87571E3}' = 'Scripts (Startup/Shutdown)'
            '{00000000-0000-0000-0000-000000000000}' = 'Core GPO Engine'
            '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Preference CSE GUID Environment Variables'
            '{0F6B957D-509E-11D1-A7CC-0000F87571E3}' = 'Tool Extension GUID (Computer Policy Settings)'
            '{0F6B957E-509E-11D1-A7CC-0000F87571E3}' = 'Tool Extension GUID (User Policy Settings) Restrict Run'
            '{1612b55c-243c-48dd-a449-ffc097b19776}' = 'Preference Tool CSE GUID Data Sources'
            '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Preference CSE GUID Local users and groups'
            '{1A6364EB-776B-4120-ADE1-B63A406A76B5}' = 'Preference CSE GUID Devices'
            '{1b767e9a-7be4-4d35-85c1-2e174a7ba951}' = 'Preference Tool CSE GUID Devices'
            '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
            '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Preference Tool CSE GUID Drives'
            '{3060E8CE-7020-11D2-842D-00C04FA372D4}' = 'Remote Installation Services'
            '{35141B6B-498A-4CC7-AD59-CEF93D89B2CE}' = 'Preference Tool CSE GUID Environment Variables'
            '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = 'Registry Settings'
            '{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}' = 'Microsoft Disk Quota'
            '{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}' = 'Preference CSE GUID Network Options'
            '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}' = 'Preference Tool CSE GUID Files'
            '{3BFAE46A-7F3A-467B-8CEA-6AA34DC71F53}' = 'Preference Tool CSE GUID Folder Options'
            '{3EC4E9D3-714D-471F-88DC-4DD4471AAB47}' = 'Preference Tool CSE GUID Folders'
            '{40B66650-4972-11D1-A7CA-0000F87571E3}' = 'Scripts (Logon/Logoff) Run Restriction'
            '{42B5FAAE-6536-11d2-AE5A-0000F87571E3}' = 'ProcessScriptsGroupPolicy'
            '{47BA4403-1AA0-47F6-BDC5-298F96D1C2E3}' = 'Print Policy in PolicyMaker'
            '{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}' = 'Internet Explorer Zonemapping'
            '{516FC620-5D34-4B08-8165-6A06B623EDEB}' = 'Preference Tool CSE GUID Ini Files'
            '{53D6AB1D-2488-11D1-A28C-00C04FB94F17}' = 'Certificates Run Restriction'
            '{5794DAFD-BE60-433f-88A2-1A31939AC01F}' = 'Preference CSE GUID Drives'
            '{5C935941-A954-4F7C-B507-885941ECE5C4}' = 'Preference Tool CSE GUID Internet Settings'
            '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Preference CSE GUID Folders'
            '{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}' = 'Preference CSE GUID Network Shares'
            '{7150F9BF-48AD-4da4-A49C-29EF4A8369BA}' = 'Preference CSE GUID Files'
            '{74EE6C03-5363-4554-B161-627540339CAB}' = 'Preference CSE GUID Ini Files'
            '{79F92669-4224-476c-9C5C-6EFB4D87DF4A}' = 'Preference Tool CSE GUID Local users and groups'
            '{7B849a69-220F-451E-B3FE-2CB811AF94AE}' = 'Internet Explorer User Accelerators/PolicyMaker'
            '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}' = 'Computer Restricted Groups'
            '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = 'Security'
            '{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}' = 'Folder Redirection'
            '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed Printer Connections'
            '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Preference CSE GUID Services'
            '{942A8E4F-A261-11D1-A760-00C04FB9603F}' = 'Software Installation (Computers)'
            '{949FB894-E883-42C6-88C1-29169720E8CA}' = 'Preference Tool CSE GUID Network Options'
            '{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}' = 'Preference Tool CSE GUID Power Options'
            '{A2E30F80-D7DE-11d2-BBDE-00C04F86AE3B}' = 'Internet Explorer Maintenance policy processing'
            '{A3F3E39B-5D83-4940-B954-28315B82F0A8}' = 'Preference CSE GUID Folder Options'
            '{A8C42CEA-CDB8-4388-97F4-5831F933DA84}' = 'Preference Tool CSE GUID Printers'
            '{AADCED64-746C-4633-A97C-D61349046527}' = 'Preference CSE GUID Scheduled Tasks'
            '{B087BE9D-ED37-454f-AF9C-04291E351182}' = 'Preference CSE GUID Registry'
            '{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}' = 'EFS Recovery'
            '{B587E2B1-4D59-4e7e-AED9-22B9DF11D053}' = '802.3 Group Policy'
            '{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}' = 'Preference Tool CSE GUID Regional Options'
            '{BACF5C8A-A3C7-11D1-A760-00C04FB9603F}' = 'Software Installation (Users) Run Restriction'
            '{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}' = 'Preference CSE GUID Printers'
            '{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}' = 'Preference Tool CSE GUID Registry'
            '{BFCBBEB0-9DF4-4c0c-A728-434EA66A0373}' = 'Preference Tool CSE GUID Network Shares'
            '{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}' = 'Preference CSE GUID Shortcuts'
            '{C631DF4C-088F-4156-B058-4375F0853CD8}' = 'Microsoft Offline Files'
            '{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}' = 'Preference Tool CSE GUID Scheduled Tasks'
            '{CC5746A9-9B74-4be5-AE2E-64379C86E0E4}' = 'Preference Tool CSE GUID Services'
            '{cdeafc3d-948d-49dd-ab12-e578ba4af7aa}' = 'TCPIP'
            '{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}' = 'Preference Tool CSE GUID Shortcuts'
            '{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}' = 'Internet Explorer Machine Accelerators'
            '{CF848D48-888D-4F45-B530-6A201E62A605}' = 'Preference Tool CSE GUID Start Menu'
            '{D02B1F72-3407-48AE-BA88-E8213C6761F1}' = 'Tool Extension GUID (Computer Policy Settings)'
            '{D02B1F73-3407-48AE-BA88-E8213C6761F1}' = 'Tool Extension GUID (User Policy Settings)'
            '{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}' = 'Preference CSE GUID Internet Settings'
            '{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}' = 'Preference CSE GUID Start Menu'
            '{E5094040-C46C-4115-B030-04FB2E545B00}' = 'Preference CSE GUID Regional Options'
            '{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}' = 'Preference CSE GUID Power Options'
            '{F0DB2806-FD46-45B7-81BD-AA3744B32765}' = 'Policy Maker'
            '{F17E8B5B-78F2-49A6-8933-7B767EDA5B41}' = 'Policy Maker'
            '{F27A6DA8-D22B-4179-A042-3D715F9E75B5}' = 'Policy Maker'
            '{f3ccc681-b74c-4060-9f26-cd84525dca2a}' = 'Audit Policy Configuration'
            '{F581DAE7-8064-444A-AEB3-1875662A61CE}' = 'Policy Maker'
            '{F648C781-42C9-4ED4-BB24-AEB8853701D0}' = 'Policy Maker'
            '{F6E72D5A-6ED3-43D9-9710-4440455F6934}' = 'Policy Maker'
            '{F9C77450-3A41-477E-9310-9ACD617BD9E3}' = 'Group Policy Applications'
            '{FB2CA36D-0B40-4307-821B-A13B252DE56C}' = 'Enterprise QoS'
            '{FC715823-C5FB-11D1-9EEF-00A0C90347FF}' = 'Internet Explorer Maintenance Extension protocol'
            '{FD2D917B-6519-4BF7-8403-456C0C64312F}' = 'Policy Maker'
            '{FFC64763-70D2-45BC-8DEE-7ACAF1BA7F89}' = 'Policy Maker'
            '{53D6AB1B-2488-11D1-A28C-00C04FB94F17}' = 'EFS Policy'
            '{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}' = 'Computer Policy Setting'
        }

        $gpoFilter = "(&$($gpoFilter)$($TempFilter))"
    }
    Process
    {
        write-verbose -message "Executing search with filter $gpoFilter"
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' { 
                if ($searchRoot) {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -SearchRoot $searchRoot -Credential $Credential -Filter $gpoFilter

                } else {
                    $objSearcher = Get-DSDirectorySearcher -ComputerName $ComputerName -Credential $Credential -Filter $gpoFilter
                }
                
             }
            'Alternate' {
                $objSearcher = Get-DSDirectorySearcher -Credential $Credential -Filter $gpoFilter
            }
            'Current' {
                $objSearcher = Get-DSDirectorySearcher -Filter $gpoFilter
            }
            Default {}
        }
        $objSearcher.SizeLimit = $Limit
        $objSearcher.PageSize = $PageSize
        $objSearcher.SearchScope = $SearchScope
        $objSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]$SecurityMask
        $objSearcher.findall() | ForEach-Object -Process {
            $objProps = [ordered]@{}
            foreach ($prop in ($_.Properties.PropertyNames | Sort-Object))
            {
                if ($prop -eq 'objectguid') {
                    $objProps['Guid'] = [guid]$_.properties."$($prop)"[0]
                } else {
                    $objProps[$prop] = $_.properties."$($prop)"[0]
                }
            }
            $gpopObj = [PSCustomObject]$objProps
            $gpopObj
        }

    }
    End
    {
    }
}