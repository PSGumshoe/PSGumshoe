@{

Author = "Carlos Perez (carlos_perez@darkoperator.com)"
# Script module or binary module file associated with this manifest.
RootModule = 'PSGumshoe.psm1'

# Version number of this module.
ModuleVersion = '2.0.12'

# ID used to uniquely identify this module
GUID = '6f0aaa95-8bc2-43ef-b06c-440ba94a7e5d'

# Description of the functionality provided by this module
Description = 'PowerShell module for data collection, incident response, hunting, and security analysis'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    # Volatile information functions
    #'Get-InjectedThread',
    'Get-NamedPipe',
    'Measure-CharacterFrequency',
    'Measure-DamerauLevenshteinDistance',
    'Measure-VectorSimilarity',
    #'Stop-Thread',
    # Directory Service functions
    'Get-DSForest',
    'Get-DSDirectoryEntry',
    'Get-DSDirectorySearcher',
    'Get-DSComputer',
    'Get-DSDomain',
    'Get-DSGpo',
    'Get-DSUser',
    'Get-DSGroup'
    'Get-DSReplicationAttribute',
    'Get-DSGroupMember',
    'Get-DSOU',
    'Get-DSTrust',
    'Get-DSObjectAcl',
    # Eventlog functions
    'Get-EventPsEngineState',
    'Get-EventPsScriptCommandExec',
    'Get-EventPsPipeline',
    'Get-EventPsIPC',
    'Get-EventPsScriptBlock',
    'Get-WinEventBaseXPathFilter',
    'Get-SysmonProcessAccess',
    'Get-SysmonConfigChange',
    'Get-SysmonConnectNamedPipe',
    'Get-SysmonCreateNamedPipe',
    'Get-SysmonCreateRemoteThreadEvent',
    'Get-SysmonDriverLoadEvent',
    'Get-SysmonFileCreateEvent',
    'Get-SysmonFileStreamHash',
    'Get-SysmonFileTime',
    'Get-SysmonFileDeleteEvent',
    'Get-SysmonFileDeleteDetectedEvent',
    'Get-SysmonImageLoadEvent',
    'Get-SysmonNetworkConnect',
    'Get-SysmonProcessCreateEvent',
    'Get-SysmonProcessTampering',
    'Get-SysmonProcessTerminateEvent',
    'Get-SysmonRawAccessRead',
    'Get-SysmonRegistryKey',
    'Get-SysmonRegistryRename',
    'Get-SysmonRegistrySetValue',
    'Get-SysmonServiceStateChange',
    'Get-SysmonWmiBinding',
    'Get-SysmonWmiConsumer',
    'Get-SysmonWmiFilter',
    'Get-SysmonDNSQuery',
    'Get-SysmonProcessActivityEvent',
    'Get-SysmonClipboardChange',
    'Get-SysmonError',
    'Get-EventSystemLogon',
    'Get-EventSystemLogonFailure',
    'Get-EventSystemLogoff',
    'Get-EventTerminalLogon',
    'Get-EventTerminalLogoff',
    'Get-EventScheduledTaskStart',
    'Get-EventScheduledTaskProcess',
    'Get-EventScheduledTaskStop',
    'Get-EventScheduledTaskComplete',
    'Get-EventBitsTransferComplete',
    'Get-EventBitsTransferStart',
    'Get-EventKerberosPreAuthFailure',
    'Get-EventKerberosTGTRequest',
    'Get-EventSystemLoginAttempt',
    'Get-SysmonAccessMask',
    'Get-SysmonRuleHash',
    'Get-SysmonFileBlockExecutable',
    'Get-SysmonFileBlockShredding',
    'Get-SysmonFileExecutableDetected',
    'ConvertTo-SysmonRule',
    'Get-EventProcessCreate',
    'Clear-WinEvent',
    'Export-WinEvent',
    'Get-EventWmiQueryError',
    'Get-EventWmiProviderStart',
    'Get-EventWmiOperationFailure',
    'Get-EventWmiTemporaryEvent',
    'Get-EventWmiPermanentEvent',
    'Get-EventWmiObjectAccess',
    'Get-EventVHDImageMount',
    'convertFrom-EventLogRecord',
    'ConvertFrom-EventlogSDDL',
    'Get-FilteredEvent',
    'Export-EventLogToCSV',

    # CIM Functions
    'Get-CimLogonSession',
    'Get-CimProcessLogonSession',
    'Get-CimProcess',
    'Get-CimComputerInfo',
    'Get-CimDNSCache',
    'Get-CimNetLogon',

    #MITRE Functions
    'New-NavigatorJson',
    'ConvertTo-SDDL'
)

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = 'Psg'

}
