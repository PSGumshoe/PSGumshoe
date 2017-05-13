@{

# Script module or binary module file associated with this manifest.
RootModule = 'PSGumshoe.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = '6f0aaa95-8bc2-43ef-b06c-440ba94a7e5d'

# Description of the functionality provided by this module
Description = 'PowerShell module for data collection, incident response, hunting, and security analysis'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    'Get-InjectedThread',
    'Get-NamedPipe',
    'Measure-CharacterFrequency',
    'Measure-DamerauLevenshteinDistance',
    'Measure-VectorSimilarity',
    'Stop-Thread',
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
    'Get-DSObjectAcl'
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
 DefaultCommandPrefix = 'Psg'

}
