
# Importing module files
# Directory Service Functions
#-----------------------------
. $PSScriptRoot\DirectoryService\PrivateFunctions.ps1
. $PSScriptRoot\DirectoryService\Get-DSForest.ps1
. $PSScriptRoot\DirectoryService\Get-DSDirectoryEntry.ps1
. $PSScriptRoot\DirectoryService\Get-DSDirectorySearcher.ps1
. $PSScriptRoot\DirectoryService\Get-DSComputer.ps1
. $PSScriptRoot\DirectoryService\Get-DSDomain.ps1
. $PSScriptRoot\DirectoryService\Get-DSGpo.ps1
. $PSScriptRoot\DirectoryService\Get-DSUser.ps1
. $PSScriptRoot\DirectoryService\Get-DSReplicationAttribute.ps1
. $PSScriptRoot\DirectoryService\Get-DSGroup.ps1
. $PSScriptRoot\DirectoryService\Get-DSGroupMember.ps1
. $PSScriptRoot\DirectoryService\Get-DSOU.ps1
. $PSScriptRoot\DirectoryService\Get-DSTrust.ps1
. $PSScriptRoot\DirectoryService\Get-DSObjectAcl.ps1

# Volatile Information Functions
#-----------------------------
#. $PSScriptRoot\Volatile\Get-InjectedThread.ps1
. $PSScriptRoot\Volatile\Get-LogonSession.ps1
. $PSScriptRoot\Volatile\Get-NamedPipe.ps1
#. $PSScriptRoot\Volatile\Stop-Thread.ps1

# Analysis Functions
#-----------------------------
. $PSScriptRoot\Analysis\Measure-CharacterFrequency.ps1
. $PSScriptRoot\Analysis\Measure-DamerauLevenshteinDistance.ps1
. $PSScriptRoot\Analysis\Measure-VectorSimilarity.ps1
. $PSScriptRoot\Analysis\ConvertTo-SDDL.ps1

# Event Log Functions
#-----------------------------
. $PSScriptRoot\EventLog\Get-EventPsEngineState.ps1
. $PSScriptRoot\EventLog\Get-EventPsIPC.ps1
. $PSScriptRoot\EventLog\Get-EventPsPipeline.ps1
. $PSScriptRoot\EventLog\Get-EventPsScriptCommandExec.ps1
. $PSScriptRoot\EventLog\Get-EventPsScriptBlock.ps1
. $PSScriptRoot\EventLog\Get-WinEventBaseXPathFilter.ps1
. $PSScriptRoot\EventLog\ConvertFrom-SysmonEventLogRecord.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventEventXMLRecord.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessAccess.ps1
. $PSScriptRoot\EventLog\Get-SysmonConfigChange.ps1
. $PSScriptRoot\EventLog\Get-SysmonConnectNamedPipe.ps1
. $PSScriptRoot\EventLog\Get-SysmonCreateNamedPipe.ps1
. $PSScriptRoot\EventLog\Get-SysmonCreateRemoteThreadEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonDriverLoadEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileCreateEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileStreamHash.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileTime.ps1
. $PSScriptRoot\EventLog\Get-SysmonImageLoadEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonNetworkConnect.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessCreateEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessTampering.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessTerminateEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonRawAccessRead.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistryKey.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistryRename.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistrySetValue.ps1
. $PSScriptRoot\EventLog\Get-SysmonClipboardChange.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiBinding.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiConsumer.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiFilter.ps1
. $PSScriptRoot\EventLog\Get-SysmonNetworkConnect.ps1
. $PSScriptRoot\EventLog\Get-SysmonDNSQuery.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileDeleteEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileDeleteDetectedEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonError.ps1
. $PSScriptRoot\EventLog\Search-SysmonEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessActivityEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessActivityEvent.ps1
. $PSScriptRoot\EventLog\Search-EventLogEventData.ps1
. $PSScriptRoot\EventLog\Search-EventLogEventXML.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventLogRecord.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventEventXMLRecord.ps1
. $PSScriptRoot\EventLog\Get-EventSystemLogon.ps1
. $PSScriptRoot\EventLog\Get-EventSystemLogonFailure.ps1
. $PSScriptRoot\EventLog\Get-EventSystemLogoff.ps1
. $PSScriptRoot\EventLog\Get-EventTerminalLogon.ps1
. $PSScriptRoot\EventLog\Get-EventTerminalLogoff.ps1
. $PSScriptRoot\EventLog\Get-EventScheduledTaskStart.ps1
. $PSScriptRoot\EventLog\Get-EventScheduledTaskProcess.ps1
. $PSScriptRoot\EventLog\Get-EventScheduledTaskStop.ps1
. $PSScriptRoot\EventLog\Get-EventScheduledTaskComplete.ps1
. $PSScriptRoot\EventLog\Get-EventBitsTransferComplete.ps1
. $PSScriptRoot\EventLog\Get-EventBitsTransferStart.ps1
. $PSScriptRoot\EventLog\Get-SysmonAccessMask.ps1
. $PSScriptRoot\EventLog\Get-SysmonRuleHash.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileBlockExecutable.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileBlockShredding.ps1
. $PSScriptRoot\EventLog\Get-EventProcessCreate.ps1
. $PSScriptRoot\EventLog\Get-EventKerberosPreAuthFailure.ps1
. $PSScriptRoot\EventLog\Get-EventKerberosTGTRequest.ps1
. $PSScriptRoot\EventLog\ConvertTo-SysmonRule.ps1
. $PSScriptRoot\EventLog\Clear-WinEvent.ps1
. $PSScriptRoot\EventLog\Export-WinEvent.ps1
. $PSScriptRoot\EventLog\Get-EventWmiProviderStart.ps1
. $PSScriptRoot\EventLog\Get-EventWmiOperationFailure.ps1
. $PSScriptRoot\EventLog\Search-EventLogUserData.ps1
. $PSScriptRoot\EventLog\Get-EventWmiTemporaryEvent.ps1
. $PSScriptRoot\EventLog\Get-EventWmiPermanentEvent.ps1
. $PSScriptRoot\EventLog\Get-EventWmiObjectAccess.ps1
. $PSScriptRoot\EventLog\Get-EventVHDImageMount.ps1
. $PSScriptRoot\EventLog\Get-SysmonFileExecutableDetected.ps1
. $PSScriptRoot\EventLog\Get-EventSystemLoginAttempt.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventlogSDDL.ps1
. $PSScriptRoot\EventLog\Get-FilteredEvent.ps1
. $PSScriptRoot\EventLog\Export-EventLogToCSV.ps1

# CIM Collection Functions
#-------------------------

. $PSScriptRoot\CIM\Get-CimLogonSession.ps1
. $PSScriptRoot\CIM\Get-CimProcessLogonSession.ps1
. $PSScriptRoot\CIM\Get-CimProcess.ps1
. $PSScriptRoot\CIM\Get-CimComputerInfo.ps1
. $PSScriptRoot\CIM\Get-CimDNSCache.ps1
. $PSScriptRoot\CIM\Get-CimNetLogon.ps1

# MITRE Functions
#------------------------

. $PSScriptRoot\mitre\New-NavigatorJson.ps1