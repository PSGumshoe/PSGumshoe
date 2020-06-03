# PSGumshoe

PSGumshoe is a Windows PowerShell module for the collection of OS and domain artifacts for the purposes of performing live response, hunt, and forensics.

The module focuses on being as forensically sound as possible using existing Windows APIs to achieve the collection of information from the target host.

## Functions

### Volatile information functions

* Get-InjectedThread 
* Get-NamedPipe 
* Measure-CharacterFrequency 
* Measure-DamerauLevenshteinDistance 
* Measure-VectorSimilarity 
* Stop-Thread 

### Directory Service functions

* Get-DSForest 
* Get-DSDirectoryEntry 
* Get-DSDirectorySearcher 
* Get-DSComputer 
* Get-DSDomain 
* Get-DSGpo 
* Get-DSUser 
* Get-DSGroup* 
* Get-DSReplicationAttribute 
* Get-DSGroupMember 
* Get-DSOU 
* Get-DSTrust 
* Get-DSObjectAcl 

### Eventlog functions

* Get-EventPsEngineState 
* Get-EventPsPipeline 
* Get-EventPsIPC 
* Get-EventPsScriptBlock 
* Get-WinEventBaseXPathFilter 
* Get-SysmonProcessAccess 
* Get-SysmonConfigChange 
* Get-SysmonConnectNamedPipe 
* Get-SysmonCreateNamedPipe 
* Get-SysmonCreateRemoteThreadEvent 
* Get-SysmonDriverLoadEvent 
* Get-SysmonFileCreateEvent 
* Get-SysmonFileStreamHash 
* Get-SysmonFileTime 
* Get-SysmonImageLoadEvent 
* Get-SysmonNetworkConnect 
* Get-SysmonProcessCreateEvent 
* Get-SysmonProcessTerminateEvent 
* Get-SysmonRawAccessRead  
* Get-SysmonRegistryKey 
* Get-SysmonRegistryRename 
* Get-SysmonRegistrySetValue 
* Get-SysmonServiceStateChange 
* Get-SysmonWmiBinding 
* Get-SysmonWmiConsumer 
* Get-SysmonWmiFilter 
* Get-SysmonDNSQuery 
* Get-SysmonProcessActivityEvent 
* Get-EventSystemLogon 
* Get-EventSystemLogoff 
* Get-EventTerminalLogon 
* Get-EventTerminalLogoff 
* Get-EventScheduledTaskStart 
* Get-EventScheduledTaskProcess 
* Get-EventScheduledTaskStop 
* Get-EventScheduledTaskComplete 
* Get-EventBitsTransferComplete 
* Get-EventBitsTransferStart 
* Get-SysmonAccessMask 
* Get-SysmonRuleHash 
* ConvertTo-SysmonRule 
* Get-EventProcessCreate 
* Clear-WinEvent 
* Export-WinEvent 

### CIM Functions

* Get-CimLogonSession 
* Get-CimProcessLogonSession 
* Get-CimProcess 
* Get-CimComputerInfo 
* Get-CimDNSCache* 