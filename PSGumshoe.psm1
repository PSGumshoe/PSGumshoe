
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
. $PSScriptRoot\Volatile\Get-InjectedThread.ps1
. $PSScriptRoot\Volatile\Get-LogonSession.ps1
. $PSScriptRoot\Volatile\Get-NamedPipe.ps1
. $PSScriptRoot\Volatile\Stop-Thread.ps1

# Analysis Functions
#-----------------------------
. $PSScriptRoot\Analysis\Measure-CharacterFrequency.ps1
. $PSScriptRoot\Analysis\Measure-DamerauLevenshteinDistance.ps1
. $PSScriptRoot\Analysis\Measure-VectorSimilarity.ps1

# Event Log Functions
#-----------------------------
. $PSScriptRoot\EventLog\Get-EventPsEngineState.ps1
. $PSScriptRoot\EventLog\Get-EventPsIPC.ps1
. $PSScriptRoot\EventLog\Get-EventPsPipeline.ps1
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
. $PSScriptRoot\EventLog\Get-SysmonProcessTerminateEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonRawAccessRead.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistryKey.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistryRename.ps1
. $PSScriptRoot\EventLog\Get-SysmonRegistrySetValue.ps1
. $PSScriptRoot\EventLog\Get-SysmonServiceStateChange.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiBinding.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiConsumer.ps1
. $PSScriptRoot\EventLog\Get-SysmonWmiFilter.ps1
. $PSScriptRoot\EventLog\Get-SysmonNetworkConnect.ps1
. $PSScriptRoot\EventLog\Get-SysmonDNSQuery.ps1
. $PSScriptRoot\EventLog\Search-SysmonEvent.ps1
. $PSScriptRoot\EventLog\Get-SysmonProcessActivityEvent.ps1
. $PSScriptRoot\EventLog\Search-EventLogEventData.ps1
. $PSScriptRoot\EventLog\Search-EventLogEventXML.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventLogonRecord.ps1
. $PSScriptRoot\EventLog\ConvertFrom-EventEventXMLRecord.ps1
. $PSScriptRoot\EventLog\Get-EventSystemLogon.ps1
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
. $PSScriptRoot\EventLog\Get-EventProcessCreate.ps1
. $PSScriptRoot\EventLog\ConvertTo-SysmonRule.ps1
. $PSScriptRoot\EventLog\Clear-WinEvent.ps1
. $PSScriptRoot\EventLog\Export-WinEvent.ps1

# CIM Collection Functions
#-------------------------

. $PSScriptRoot\CIM\Get-CimLogonSession.ps1
. $PSScriptRoot\CIM\Get-CimProcessLogonSession.ps1
. $PSScriptRoot\CIM\Get-CimProcess.ps1
. $PSScriptRoot\CIM\Get-CimComputerInfo.ps1
. $PSScriptRoot\CIM\Get-CimDNSCache.ps1


#region PSReflect

function New-InMemoryModule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type {
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN {
        $TypeHash = @{}
    }

    PROCESS {
        if ($Module -is [Reflection.Assembly]) {
            if ($Namespace) {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            } else {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        } else {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName)) {
                if ($Namespace) {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                } else {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes) {
                if ($Parameter.IsByRef) {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly]) {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys) {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

function psenum {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct {
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout) {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys) {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields) {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs) {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

#endregion PSReflect

#region PSReflect Definitions (Thread)

$Mod = New-InMemoryModule -ModuleName Thread

$LuidAttributes = psenum $Mod Thread.LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$MemProtection = psenum $Mod Thread.MemProtection UInt32 @{
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400
} -Bitfield

$MemState = psenum $Mod Thread.MemState UInt32 @{
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_FREE = 0x10000
}

$MemType = psenum $Mod Thread.MemType UInt32 @{
    MEM_PRIVATE = 0x20000
    MEM_MAPPED = 0x40000
    MEM_IMAGE = 0x1000000
}

$SecurityEntity = psenum $Mod Thread.SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SidNameUser = psenum $Mod Thread.SID_NAME_USE UInt32 @{
  SidTypeUser                            = 1
  SidTypeGroup                           = 2
  SidTypeDomain                          = 3
  SidTypeAlias                           = 4
  SidTypeWellKnownGroup                  = 5
  SidTypeDeletedAccount                  = 6
  SidTypeInvalid                         = 7
  SidTypeUnknown                         = 8
  SidTypeComputer                        = 9
}

$TokenInformationClass = psenum $Mod Thread.TOKEN_INFORMATION_CLASS UInt16 @{
  TokenUser                             = 1
  TokenGroups                           = 2
  TokenPrivileges                       = 3
  TokenOwner                            = 4
  TokenPrimaryGroup                     = 5
  TokenDefaultDacl                      = 6
  TokenSource                           = 7
  TokenType                             = 8
  TokenImpersonationLevel               = 9
  TokenStatistics                       = 10
  TokenRestrictedSids                   = 11
  TokenSessionId                        = 12
  TokenGroupsAndPrivileges              = 13
  TokenSessionReference                 = 14
  TokenSandBoxInert                     = 15
  TokenAuditPolicy                      = 16
  TokenOrigin                           = 17
  TokenElevationType                    = 18
  TokenLinkedToken                      = 19
  TokenElevation                        = 20
  TokenHasRestrictions                  = 21
  TokenAccessInformation                = 22
  TokenVirtualizationAllowed            = 23
  TokenVirtualizationEnabled            = 24
  TokenIntegrityLevel                   = 25
  TokenUIAccess                         = 26
  TokenMandatoryPolicy                  = 27
  TokenLogonSid                         = 28
  TokenIsAppContainer                   = 29
  TokenCapabilities                     = 30
  TokenAppContainerSid                  = 31
  TokenAppContainerNumber               = 32
  TokenUserClaimAttributes              = 33
  TokenDeviceClaimAttributes            = 34
  TokenRestrictedUserClaimAttributes    = 35
  TokenRestrictedDeviceClaimAttributes  = 36
  TokenDeviceGroups                     = 37
  TokenRestrictedDeviceGroups           = 38
  TokenSecurityAttributes               = 39
  TokenIsRestricted                     = 40
  MaxTokenInfoClass                     = 41
}

$LUID = struct $Mod Thread.Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Mod Thread.LuidAndAttributes @{
    Luid            =   field 0 $LUID
    Attributes      =   field 1 UInt32
}

$MEMORYBASICINFORMATION = struct $Mod Thread.MEMORY_BASIC_INFORMATION @{
  BaseAddress       = field 0 UIntPtr
  AllocationBase    = field 1 UIntPtr
  AllocationProtect = field 2 UInt32
  RegionSize        = field 3 UIntPtr
  State             = field 4 UInt32
  Protect           = field 5 UInt32
  Type              = field 6 UInt32
}

$SID_AND_ATTRIBUTES = struct $Mod Thread.SidAndAttributes @{
    Sid             =   field 0 IntPtr
    Attributes      =   field 1 UInt32
}

$THREADENTRY32 = struct $Mod Thread.THREADENTRY32 @{
    dwSize          = field 0 UInt32
    cntUsage        = field 1 UInt32
    th32ThreadID    = field 2 UInt32
    th32OwnerProcessID = field 3 UInt32
    tpBasePri       = field 4 UInt32
    tpDeltaPri      = field 5 UInt32
    dwFlags         = field 6 UInt32
}

$TOKEN_MANDATORY_LABEL = struct $Mod Thread.TokenMandatoryLabel @{
    Label           = field 0 $SID_AND_ATTRIBUTES;
}

$TOKEN_ORIGIN = struct $Mod Thread.TokenOrigin @{
  OriginatingLogonSession = field 0 UInt64
}

$TOKEN_PRIVILEGES = struct $Mod Thread.TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$TOKEN_USER = struct $Mod Thread.TOKEN_USER @{
    User            = field 0 $SID_AND_ATTRIBUTES
}

$FunctionDefinitions = @(
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError),

    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError),

    (func kernel32 CreateToolhelp32Snapshot ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwFlags,
        [UInt32]                                  #_In_ DWORD th32ProcessID
    ) -SetLastError),

    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError),

    (func ntdll NtQueryInformationThread ([UInt32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    )),

    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwDesiredAccess,
        [bool],                                   #_In_ BOOL  bInheritHandle,
        [UInt32]                                  #_In_ DWORD dwProcessId
    ) -SetLastError),

    (func advapi32 OpenProcessToken ([bool]) @(
      [IntPtr],                                   #_In_  HANDLE  ProcessHandle
      [UInt32],                                   #_In_  DWORD   DesiredAccess
      [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
    ) -SetLastError),

    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32],                                  #_In_ DWORD dwDesiredAccess,
        [bool],                                    #_In_ BOOL  bInheritHandle,
        [UInt32]                                   #_In_ DWORD dwThreadId
    ) -SetLastError),

    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                                    #_In_  HANDLE  ThreadHandle
      [UInt32],                                    #_In_  DWORD   DesiredAccess
      [bool],                                      #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType()                     #_Out_ PHANDLE TokenHandle
    ) -SetLastError),

    (func kernel32 QueryFullProcessImageName ([bool]) @(
      [IntPtr]                                     #_In_    HANDLE hProcess
      [UInt32]                                     #_In_    DWORD  dwFlags,
      [System.Text.StringBuilder]                  #_Out_   LPTSTR lpExeName,
      [UInt32].MakeByRefType()                     #_Inout_ PDWORD lpdwSize
    ) -SetLastError),

    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError),

    (func kernel32 TerminateThread ([bool]) @(
        [IntPtr],                                  # _InOut_ HANDLE hThread
        [UInt32]                                   # _In_ DWORD dwExitCode
    ) -SetLastError),

    (func kernel32 Thread32First ([bool]) @(
        [IntPtr],                                  #_In_    HANDLE          hSnapshot,
        $THREADENTRY32.MakeByRefType()             #_Inout_ LPTHREADENTRY32 lpte
    ) -SetLastError)

    (func kernel32 Thread32Next ([bool]) @(
        [IntPtr],                                  #_In_  HANDLE          hSnapshot,
        $THREADENTRY32.MakeByRefType()             #_Out_ LPTHREADENTRY32 lpte
    ) -SetLastError),

    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32SysInfo'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Advapi32 = $Types['advapi32']

$DELETE = 0x00010000
$READ_CONTROL = 0x00020000
$SYNCHRONIZE = 0x00100000
$WRITE_DAC = 0x00040000
$WRITE_OWNER = 0x00080000

$PROCESS_CREATE_PROCESS = 0x0080
$PROCESS_CREATE_THREAD = 0x0002
$PROCESS_DUP_HANDLE = 0x0040
$PROCESS_QUERY_INFORMATION = 0x0400
$PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
$PROCESS_SET_INFORMATION = 0x0200
$PROCESS_SET_QUOTA = 0x0100
$PROCESS_SUSPEND_RESUME = 0x0800
$PROCESS_TERMINATE = 0x0001
$PROCESS_VM_OPERATION = 0x0008
$PROCESS_VM_READ = 0x0010
$PROCESS_VM_WRITE = 0x0020
$PROCESS_ALL_ACCESS = $DELETE -bor
                      $READ_CONTROL -bor
                      $SYNCHRONIZE -bor
                      $WRITE_DAC -bor
                      $WRITE_OWNER -bor
                      $PROCESS_CREATE_PROCESS -bor
                      $PROCESS_CREATE_THREAD -bor
                      $PROCESS_DUP_HANDLE -bor
                      $PROCESS_QUERY_INFORMATION -bor
                      $PROCESS_QUERY_LIMITED_INFORMATION -bor
                      $PROCESS_SET_INFORMATION -bor
                      $PROCESS_SET_QUOTA -bor
                      $PROCESS_SUSPEND_RESUME -bor
                      $PROCESS_TERMINATE -bor
                      $PROCESS_VM_OPERATION -bor
                      $PROCESS_VM_READ -bor
                      $PROCESS_VM_WRITE

$THREAD_DIRECT_IMPERSONATION = 0x0200
$THREAD_GET_CONTEXT = 0x0008
$THREAD_IMPERSONATE = 0x0100
$THREAD_QUERY_INFORMATION = 0x0040
$THREAD_QUERY_LIMITED_INFORMATION = 0x0800
$THREAD_SET_CONTEXT = 0x0010
$THREAD_SET_INFORMATION = 0x0020
$THREAD_SET_LIMITED_INFORMATION = 0x0400
$THREAD_SET_THREAD_TOKEN = 0x0080
$THREAD_SUSPEND_RESUME = 0x0002
$THREAD_TERMINATE = 0x0001
$THREAD_ALL_ACCESS = $DELETE -bor
                     $READ_CONTROL -bor
                     $SYNCHRONIZE -bor
                     $WRITE_DAC -bor
                     $WRITE_OWNER -bor
                     $THREAD_DIRECT_IMPERSONATION -bor
                     $THREAD_GET_CONTEXT -bor
                     $THREAD_IMPERSONATE -bor
                     $THREAD_QUERY_INFORMATION -bor
                     $THREAD_QUERY_LIMITED_INFORMATION -bor
                     $THREAD_SET_CONTEXT -bor
                     $THREAD_SET_LIMITED_INFORMATION -bor
                     $THREAD_SET_THREAD_TOKEN -bor
                     $THREAD_SUSPEND_RESUME -bor
                     $THREAD_TERMINATE

$STANDARD_RIGHTS_REQUIRED = 0x000F0000
$TOKEN_ASSIGN_PRIMARY = 0x0001
$TOKEN_DUPLICATE = 0x0002
$TOKEN_IMPERSONATE = 0x0004
$TOKEN_QUERY = 0x0008
$TOKEN_QUERY_SOURCE = 0x0010
$TOKEN_ADJUST_PRIVILEGES = 0x0020
$TOKEN_ADJUST_GROUPS = 0x0040
$TOKEN_ADJUST_DEFAULT = 0x0080
$TOKEN_ADJUST_SESSIONID = 0x0100
$TOKEN_ALL_ACCESS = $STANDARD_RIGHTS_REQUIRED -bor
                    $TOKEN_ASSIGN_PRIMARY -bor
                    $TOKEN_DUPLICATE -bor
                    $TOKEN_IMPERSONATE -bor
                    $TOKEN_QUERY -bor
                    $TOKEN_QUERY_SOURCE -bor
                    $TOKEN_ADJUST_PRIVILEGES -bor
                    $TOKEN_ADJUST_GROUPS -bor
                    $TOKEN_ADJUST_DEFAULT


$UNTRUSTED_MANDATORY_LEVEL = "S-1-16-0"
$LOW_MANDATORY_LEVEL = "S-1-16-4096"
$MEDIUM_MANDATORY_LEVEL = "S-1-16-8192"
$MEDIUM_PLUS_MANDATORY_LEVEL = "S-1-16-8448"
$HIGH_MANDATORY_LEVEL = "S-1-16-12288"
$SYSTEM_MANDATORY_LEVEL = "S-1-16-16384"
$PROTECTED_PROCESS_MANDATORY_LEVEL = "S-1-16-20480"
$SECURE_PROCESS_MANDATORY_LEVEL = "S-1-16-28672"

#endregion PSReflect Definitions (Thread)

#region Win32 API Abstractions

function CloseHandle
{
    <#
    .SYNOPSIS

    Closes an open object handle.

    .DESCRIPTION

    The CloseHandle function closes handles to the following objects:
    - Access token
    - Communications device
    - Console input
    - Console screen buffer
    - Event
    - File
    - File mapping
    - I/O completion port
    - Job
    - Mailslot
    - Memory resource notification
    - Mutex
    - Named pipe
    - Pipe
    - Process
    - Semaphore
    - Thread
    - Transaction
    - Waitable timer

    The documentation for the functions that create these objects indicates that CloseHandle should be used when you are finished with the object, and what happens to pending operations on the object after the handle is closed. In general, CloseHandle invalidates the specified object handle, decrements the object's handle count, and performs object retention checks. After the last handle to an object is closed, the object is removed from the system.

    .PARAMETER Handle

    A valid handle to an open object.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $Handle
    )

    <#
    (func kernel32 CloseHandle ([bool]) @(
        [IntPtr]                                  #_In_ HANDLE hObject
    ) -SetLastError)
    #>

    $Success = $Kernel32::CloseHandle($Handle); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "Close Handle Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function ConvertSidToStringSid
{
    <#
    .SYNOPSIS

    The ConvertSidToStringSid function converts a security identifier (SID) to a string format suitable for display, storage, or transmission.

    .DESCRIPTION

    The ConvertSidToStringSid function uses the standard S-R-I-S-S… format for SID strings.

    .PARAMETER SidPointer

    A pointer to the SID structure to be converted.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa376399(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SidPointer
    )

    <#
    (func advapi32 ConvertSidToStringSid ([bool]) @(
        [IntPtr]                                  #_In_  PSID   Sid,
        [IntPtr].MakeByRefType()                  #_Out_ LPTSTR *StringSid
    ) -SetLastError)
    #>

    $StringPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSid($SidPointer, [ref]$StringPtr); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "ConvertSidToStringSid Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringPtr))
}

function CreateToolhelp32Snapshot
{
    <#
    .SYNOPSIS

    Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

    .DESCRIPTION

    .PARAMETER ProcessId

    .PARAMETER Flags

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $Flags
    )

    <#
    (func kernel32 CreateToolhelp32Snapshot ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwFlags,
        [UInt32]                                  #_In_ DWORD th32ProcessID
    ) -SetLastError)
    #>

    $hSnapshot = $Kernel32::CreateToolhelp32Snapshot($Flags, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $hSnapshot)
    {
        Write-Debug "CreateToolhelp32Snapshot Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $hSnapshot
}

function GetTokenInformation
{
    <#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER TokenHandle

    .PARAMETER TokenInformationClass

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $TokenHandle,

        [Parameter(Mandatory = $true)]
        $TokenInformationClass
    )

    <#
    (func advapi32 GetTokenInformation ([bool]) @(
      [IntPtr],                                   #_In_      HANDLE                  TokenHandle
      [Int32],                                    #_In_      TOKEN_INFORMATION_CLASS TokenInformationClass
      [IntPtr],                                   #_Out_opt_ LPVOID                  TokenInformation
      [UInt32],                                   #_In_      DWORD                   TokenInformationLength
      [UInt32].MakeByRefType()                    #_Out_     PDWORD                  ReturnLength
    ) -SetLastError)
    #>

    # initial query to determine the necessary buffer size
    $TokenPtrSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, 0, $TokenPtrSize, [ref]$TokenPtrSize)
    [IntPtr]$TokenPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPtrSize)

    # retrieve the proper buffer value
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, $TokenPtr, $TokenPtrSize, [ref]$TokenPtrSize); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($Success)
    {
        switch($TokenInformationClass)
        {
            1 # TokenUser
            {
                $TokenUser = $TokenPtr -as $TOKEN_USER
                ConvertSidToStringSid -SidPointer $TokenUser.User.Sid
            }
            3 # TokenPrivilege
            {
                # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure
                $TokenPrivileges = $TokenPtr -as $TOKEN_PRIVILEGES

                $sb = New-Object System.Text.StringBuilder

                for($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++)
                {
                    if((($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes) -band $LuidAttributes::SE_PRIVILEGE_ENABLED) -eq $LuidAttributes::SE_PRIVILEGE_ENABLED)
                    {
                       $sb.Append(", $($TokenPrivileges.Privileges[$i].Luid.LowPart.ToString())") | Out-Null
                    }
                }
                Write-Output $sb.ToString().TrimStart(', ')
            }
            17 # TokenOrigin
            {
                $TokenOrigin = $TokenPtr -as $LUID
                Write-Output (Get-LogonSession -LogonId $TokenOrigin.LowPart)
            }
            22 # TokenAccessInformation
            {

            }
            25 # TokenIntegrityLevel
            {
                $TokenIntegrity = $TokenPtr -as $TOKEN_MANDATORY_LABEL
                switch(ConvertSidToStringSid -SidPointer $TokenIntegrity.Label.Sid)
                {
                    $UNTRUSTED_MANDATORY_LEVEL
                    {
                        Write-Output "UNTRUSTED_MANDATORY_LEVEL"
                    }
                    $LOW_MANDATORY_LEVEL
                    {
                        Write-Output "LOW_MANDATORY_LEVEL"
                    }
                    $MEDIUM_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_MANDATORY_LEVEL"
                    }
                    $MEDIUM_PLUS_MANDATORY_LEVEL
                    {
                        Write-Output "MEDIUM_PLUS_MANDATORY_LEVEL"
                    }
                    $HIGH_MANDATORY_LEVEL
                    {
                        Write-Output "HIGH_MANDATORY_LEVEL"
                    }
                    $SYSTEM_MANDATORY_LEVEL
                    {
                        Write-Output "SYSTEM_MANDATORY_LEVEL"
                    }
                    $PROTECTED_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "PROTECTED_PROCESS_MANDATORY_LEVEL"
                    }
                    $SECURE_PROCESS_MANDATORY_LEVEL
                    {
                        Write-Output "SECURE_PROCESS_MANDATORY_LEVEL"
                    }
                }
            }
        }
    }
    else
    {
        Write-Debug "GetTokenInformation Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    try
    {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPtr)
    }
    catch
    {

    }
}

function NtQueryInformationThread
{
    <#
    .SYNOPSIS

    Retrieves information about the specified thread.

    .DESCRIPTION

    .PARAMETER ThreadHandle

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle
    )

    <#
    (func ntdll NtQueryInformationThread ([Int32]) @(
        [IntPtr],                                 #_In_      HANDLE          ThreadHandle,
        [Int32],                                  #_In_      THREADINFOCLASS ThreadInformationClass,
        [IntPtr],                                 #_Inout_   PVOID           ThreadInformation,
        [Int32],                                  #_In_      ULONG           ThreadInformationLength,
        [IntPtr]                                  #_Out_opt_ PULONG          ReturnLength
    ))
    #>

    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)

    $Success = $Ntdll::NtQueryInformationThread($ThreadHandle, 9, $buf, [IntPtr]::Size, [IntPtr]::Zero); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "NtQueryInformationThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output ([System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf))
}

function OpenProcess
{
    <#
    .SYNOPSIS

    Opens an existing local process object.

    .DESCRIPTION

    To open a handle to another local process and obtain full access rights, you must enable the SeDebugPrivilege privilege.
    The handle returned by the OpenProcess function can be used in any function that requires a handle to a process, such as the wait functions, provided the appropriate access rights were requested.
    When you are finished with the handle, be sure to close it using the CloseHandle function.

    .PARAMETER ProcessId

    The identifier of the local process to be opened.
    If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED because their access restrictions prevent user-level code from opening them.

    .PARAMETER DesiredAccess

    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the process access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684320(v=vs.85).aspx

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ProcessId,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $DesiredAccess,

        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    <#
    (func kernel32 OpenProcess ([IntPtr]) @(
        [UInt32],                                 #_In_ DWORD dwDesiredAccess,
        [bool],                                   #_In_ BOOL  bInheritHandle,
        [UInt32]                                  #_In_ DWORD dwProcessId
    ) -SetLastError)
    #>

    $hProcess = $Kernel32::OpenProcess($DesiredAccess, $InheritHandle, $ProcessId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hProcess -eq 0)
    {
        Write-Debug "OpenProcess Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $hProcess
}

function OpenProcessToken
{
    <#
    .SYNOPSIS

    The OpenProcessToken function opens the access token associated with a process.

    .PARAMETER ProcessHandle

    A handle to the process whose access token is opened. The process must have the PROCESS_QUERY_INFORMATION access permission.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are compared with the discretionary access control list (DACL) of the token to determine which accesses are granted or denied.
    For a list of access rights for access tokens, see Access Rights for Access-Token Objects.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $DesiredAccess
    )

    <#
    (func advapi32 OpenProcessToken ([bool]) @(
      [IntPtr],                                   #_In_  HANDLE  ProcessHandle
      [UInt32],                                   #_In_  DWORD   DesiredAccess
      [IntPtr].MakeByRefType()                    #_Out_ PHANDLE TokenHandle
    ) -SetLastError)
    #>

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $DesiredAccess, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "OpenProcessToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $hToken
}

function OpenThread
{
    <#
    .SYNOPSIS

    Opens an existing thread object.

    .DESCRIPTION

    The handle returned by OpenThread can be used in any function that requires a handle to a thread, such as the wait functions, provided you requested the appropriate access rights. The handle is granted access to the thread object only to the extent it was specified in the dwDesiredAccess parameter.
    When you are finished with the handle, be sure to close it by using the CloseHandle function.

    .PARAMETER ThreadId

    The identifier of the thread to be opened.

    .PARAMETER DesiredAccess

    The access to the thread object. This access right is checked against the security descriptor for the thread. This parameter can be one or more of the thread access rights.
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.

    .PARAMETER InheritHandle

    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684335(v=vs.85).aspx

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [UInt32]
        $ThreadId,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $DesiredAccess,

        [Parameter()]
        [bool]
        $InheritHandle = $false
    )

    <#
    (func kernel32 OpenThread ([IntPtr]) @(
        [UInt32],                                  #_In_ DWORD dwDesiredAccess,
        [bool],                                    #_In_ BOOL  bInheritHandle,
        [UInt32]                                   #_In_ DWORD dwThreadId
    ) -SetLastError)
    #>

    $hThread = $Kernel32::OpenThread($DesiredAccess, $InheritHandle, $ThreadId); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if($hThread -eq 0)
    {
        Write-Debug "OpenThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $hThread
}

function OpenThreadToken
{
    <#
    .SYNOPSIS

    The OpenThreadToken function opens the access token associated with a thread

    .DESCRIPTION

    Tokens with the anonymous impersonation level cannot be opened.
    Close the access token handle returned through the Handle parameter by calling CloseHandle.

    .PARAMETER ThreadHandle

    A handle to the thread whose access token is opened.

    .PARAMETER DesiredAccess

    Specifies an access mask that specifies the requested types of access to the access token. These requested access types are reconciled against the token's discretionary access control list (DACL) to determine which accesses are granted or denied.

    .PARAMETER OpenAsSelf

    TRUE if the access check is to be made against the process-level security context.
    FALSE if the access check is to be made against the current security context of the thread calling the OpenThreadToken function.
    The OpenAsSelf parameter allows the caller of this function to open the access token of a specified thread when the caller is impersonating a token at SecurityIdentification level. Without this parameter, the calling thread cannot open the access token on the specified thread because it is impossible to open executive-level objects by using the SecurityIdentification impersonation level.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa379296(v=vs.85).aspx

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $DesiredAccess,

        [Parameter()]
        [bool]
        $OpenAsSelf = $false
    )

    <#
    (func advapi32 OpenThreadToken ([bool]) @(
      [IntPtr],                                    #_In_  HANDLE  ThreadHandle
      [UInt32],                                    #_In_  DWORD   DesiredAccess
      [bool],                                      #_In_  BOOL    OpenAsSelf
      [IntPtr].MakeByRefType()                     #_Out_ PHANDLE TokenHandle
    ) -SetLastError)
    #>

    $hToken = [IntPtr]::Zero
    $Success = $Advapi32::OpenThreadToken($ThreadHandle, $DesiredAccess, $OpenAsSelf, [ref]$hToken); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        throw "OpenThreadToken Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $hToken
}

function QueryFullProcessImageName
{
    <#
    .SYNOPSIS

    Retrieves the full name of the executable image for the specified process.

    .PARAMETER ProcessHandle

    A handle to the process. This handle must be created with the PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access right.

    .PARAMETER Flags

    This parameter can be one of the following values.
    0x00 - The name should use the Win32 path format.
    0x01 - The name should use the native system path format.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms684919(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter()]
        [UInt32]
        $Flags = 0
    )

    $capacity = 2048
    $sb = New-Object -TypeName System.Text.StringBuilder($capacity)

    $Success = $Kernel32::QueryFullProcessImageName($ProcessHandle, $Flags, $sb, [ref]$capacity); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "QueryFullProcessImageName Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $sb.ToString()
}

function ReadProcessMemory
{
    <#
    .SYNOPSIS

    Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.

    .DESCRIPTION

    ReadProcessMemory copies the data in the specified address range from the address space of the specified process into the specified buffer of the current process. Any process that has a handle with PROCESS_VM_READ access can call the function.

    The entire area to be read must be accessible, and if it is not accessible, the function fails.

    .PARAMETER ProcessHandle

    A handle to the process with memory that is being read. The handle must have PROCESS_VM_READ access to the process.

    .PARAMETER BaseAddress

    The base address in the specified process from which to read. Before any data transfer occurs, the system verifies that all data in the base address and memory of the specified size is accessible for read access, and if it is not accessible the function fails.

    .PARAMETER Size

    The number of bytes to be read from the specified process.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress,

        [Parameter(Mandatory = $true)]
        [Int]
        $Size
    )

    <#
    (func kernel32 ReadProcessMemory ([Bool]) @(
        [IntPtr],                                  # _In_ HANDLE hProcess
        [IntPtr],                                  # _In_ LPCVOID lpBaseAddress
        [Byte[]],                                  # _Out_ LPVOID  lpBuffer
        [Int],                                     # _In_ SIZE_T nSize
        [Int].MakeByRefType()                      # _Out_ SIZE_T *lpNumberOfBytesRead
    ) -SetLastError) # MSDN states to call GetLastError if the return value is false.
    #>

    $buf = New-Object byte[]($Size)
    [Int32]$NumberOfBytesRead = 0

    $Success = $Kernel32::ReadProcessMemory($ProcessHandle, $BaseAddress, $buf, $buf.Length, [ref]$NumberOfBytesRead); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "ReadProcessMemory Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $buf
}

function TerminateThread
{
    <#
    .SYNOPSIS

    Terminates a thread.

    .DESCRIPTION

    TerminateThread is used to cause a thread to exit. When this occurs, the target thread has no chance to execute any user-mode code. DLLs attached to the thread are not notified that the thread is terminating. The system frees the thread's initial stack.

    .PARAMETER ThreadHandle

    A handle to the thread to be terminated.

    The handle must have the THREAD_TERMINATE access right.

    .PARAMETER ExitCode

    The exit code for the thread.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686717(v=vs.85).aspx

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686769(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ThreadHandle,

        [Parameter()]
        [UInt32]
        $ExitCode = 0
    )

    <#
    (func kernel32 TerminateThread ([bool]) @(
        [IntPtr],                                  # _InOut_ HANDLE hThread
        [UInt32]                                   # _In_ DWORD dwExitCode
    ) -SetLastError)
    #>

    $Success = $Kernel32::TerminateThread($ThreadHandle, $ExitCode); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "TerminateThread Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

function Thread32First
{
    <#
    .SYNOPSIS

    Retrieves information about the first thread of any process encountered in a system snapshot.

    .PARAMETER SnapshotHandle

    A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/ms686728(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $SnapshotHandle
    )

    <#
    (func kernel32 Thread32First ([bool]) @(
        [IntPtr],                                  #_In_    HANDLE          hSnapshot,
        $THREADENTRY32.MakeByRefType()             #_Inout_ LPTHREADENTRY32 lpte
    ) -SetLastError)
    #>

    $Thread = [Activator]::CreateInstance($THREADENTRY32)
    $Thread.dwSize = $THREADENTRY32::GetSize()

    $Success = $Kernel32::Thread32First($hSnapshot, [Ref]$Thread); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "Thread32First Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Output $Thread
}

function VirtualQueryEx
{
    <#
    .SYNOPSIS

    Retrieves information about a range of pages within the virtual address space of a specified process.

    .PARAMETER ProcessHandle

    A handle to the process whose memory information is queried. The handle must have been opened with the PROCESS_QUERY_INFORMATION access right, which enables using the handle to read information from the process object.

    .PARAMETER BaseAddress

    The base address of the region of pages to be queried. This value is rounded down to the next page boundary.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .LINK

    https://msdn.microsoft.com/en-us/library/windows/desktop/aa366907(v=vs.85).aspx

    .EXAMPLE
    #>

    param
    (
        [Parameter(Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,

        [Parameter(Mandatory = $true)]
        [IntPtr]
        $BaseAddress
    )

    <#
    (func kernel32 VirtualQueryEx ([Int32]) @(
        [IntPtr],                                  #_In_     HANDLE                    hProcess,
        [IntPtr],                                  #_In_opt_ LPCVOID                   lpAddress,
        $MEMORYBASICINFORMATION.MakeByRefType(),   #_Out_    PMEMORY_BASIC_INFORMATION lpBuffer,
        [UInt32]                                   #_In_     SIZE_T                    dwLength
    ) -SetLastError)
    #>

    $memory_basic_info = [Activator]::CreateInstance($MEMORYBASICINFORMATION)
    $Success = $Kernel32::VirtualQueryEx($ProcessHandle, $BaseAddress, [Ref]$memory_basic_info, $MEMORYBASICINFORMATION::GetSize()); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if(-not $Success)
    {
        Write-Debug "VirtualQueryEx Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        #Write-Host "ProcessHandle: $($ProcessHandle)"
        #Write-Host "BaseAddress: $($BaseAddress)"
    }

    Write-Output $memory_basic_info
}

#endregion Win32 API Abstractions
