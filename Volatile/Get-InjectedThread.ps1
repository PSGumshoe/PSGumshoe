function Get-InjectedThread {
    <#

    .SYNOPSIS

    Looks for threads that were created as a result of code injection.

    .DESCRIPTION

    Memory resident malware (fileless malware) often uses a form of memory injection to get code execution. Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.

    Common memory injection techniques that *can* be caught using this method include:
    - Classic Injection (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Reflective DLL Injection
    - Process Hollowing

    NOTE: Nothing in security is a silver bullet. An attacker could modify their tactics to avoid detection using this methodology.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .EXAMPLE

    PS > Get-InjectedThread

    ProcessName               : ThreadStart.exe
    ProcessId                 : 7784
    Path                      : C:\Users\tester\Desktop\ThreadStart.exe
    KernelPath                : C:\Users\tester\Desktop\ThreadStart.exe
    CommandLine               : "C:\Users\tester\Desktop\ThreadStart.exe"
    PathMismatch              : False
    ThreadId                  : 14512
    AllocatedMemoryProtection : PAGE_EXECUTE_READWRITE
    MemoryProtection          : PAGE_EXECUTE_READWRITE
    MemoryState               : MEM_COMMIT
    MemoryType                : MEM_PRIVATE
    BasePriority              : 8
    IsUniqueThreadToken       : False
    Integrity                 : MEDIUM_MANDATORY_LEVEL
    Privilege                 : SeChangeNotifyPrivilege
    LogonId                   : 999
    SecurityIdentifier        : S-1-5-21-386661145-2656271985-3844047388-1001
    UserName                  : DESKTOP-HMTGQ0R\SYSTEM
    LogonSessionStartTime     : 3/15/2017 5:45:38 PM
    LogonType                 : System
    AuthenticationPackage     : NTLM
    BaseAddress               : 4390912
    Size                      : 4096
    Bytes                     : {144, 195, 0, 0...}

    #>

    [CmdletBinding()]
    param ()

    $hSnapshot = CreateToolhelp32Snapshot -ProcessId 0 -Flags 4

    $Thread = Thread32First -SnapshotHandle $hSnapshot
    do {
        $proc = Get-Process -Id $Thread.th32OwnerProcessId

        if($Thread.th32OwnerProcessId -ne 0 -and $Thread.th32OwnerProcessId -ne 4) {
            $hThread = OpenThread -ThreadId $Thread.th32ThreadID -DesiredAccess $THREAD_ALL_ACCESS -InheritHandle $false
            if($hThread -ne 0) {
                $BaseAddress = NtQueryInformationThread -ThreadHandle $hThread
                $hProcess = OpenProcess -ProcessId $Thread.th32OwnerProcessID -DesiredAccess $PROCESS_ALL_ACCESS -InheritHandle $false

                if($hProcess -ne 0) {
                    $memory_basic_info = VirtualQueryEx -ProcessHandle $hProcess -BaseAddress $BaseAddress
                    $AllocatedMemoryProtection = $memory_basic_info.AllocationProtect -as $MemProtection
                    $MemoryProtection = $memory_basic_info.Protect -as $MemProtection
                    $MemoryState = $memory_basic_info.State -as $MemState
                    $MemoryType = $memory_basic_info.Type -as $MemType

                    if($MemoryState -eq $MemState::MEM_COMMIT -and $MemoryType -ne $MemType::MEM_IMAGE) {
                        $buf = ReadProcessMemory -ProcessHandle $hProcess -BaseAddress $BaseAddress -Size 100
                        $proc = Get-WmiObject Win32_Process -Filter "ProcessId = '$($Thread.th32OwnerProcessID)'"
                        $KernelPath = QueryFullProcessImageName -ProcessHandle $hProcess
                        $PathMismatch = $proc.Path.ToLower() -ne $KernelPath.ToLower()

                        # check if thread has unique token
                        try {
                            $hThreadToken = OpenThreadToken -ThreadHandle $hThread -DesiredAccess $TOKEN_ALL_ACCESS
                            $SID = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 1
                            $Privs = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 3
                            $LogonSession = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 17
                            $Integrity = GetTokenInformation -TokenHandle $hThreadToken -TokenInformationClass 25
                            $IsUniqueThreadToken = $true
                        } catch {
                            $hProcessToken = OpenProcessToken -ProcessHandle $hProcess -DesiredAccess $TOKEN_ALL_ACCESS
                            $SID = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 1
                            $Privs = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 3
                            $LogonSession = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 17
                            $Integrity = GetTokenInformation -TokenHandle $hProcessToken -TokenInformationClass 25
                            $IsUniqueThreadToken = $false
                        }

                        $ThreadDetail = New-Object PSObject
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessName -Value $proc.Name
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name ProcessId -Value $proc.ProcessId
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name Path -Value $proc.Path
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name KernelPath -Value $KernelPath
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name CommandLine -Value $proc.CommandLine
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name PathMismatch -Value $PathMismatch
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name ThreadId -Value $Thread.th32ThreadId
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name AllocatedMemoryProtection -Value $AllocatedMemoryProtection
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryProtection -Value $MemoryProtection
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryState -Value $MemoryState
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name MemoryType -Value $MemoryType
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name BasePriority -Value $Thread.tpBasePri
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name IsUniqueThreadToken -Value $IsUniqueThreadToken
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name Integrity -Value $Integrity
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name Privilege -Value $Privs
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonId -Value $LogonSession.LogonId
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name SecurityIdentifier -Value $SID
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name UserName -Value "$($LogonSession.Domain)\$($LogonSession.UserName)"
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonSessionStartTime -Value $LogonSession.StartTime
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name LogonType -Value $LogonSession.LogonType
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name AuthenticationPackage -Value $LogonSession.AuthenticationPackage
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name BaseAddress -Value $BaseAddress
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name Size -Value $memory_basic_info.RegionSize
                        $ThreadDetail | Add-Member -MemberType Noteproperty -Name Bytes -Value $buf
                        Write-Output $ThreadDetail
                    }
                    CloseHandle($hProcess)
                }
            }
            CloseHandle($hThread)
        }
    } while($Kernel32::Thread32Next($hSnapshot, [ref]$Thread))
    CloseHandle($hSnapshot)
}
