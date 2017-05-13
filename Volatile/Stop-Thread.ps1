function Stop-Thread {
    <#

    .SYNOPSIS

    Terminates a specified Thread.

    .DESCRIPTION

    The Stop-Thread function can stop an individual thread in a process. This is quite useful in situations where code injection (dll injection) techniques have been used by attackers. If an attacker runs their malicious code in a thread within a critical process, then Stop-Thread can kill the malicious thread without hurting the critical process.

    .NOTES

    Author - Jared Atkinson (@jaredcatkinson)

    .EXAMPLE

    PS > Stop-Thread -ThreadId 1776

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [UInt32]
        $ThreadId
    )

    $hThread = OpenThread -ThreadId $ThreadId -DesiredAccess $THREAD_TERMINATE
    TerminateThread -ThreadHandle $hThread
    CloseHandle -Handle $hThread
}