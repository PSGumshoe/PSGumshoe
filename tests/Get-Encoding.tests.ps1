Describe -Name 'Get-PsgEncoding' {
    ## Setup
    $Path = "$TestDrive\Test.txt"
    Add-Content -Path $Path -Value "This is a pester test."

    It -Name 'Runs without errors' -Test {
        {Get-PsgEncoding -Path $Path} | Should Not Throw
    }
    It -Name 'Accepts Pipeline Input' -Test {
        {$Path | Get-PsgEncoding} | Should Not Throw
    }
    It -Name 'Returns the correct Path' -Test {
        (Get-PsgEncoding -Path $Path).Path | Should Be $Path
    }
    It -Name 'Returns the correct encoding' -Test {
        (Get-PsgEncoding -Path $Path).Encoding | Should Be 'Unicode (UTF-8)'
    }
}