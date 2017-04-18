Describe -Name 'Get-PsgEncoding' {
    ## Setup
    $Path = "$TestDrive\Test.txt"
    Add-Content -Path $Path -Value "This is a pester test."

    It -Name 'Runs without errors' -Pending -Test {
        {Get-PsgEncoding -Path $Path} | Should Not Throw
    }
    It -Name 'Accepts Pipeline Input' -Pending -Test {
        {TestDrive:\Test.txt | Get-PsgEncoding} | Should Not Throw
    }
    It -Name 'Returns the correct Path' -Pending -Test {
        (Get-PsgEncoding -Path $Path).Path | Should Be $Path
    }
    It -Name 'Returns the correct encoding' -Pending -Test {
        (Get-PsgEncoding -Path $Path).Encoding | Should Be 'Encoding'
    }
}