Describe "Measure-CharacterFrequency" {

    It "Validates by content, one item" {
        $characterFrequency = Measure-PsgCharacterFrequency -Content "A"
        $characterFrequency | Where-Object Name -eq 'A' | Foreach-Object Percent | Should be 100
    }

    It "Validates by content, multiple items" {
        $characterFrequency = Measure-PsgCharacterFrequency -Content "AB"
        $characterFrequency | Where-Object Name -eq 'A' | Foreach-Object Percent | Should be 50
        $characterFrequency | Where-Object Name -eq 'B' | Foreach-Object Percent | Should be 50
    }

    It "Validates by content, long string" {
        $characterFrequency = Measure-PsgCharacterFrequency -Content ("A" * 1kb)
        $characterFrequency | Where-Object Name -eq 'A' | Foreach-Object Percent | Should be 100
    }

    It "Validates whitespace and comments are stripped" {
        $characterFrequency = Measure-PsgCharacterFrequency -Content "Hello World <# Something in a comment #> Hello # More comment stuff"
        
        $characterFrequency | Where-Object Name -eq 'L' | Foreach-Object Percent | Should be 33.333
        $characterFrequency | Where-Object Name -eq 'O' | Foreach-Object Percent | Should be 20
        $characterFrequency | Where-Object Name -eq 'H' | Foreach-Object Percent | Should be 13.333
        $characterFrequency | Where-Object Name -eq 'R' | Foreach-Object Percent | Should be 6.667
        $characterFrequency | Where-Object Name -eq 'D' | Foreach-Object Percent | Should be 6.667
        $characterFrequency | Where-Object Name -eq 'W' | Foreach-Object Percent | Should be 6.667

        $characterFrequency | Measure-Object -Sum Percent | Foreach-Object Sum | Should be 100
    }

    It "Validates processing by path" {
        $content = "Hello World <# Something in a comment #> Hello # More comment stuff"

        try
        {
            $tempFile = New-TemporaryFile
            $tempFile | Set-Content -Value $content

            $characterFrequency = $tempFile | Measure-PsgCharacterFrequency
            
            $characterFrequency | Where-Object Name -eq 'L' | Foreach-Object Percent | Should be 33.333
            $characterFrequency | Where-Object Name -eq 'O' | Foreach-Object Percent | Should be 20
            $characterFrequency | Where-Object Name -eq 'H' | Foreach-Object Percent | Should be 13.333
            $characterFrequency | Where-Object Name -eq 'R' | Foreach-Object Percent | Should be 6.667
            $characterFrequency | Where-Object Name -eq 'D' | Foreach-Object Percent | Should be 6.667
            $characterFrequency | Where-Object Name -eq 'W' | Foreach-Object Percent | Should be 6.667

            $characterFrequency | Measure-Object -Sum Percent | Foreach-Object Sum | Should be 100            
        }
        finally
        {
            Remove-Item $tempFile            
        }
    }
    
}