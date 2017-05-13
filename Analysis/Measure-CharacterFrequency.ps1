function Measure-CharacterFrequency
{
    <#

    .SYNOPSIS

    Measures the letter / character frequency in a block of text, ignoring whitespace
    and PowerShell comment blocks.

    #>

    [CmdletBinding(DefaultParameterSetName = "ByPath")]
    param(
        ## The path of items with content
        [Parameter(ParameterSetName = "ByPath", Position = 0)]
        $Path,

        ## The literal path of items with content
        [Parameter(ParameterSetName = "ByLiteralPath", Position = 0, ValueFromPipelineByPropertyName)]
        [Alias("PSPath")]
        $LiteralPath,

        ## The actual content to be measured
        [Parameter(ParameterSetName = "ByContent")]
        [String]
        $Content
    )

    begin
    {
        $characterMap = @{}
    }

    process
    {
        if($PSCmdlet.ParameterSetName -ne "ByContent")
        {
            ## If the items were piped in or supplied by Path / LiteralPath, get the content of each of them.
            Get-ChildItem @PSBoundParameters | Foreach-Object {
                $content = Get-Content -LiteralPath $_.FullName -Raw

                ## Remove comments and whitespace
                ($content -replace '(?s)<#.*?#>','' -replace '#.*','' -replace '(?s)\s','').ToCharArray() | % {
                    $key = $_.ToString().ToUpper()

                    ## And store the character frequency for each character
                    $characterMap[$key] = 1 + $characterMap[$key] }
            }
        }
        else
        {
            ## Remove comments and whitespace
            ($content -replace '(?s)<#.*?#>','' -replace '#.*','' -replace '\s','').ToCharArray() | % {
                $key = $_.ToString().ToUpper()

                ## And store the character frequency for each character
                $characterMap[$key] = 1 + $characterMap[$key] }
        }
    }

    end
    {
        ## Figure out how many characters were present in total so that we can calculate a percentage
        $total = $characterMap.GetEnumerator() | Measure-Object -sum Value | % Sum

        ## And generate nice object-based output for each character and its frequency
        $characterMap.GetEnumerator() | Sort-Object -desc value | % {
            [PSCustomObject] @{ Name = $_.Name; Percent = [Math]::Round($_.Value / $total * 100, 3) } }
    }
}