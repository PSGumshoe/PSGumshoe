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

function Measure-VectorSimilarity
{
    <# 
    
    .SYNOPSIS 
    
    Measures the vector / cosine similarity between two sets of items. 
    See: https://en.wikipedia.org/wiki/Cosine_similarity 
    
    .EXAMPLE 
    
    PS > .\Measure-VectorSimilarity.ps1 @(1..10) @(3..8) 
    0.775 
    
    .EXAMPLE 
    
    PS > $items = dir c:\windows\ | Select -First 10 
    PS > $items2 = dir c:\windows\ | Select -First 8 
    PS > .\Measure-VectorSimilarity.ps1 $items $items2 -KeyProperty Name -ValueProperty Length 
    0.894 
    
    #>

    [CmdletBinding()]
    param(
        ## The first set of items to compare
        [Parameter(Position = 0)]
        $Set1,

        ## The second set of items to compare
        [Parameter(Position = 1)]   
        $Set2,
        
        ## If the item sets represent objects that have a main property
        ## (like file names), the name of that key property 
        [Parameter()]
        $KeyProperty,

        ## If the item sets represent objects that have a main property
        ## to represent the values (like Count or Percent),
        ## the name of that key property. If they don't have a property
        ## like this, simple existence of the item will be used. 
        [Parameter()]
        $ValueProperty
    )

    ## If either set is empty, there is no similarity
    if((-not $Set1) -or (-not $Set2))
    {
        return 0
    }

    ## Figure out the unique set of items to be compared - either based on
    ## the key property (if specified), or the item value directly
    $allkeys = @($Set1) + @($Set2) | Foreach-Object {
        if($PSBoundParameters.ContainsKey("KeyProperty")) { $_.$KeyProperty }
        else { $_ }
    } | Sort-Object -Unique

    ## Figure out the values of items to be compared - either based on
    ## the value property (if specified), or the item value directly. Put
    ## these into a hashtable so that we can process them efficiently.

    $set1Hash = @{}
    $set2Hash = @{}
    $setsToProcess = @($Set1, $Set1Hash), @($Set2, $Set2Hash)

    foreach($set in $setsToProcess)
    {
        $set[0] | Foreach-Object {
            if($PSBoundParameters.ContainsKey("ValueProperty")) { $value = $_.$ValueProperty }
            else { $value = 1 }
            
            if($PSBoundParameters.ContainsKey("KeyProperty")) { $_ = $_.$KeyProperty }

            $set[1][$_] = $value
        }
    }

    ## Calculate the vector / cosine similarity of the two sets
    ## based on their keys and values.
    $dot = 0
    $mag1 = 0
    $mag2 = 0

    foreach($key in $allkeys)
    {
        $dot += $set1Hash[$key] * $set2Hash[$key]
        $mag1 +=  ($set1Hash[$key] * $set1Hash[$key])
        $mag2 +=  ($set2Hash[$key] * $set2Hash[$key])
    }

    $mag1 = [Math]::Sqrt($mag1)
    $mag2 = [Math]::Sqrt($mag2)

    ## Return the result
    [Math]::Round($dot / ($mag1 * $mag2), 3)
}

function Get-NamedPipe {
	<#
		.SYNOPSIS
			Gets named pipes on local computer.
		
		.DESCRIPTION
			Gets named pipes on the local computer.
		
		.EXAMPLE
			PS C:\> Get-PsgNamedPipes
		
		.NOTES
			Additional information about the function.
	#>

  [CmdletBinding()]
	[OutputType([PSObject])]
	param ()
	begin {
		$PipeList = @()	
	}
	process{
		$Pipes = [IO.Directory]::GetFiles('\\.\pipe\')
		
		foreach ($Pipe in $Pipes) {
			$Object = New-Object -TypeName PSObject -Property (@{ 'NamedPipe' = $Pipe })
			$PipeList += $Object
			
		}
	}
	end {
		Write-Output -InputObject $PipeList	
	}
}