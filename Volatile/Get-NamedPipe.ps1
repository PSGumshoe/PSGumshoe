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