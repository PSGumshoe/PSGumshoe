Describe 'Get-PsgNamedPipe' {
	It 'Runs without error' {
		{ Get-PsgNamedPipe } | Should Not Throw
	}
	
	It 'Finds the LSASS Pipe' {
		$Pipes = Get-PsgNamedPipe
		foreach ($Pipe in $Pipes) {
			if ($Pipe -contains '\\.\pipe\lsass') {
				$Found = $true	
			}
		}
		
		$Found | Should Be $true
	}
}