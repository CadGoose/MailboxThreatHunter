#Requires -Version 7.2
Set-StrictMode -Version Latest

foreach ($folder in 'Private', 'Public') {
    $path = Join-Path $PSScriptRoot $folder
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }
    }
}
