@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Test-Check* / Get-* helpers are private and intentionally return plural collections.
        'PSUseSingularNouns',
        # New-* helpers only build in-memory objects; they change no system state.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
