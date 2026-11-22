function Get-MTHVerdict {
    param([int] $Score)
    if ($Score -ge 12) { 'Likely compromised' } elseif ($Score -ge 6) { 'Investigate' } else { 'Review' }
}

function ConvertTo-MTHHtml {
    param([object[]] $Findings, [object[]] $Summary, [string] $Title)
    Add-Type -AssemblyName System.Web
    $enc = { param($s) [System.Web.HttpUtility]::HtmlEncode([string]$s) }
    $vColor = @{ 'Likely compromised' = '#b91c1c'; 'Investigate' = '#c2410c'; 'Review' = '#a16207' }
    $sColor = @{ High = '#b91c1c'; Medium = '#c2410c'; Low = '#a16207' }
    $dot = [char]0x00B7
    $cards = foreach ($s in $Summary) {
        $items = foreach ($f in @($Findings | Where-Object Mailbox -EQ $s.Mailbox | Sort-Object Score -Descending)) {
            $ev = (@($f.Evidence) | Where-Object { $_ } | ForEach-Object { "<li class='mono'>$(& $enc $_)</li>" }) -join ''
            "<div class='f'><span class='sev' style='background:$($sColor[$f.Severity])'>$($f.Severity)</span> <b>$(& $enc $f.Title)</b> <span class='muted'>$($f.Category) $dot $($f.Technique) $dot +$($f.Score)</span><p>$(& $enc $f.Detail)</p>$(if ($ev) { "<ul>$ev</ul>" })</div>"
        }
        @"
<section class="card"><header><h2 class="mono">$(& $enc $s.Mailbox)</h2><span class="badge" style="background:$($vColor[$s.Verdict])">$($s.Verdict) $dot score $($s.Score)</span></header>
$($items -join "`n")
<details><summary>Incident checklist</summary><pre>$(& $enc ((Get-MTHIncidentChecklist -UserPrincipalName $s.Mailbox) -join "`n"))</pre></details></section>
"@
    }
    $generated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC'
    $likely = @($Summary | Where-Object Verdict -EQ 'Likely compromised').Count
    @"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(& $enc $Title)</title><style>
:root{--bg:#f6f4f0;--card:#fff;--ink:#16181d;--muted:#5b6270;--line:#e4dfd6;--code:#1b1d23}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1c1f25;--ink:#eceae6;--muted:#a3a9b5;--line:#2c3038;--code:#0f1115}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}.mono{font-family:ui-monospace,Menlo,monospace}.muted{color:var(--muted);font-size:13px}
h1{margin:0 0 4px;font-size:26px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin:14px 0}
.card header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}.card h2{margin:0;font-size:16px;word-break:break-all}
.badge,.sev{color:#fff;font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px}.f{border-top:1px solid var(--line);padding:10px 0}
.f p{margin:6px 0}.f ul{margin:4px 0;padding-left:18px;font-size:13px;color:var(--muted);word-break:break-all}
pre{background:var(--code);color:#e8e6e3;padding:14px;border-radius:10px;overflow-x:auto;font-size:13px;white-space:pre-wrap}summary{cursor:pointer;font-weight:600}
</style></head><body><div class="wrap">
<h1>$(& $enc $Title)</h1><p class="muted">$(@($Summary).Count) mailbox(es) with findings $dot $likely likely compromised $dot $(@($Findings).Count) findings $dot $generated $dot read-only hunt</p>
$($cards -join "`n")
<p class="muted">MailboxThreatHunter $dot github.com/CadGoose/MailboxThreatHunter</p></div></body></html>
"@
}
