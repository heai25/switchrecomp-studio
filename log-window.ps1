# Live, colour-coded Kirikae log for the game that is running (or the newest test run).
# Usage: log-window.ps1 [-Path <stderr.txt>] [-Quiet]   (-Quiet hides the per-thread timing lines)
param([string]$Path = "", [switch]$Quiet)
$Host.UI.RawUI.WindowTitle = "Kirikae log"
if (-not $Path) {
    $Path = Get-ChildItem "$PSScriptRoot\test" -Recurse -Filter stderr.txt -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $Path) { Write-Host "No log found yet. Start a game from test\live.ps1 or test\run.ps1." -ForegroundColor Yellow; Read-Host; exit }
Write-Host "Following $Path  (Ctrl+C to stop)" -ForegroundColor Cyan
Get-Content $Path -Wait -Tail 200 | ForEach-Object {
    $l = $_
    if ($Quiet -and $l -match '^kirikae:\s{3,}|guest-\d+:|SVCs per frame|lock free per') { return }
    $c = switch -Regex ($l) {
        'panic|fault|unmapped|crash|abort|svcBreak|not implemented|failed|error' { 'Red'; break }
        'skipped:|missing|placeholder|stub' { 'Yellow'; break }
        'coverage: new' { 'Magenta'; break }
        '^kirikae: \[\s*\d+s\]' { 'Green'; break }
        '^(svc|ipc|gpu):' { 'DarkCyan'; break }
        '^kirikae:\s{3,}|guest-' { 'DarkGray'; break }
        default { 'Gray' }
    }
    Write-Host $l -ForegroundColor $c
}
