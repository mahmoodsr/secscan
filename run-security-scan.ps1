param(
    [Parameter(Position = 0)][string]$Project,
    [switch]$NoFail, [switch]$Build, [string]$Only, [string]$Skip,
    [string]$Timeout, [string]$Config, [switch]$SelfTest, [switch]$Version,
    [switch]$UI
)

$venv = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
$launcherArgs = @()
if (Test-Path $venv) { $python = $venv }
elseif (Get-Command py -ErrorAction SilentlyContinue) { $python = 'py'; $launcherArgs = @('-3') }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $python = 'python' }
else { $python = $null }

if ($python) {
    & $python @launcherArgs -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>$null
}
if (!$python -or $LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine('Python 3.9+ is required. Install with: winget install -e --id Python.Python.3.13')
    exit 3
}

$forward = @()
if ($NoFail) { $forward += '--no-fail' }
if ($Build) { $forward += '--build' }
if ($Only) { $forward += @('--only', $Only) }
if ($Skip) { $forward += @('--skip', $Skip) }
if ($Timeout) { $forward += @('--timeout', $Timeout) }
if ($Config) { $forward += @('--config', $Config) }
if ($SelfTest) { $forward += '--self-test' }
if ($Version) { $forward += '--version' }
if ($Project) { $forward += @('--', $Project) }

$previous = $env:PYTHONPATH
try {
    $env:PYTHONPATH = if ($previous) { "$PSScriptRoot;$previous" } else { $PSScriptRoot }
    if ($UI) {
        & $python @launcherArgs -m secscan ui
    } else {
        & $python @launcherArgs -m secscan scan @forward
    }
    $code = $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $previous
}
exit $code
