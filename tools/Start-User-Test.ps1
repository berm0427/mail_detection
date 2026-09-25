[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$PrepareOnly
)

$ErrorActionPreference = 'Stop'

function Write-Ok($Message) {
    Write-Host "[OK] $Message"
}

function Write-WarnLine($Message) {
    Write-Host "[WARN] $Message"
}

function Write-ErrorLine($Message) {
    Write-Host "[ERROR] $Message"
}

function Test-RequiredPath($Label, $Path) {
    if (Test-Path -LiteralPath $Path) {
        Write-Ok $Label
        return $true
    }
    Write-ErrorLine "$Label path is missing: $Path"
    return $false
}

function Test-TcpPort($HostName, $Port, $TimeoutMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        $ready = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ready) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Test-RazorRelay($TimeoutMs) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', 57698, $null, $null)
        $ready = $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $ready) {
            return $false
        }
        $client.EndConnect($async)
        $client.ReceiveTimeout = $TimeoutMs
        $client.SendTimeout = $TimeoutMs
        $stream = $client.GetStream()
        $probe = [System.Text.Encoding]::ASCII.GetBytes("CONNECT example.com:2703 HTTP/1.0`r`n`r`n")
        $stream.Write($probe, 0, $probe.Length)
        $buffer = New-Object byte[] 128
        $count = $stream.Read($buffer, 0, $buffer.Length)
        if ($count -le 0) {
            return $false
        }
        $response = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        return $response.StartsWith('HTTP/1.0 403 Forbidden')
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Test-PortOpen($TimeoutMs) {
    return Test-TcpPort '127.0.0.1' 57698 $TimeoutMs
}

function Start-RazorRelayIfNeeded($LauncherPython, $TunnelScript, $TimeoutSeconds) {
    if (Test-RazorRelay 1000) {
        Write-Ok 'Razor relay is ready on 127.0.0.1:57698'
        return $true
    }

    if (Test-PortOpen 1000) {
        Write-ErrorLine 'Port 127.0.0.1:57698 is occupied, but it did not respond like the expected Razor relay.'
        Write-ErrorLine 'No process was stopped. Free the port or start the existing Razor relay manually, then retry.'
        exit 5
    }

    if (-not (Test-Path -LiteralPath $LauncherPython)) {
        Write-ErrorLine "Razor relay launcher Python is missing: $LauncherPython"
        exit 6
    }
    if (-not (Test-Path -LiteralPath $TunnelScript)) {
        Write-ErrorLine "Razor relay script is missing: $TunnelScript"
        exit 6
    }

    Write-Host 'Razor relay is not running. Starting existing relay as a hidden process...'
    Start-Process -WindowStyle Hidden -FilePath $LauncherPython -ArgumentList ('"' + $TunnelScript + '"') | Out-Null

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 250
        if (Test-RazorRelay 1000) {
            Write-Ok 'Razor relay started and is ready on 127.0.0.1:57698'
            return $true
        }
        if ((Test-PortOpen 250) -and -not (Test-RazorRelay 250)) {
            Write-ErrorLine 'Port 127.0.0.1:57698 became occupied, but the expected Razor relay was not confirmed.'
            Write-ErrorLine 'No process was stopped. Check the process that owns the port and retry.'
            exit 5
        }
    }

    Write-ErrorLine "Razor relay did not become ready within $TimeoutSeconds seconds."
    Write-ErrorLine 'GUI launch was stopped so Razor lookup is not silently run without the relay.'
    exit 7
}

$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$WorkRoot = 'C:\Users\berm0\Documents\Codex\2026-09-11\x20\work'
$PythonExe = Join-Path $WorkRoot 'analysis-venv\Scripts\python.exe'
$PerlExe = Join-Path $WorkRoot 'strawberry\perl\bin\perl.exe'
$RazorCheck = Join-Path $WorkRoot 'strawberry\perl\site\bin\razor-check'
$RazorHome = Join-Path $WorkRoot 'razor-home'
$RazorConf = Join-Path $RazorHome 'razor-agent.conf'
$RazorTunnel = Join-Path $WorkRoot 'razor_tunnel.py'
$RazorTunnelPython = 'C:\Python314\python.exe'
$PythonWrapper = Join-Path $ProjectRoot 'tools\run_user_test_gui.py'
$MainGui = Join-Path $ProjectRoot 'main_gui.py'
$EngineConfig = Join-Path $ProjectRoot 'engine_config.json'
$SyntheticEmlDir = Join-Path $ProjectRoot 'tests\synthetic_eml'

Write-Host '=== User acceptance GUI launcher preflight ==='

$allRequired = $true
$allRequired = (Test-RequiredPath 'Project root' $ProjectRoot) -and $allRequired
$allRequired = (Test-RequiredPath 'Python 3.11 analysis environment' $PythonExe) -and $allRequired
$allRequired = (Test-RequiredPath 'GUI entrypoint' $MainGui) -and $allRequired
$allRequired = (Test-RequiredPath 'Python GUI wrapper' $PythonWrapper) -and $allRequired
$allRequired = (Test-RequiredPath 'Engine configuration' $EngineConfig) -and $allRequired
$allRequired = (Test-RequiredPath 'Synthetic EML test directory' $SyntheticEmlDir) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor Perl runtime' $PerlExe) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor check command' $RazorCheck) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor home directory' $RazorHome) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor agent configuration file' $RazorConf) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor relay script' $RazorTunnel) -and $allRequired
$allRequired = (Test-RequiredPath 'Razor relay launcher Python' $RazorTunnelPython) -and $allRequired

if (Test-Path -LiteralPath $PythonExe) {
    $pyVersion = (& $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null)
    if ($pyVersion -eq '3.11') {
        Write-Ok 'Python version is 3.11'
    }
    else {
        Write-ErrorLine "Expected Python 3.11 but found Python $pyVersion"
        $allRequired = $false
    }
}

$razorPortOpen = Test-PortOpen 1000
$razorRelayReady = Test-RazorRelay 1000
if ($razorRelayReady) {
    Write-Ok 'Razor relay is ready on 127.0.0.1:57698'
}
elseif ($razorPortOpen) {
    Write-ErrorLine 'Port 127.0.0.1:57698 is occupied, but the expected Razor relay was not confirmed.'
    Write-ErrorLine 'No process will be stopped by this launcher.'
}
else {
    Write-WarnLine 'Razor relay is not accepting TCP connections on 127.0.0.1:57698.'
    if ($CheckOnly) {
        Write-WarnLine 'Check-only mode is read-only and will not start the relay.'
    }
    else {
        Write-WarnLine 'The launcher will try to start the existing relay before GUI execution.'
    }
}

$env:PYTHONIOENCODING = 'utf-8'

if ($CheckOnly) {
    Write-Host '=== Check-only mode: GUI was not launched ==='
    if (-not $allRequired) {
        exit 3
    }
    if ($razorPortOpen -and -not $razorRelayReady) {
        exit 5
    }
    if (-not $razorRelayReady) {
        exit 4
    }
    exit 0
}

if (-not $allRequired) {
    Write-ErrorLine 'Required paths are missing. Fix the reported paths and run Start-User-Test.bat again.'
    exit 3
}

$relayPrepared = Start-RazorRelayIfNeeded $RazorTunnelPython $RazorTunnel 10

if ($PrepareOnly) {
    Write-Host '=== Prepare-only mode: Razor relay is ready; GUI was not launched ==='
    exit 0
}

Write-Host '=== Launching visible GUI. Close the GUI window to end this launcher. ==='
Push-Location $ProjectRoot
try {
    & $PythonExe -B $PythonWrapper
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
