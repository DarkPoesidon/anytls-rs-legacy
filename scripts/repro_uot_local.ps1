Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Repro script for local UDP ASSOCIATE testing with anytls-server and anytls-client, run from the repository root with:
# ```
# powershell -ExecutionPolicy Bypass -File ./scripts/repro_uot_local.ps1
# ```

$repoRoot = Split-Path -Parent $PSScriptRoot
$password = "password"
$serverListen = "127.0.0.1:18443"
$clientListen = "127.0.0.1:12080"
$udpEchoPort = 19090
$artifactsDir = Join-Path $repoRoot "target\uot-local"
$debugDir = Join-Path $repoRoot "target\debug"
$serverBinary = Join-Path $debugDir "anytls-server.exe"
$clientBinary = Join-Path $debugDir "anytls-client.exe"
$udpEchoHelperScript = Join-Path $artifactsDir "udp-echo-helper.ps1"
$udpEchoLog = Join-Path $artifactsDir "udp-echo.stdout.log"
$udpEchoErrLog = Join-Path $artifactsDir "udp-echo.stderr.log"
$serverLog = Join-Path $artifactsDir "server.stdout.log"
$serverErrLog = Join-Path $artifactsDir "server.stderr.log"
$clientLog = Join-Path $artifactsDir "client.stdout.log"
$clientErrLog = Join-Path $artifactsDir "client.stderr.log"

New-Item -ItemType Directory -Force -Path $artifactsDir | Out-Null

if (-not (Test-Path $serverBinary)) {
    throw "Server binary not found at '$serverBinary'. Build it first with: cargo build --bin anytls-server"
}

if (-not (Test-Path $clientBinary)) {
    throw "Client binary not found at '$clientBinary'. Build it first with: cargo build --bin anytls-client"
}

function Wait-TcpReady {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$TimeoutSeconds = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $tcp = $null
        try {
            $tcp = [System.Net.Sockets.TcpClient]::new()
            $iar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(500) -and $tcp.Connected) {
                $tcp.EndConnect($iar)
                $tcp.Dispose()
                return
            }
        } catch {
        } finally {
            if ($tcp -ne $null) {
                $tcp.Dispose()
            }
        }

        Start-Sleep -Milliseconds 300
    }

    throw "Timed out waiting for TCP endpoint ${TargetHost}:${Port}"
}

function Read-Exact {
    param(
        [System.IO.Stream]$Stream,
        [int]$Count
    )

    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            throw "Unexpected EOF while reading $Count bytes"
        }
        $offset += $read
    }
    return $buffer
}

function Read-Socks5Address {
    param([System.IO.Stream]$Stream)

    $atyp = (Read-Exact -Stream $Stream -Count 1)[0]
    switch ($atyp) {
        1 {
            $addrBytes = Read-Exact -Stream $Stream -Count 4
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $ip = [System.Net.IPAddress]::new($addrBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            return [System.Net.IPEndPoint]::new($ip, $port)
        }
        4 {
            $addrBytes = Read-Exact -Stream $Stream -Count 16
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $ip = [System.Net.IPAddress]::new($addrBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            return [System.Net.IPEndPoint]::new($ip, $port)
        }
        3 {
            $len = (Read-Exact -Stream $Stream -Count 1)[0]
            $hostBytes = Read-Exact -Stream $Stream -Count $len
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $host = [System.Text.Encoding]::ASCII.GetString($hostBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            $ip = ([System.Net.Dns]::GetHostAddresses($host) | Select-Object -First 1)
            return [System.Net.IPEndPoint]::new($ip, $port)
        }
        default {
            throw "Unsupported SOCKS5 ATYP $atyp"
        }
    }
}

function Read-Socks5AddressWithAtyp {
    param(
        [byte]$Atyp,
        [System.IO.Stream]$Stream
    )

    switch ($Atyp) {
        1 {
            $addrBytes = Read-Exact -Stream $Stream -Count 4
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $ip = [System.Net.IPAddress]::new($addrBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail = [byte[]]($addrBytes + $portBytes)
            }
        }
        4 {
            $addrBytes = Read-Exact -Stream $Stream -Count 16
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $ip = [System.Net.IPAddress]::new($addrBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail = [byte[]]($addrBytes + $portBytes)
            }
        }
        3 {
            $len = (Read-Exact -Stream $Stream -Count 1)[0]
            $hostBytes = Read-Exact -Stream $Stream -Count $len
            $portBytes = Read-Exact -Stream $Stream -Count 2
            $host = [System.Text.Encoding]::ASCII.GetString($hostBytes)
            $port = ([int]$portBytes[0] * 256) + [int]$portBytes[1]
            $ip = ([System.Net.Dns]::GetHostAddresses($host) | Select-Object -First 1)
            return [pscustomobject]@{
                Endpoint = [System.Net.IPEndPoint]::new($ip, $port)
                RawTail = [byte[]](@($len) + $hostBytes + $portBytes)
            }
        }
        default {
            throw "Unsupported SOCKS5 ATYP $Atyp"
        }
    }
}

function New-Socks5UdpPacket {
    param(
        [byte[]]$Payload,
        [string]$TargetHost,
        [int]$TargetPort
    )

    $targetIp = [System.Net.IPAddress]::Parse($TargetHost)
    $packet = [System.Collections.Generic.List[byte]]::new()
    $packet.Add(0)
    $packet.Add(0)
    $packet.Add(0)

    if ($targetIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $packet.Add(1)
    } elseif ($targetIp.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $packet.Add(4)
    } else {
        throw "Unsupported target address family: $($targetIp.AddressFamily)"
    }

    $packet.AddRange([byte[]]$targetIp.GetAddressBytes())
    $packet.Add([byte](($TargetPort -shr 8) -band 0xff))
    $packet.Add([byte]($TargetPort -band 0xff))
    $packet.AddRange([byte[]]$Payload)

    return $packet.ToArray()
}

function Parse-Socks5UdpPacket {
    param([byte[]]$Packet)

    if ($Packet.Length -lt 4) {
        throw "UDP relay packet too short"
    }

    $frag = $Packet[2]
    if ($frag -ne 0) {
        throw "Unexpected SOCKS5 UDP fragment number $frag"
    }

    $offset = 3
    $atyp = $Packet[$offset]
    $offset += 1

    switch ($atyp) {
        1 {
            $addrLen = 4
            $address = [System.Net.IPAddress]::new($Packet[$offset..($offset + $addrLen - 1)])
            $offset += $addrLen
        }
        4 {
            $addrLen = 16
            $address = [System.Net.IPAddress]::new($Packet[$offset..($offset + $addrLen - 1)])
            $offset += $addrLen
        }
        3 {
            $nameLen = $Packet[$offset]
            $offset += 1
            $address = [System.Text.Encoding]::ASCII.GetString($Packet[$offset..($offset + $nameLen - 1)])
            $offset += $nameLen
        }
        default {
            throw "Unsupported UDP relay ATYP $atyp"
        }
    }

    $port = ([int]$Packet[$offset] * 256) + [int]$Packet[$offset + 1]
    $offset += 2
    $payload = if ($offset -lt $Packet.Length) { $Packet[$offset..($Packet.Length - 1)] } else { [byte[]]::new(0) }

    return [pscustomobject]@{
        Address = $address
        Port = $port
        Payload = [byte[]]$payload
    }
}

function Request-ProcessTermination {
    param(
        [System.Diagnostics.Process]$Process,
        [string]$Name
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if ($Process.HasExited) {
            return
        }
    } catch {
        return
    }

    Write-Host "Stopping $Name..."
    Start-Process taskkill -ArgumentList @("/PID", $Process.Id, "/F", "/T") -WindowStyle Hidden | Out-Null
}

$udpJob = $null
$udpEchoProcess = $null
$serverProcess = $null
$clientProcess = $null
$controlTcp = $null
$udpClient = $null

try {
    Write-Host "Starting local UDP echo server on 127.0.0.1:$udpEchoPort"
    @'
param([int]$Port)
$udp = [System.Net.Sockets.UdpClient]::new($Port)
try {
    while ($true) {
        $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
        $data = $udp.Receive([ref]$remote)
        [void]$udp.Send($data, $data.Length, $remote)
    }
}
finally {
    $udp.Dispose()
}
'@ | Set-Content -Path $udpEchoHelperScript -Encoding ASCII

    $udpEchoProcess = Start-Process powershell -WorkingDirectory $repoRoot -ArgumentList @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", $udpEchoHelperScript,
        "-Port", $udpEchoPort
    ) -WindowStyle Hidden -RedirectStandardOutput $udpEchoLog -RedirectStandardError $udpEchoErrLog -PassThru

    Write-Host "Starting anytls-server on $serverListen from $serverBinary"
    $serverProcess = Start-Process $serverBinary -WorkingDirectory $repoRoot -ArgumentList @("-l", $serverListen, "-p", $password) -RedirectStandardOutput $serverLog -RedirectStandardError $serverErrLog -PassThru

    Write-Host "Starting anytls-client on $clientListen from $clientBinary"
    $clientProcess = Start-Process $clientBinary -WorkingDirectory $repoRoot -ArgumentList @("-l", $clientListen, "-s", $serverListen, "-p", $password) -RedirectStandardOutput $clientLog -RedirectStandardError $clientErrLog -PassThru

    Wait-TcpReady -TargetHost "127.0.0.1" -Port 18443
    Wait-TcpReady -TargetHost "127.0.0.1" -Port 12080

    Write-Host "Opening SOCKS5 control connection"
    $controlTcp = [System.Net.Sockets.TcpClient]::new("127.0.0.1", 12080)
    $controlStream = $controlTcp.GetStream()

    $controlStream.Write([byte[]](0x05, 0x01, 0x00), 0, 3)
    $authResp = Read-Exact -Stream $controlStream -Count 2
    if ($authResp[0] -ne 0x05 -or $authResp[1] -ne 0x00) {
        throw "SOCKS5 auth negotiation failed: $([System.BitConverter]::ToString($authResp))"
    }

    $udpAssociateReq = [byte[]](0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    $controlStream.Write($udpAssociateReq, 0, $udpAssociateReq.Length)

    $replyHead = Read-Exact -Stream $controlStream -Count 4
    if ($replyHead[0] -ne 0x05 -or $replyHead[1] -ne 0x00) {
        throw "UDP ASSOCIATE failed: $([System.BitConverter]::ToString($replyHead))"
    }

    $replyAddress = Read-Socks5AddressWithAtyp -Atyp $replyHead[3] -Stream $controlStream
    $relayEndpoint = $replyAddress.Endpoint
    $replyRaw = [byte[]]($replyHead + $replyAddress.RawTail)
    Write-Host "UDP ASSOCIATE raw response: $([System.BitConverter]::ToString($replyRaw))"
    Write-Host "SOCKS5 UDP relay is listening on $relayEndpoint"

    $udpClient = [System.Net.Sockets.UdpClient]::new()
    $udpClient.Client.ReceiveTimeout = 5000

    $payload = [System.Text.Encoding]::UTF8.GetBytes("anytls-uot-ok")
    $packet = New-Socks5UdpPacket -Payload $payload -TargetHost "127.0.0.1" -TargetPort $udpEchoPort
    [void]$udpClient.Send($packet, $packet.Length, $relayEndpoint)

    $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $response = $udpClient.Receive([ref]$remote)
    $decoded = Parse-Socks5UdpPacket -Packet $response
    $responsePayload = [System.Text.Encoding]::UTF8.GetString($decoded.Payload)

    if ($responsePayload -ne "anytls-uot-ok") {
        throw "Unexpected UDP payload: '$responsePayload'"
    }

    if ($decoded.Port -ne $udpEchoPort) {
        throw "Unexpected UDP source port $($decoded.Port), expected $udpEchoPort"
    }

    Write-Host "UDP ASSOCIATE end-to-end validation passed"
}
catch {
    Write-Error $_
    if (Test-Path $serverLog) {
        Write-Host "--- anytls-server stdout ---"
        Get-Content $serverLog -Tail 50
    }
    if (Test-Path $serverErrLog) {
        Write-Host "--- anytls-server stderr ---"
        Get-Content $serverErrLog -Tail 50
    }
    if (Test-Path $clientLog) {
        Write-Host "--- anytls-client stdout ---"
        Get-Content $clientLog -Tail 50
    }
    if (Test-Path $clientErrLog) {
        Write-Host "--- anytls-client stderr ---"
        Get-Content $clientErrLog -Tail 50
    }
    exit 1
}
finally {
    if ($udpClient -ne $null) {
        $udpClient.Dispose()
    }
    if ($controlTcp -ne $null) {
        $controlTcp.Dispose()
    }
    Request-ProcessTermination -Process $clientProcess -Name "anytls-client"
    Request-ProcessTermination -Process $serverProcess -Name "anytls-server"
    Request-ProcessTermination -Process $udpEchoProcess -Name "udp-echo helper"
    if (Test-Path $udpEchoHelperScript) {
        Remove-Item $udpEchoHelperScript -Force -ErrorAction SilentlyContinue
    }
}