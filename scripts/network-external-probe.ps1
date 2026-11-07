# Run from an independent Windows LAN host, never from the gateway.
# Checks reachability and expected Basic authentication challenge; no credentials sent.
param(
    [string]$Url = 'http://192.168.1.201:8080/',
    [int]$TimeoutSec = 5
)
$ErrorActionPreference = 'Stop'
try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec
    $status = [int]$response.StatusCode
    $auth = [string]$response.Headers['WWW-Authenticate']
} catch {
    if ($null -eq $_.Exception.Response) {
        Write-Output ('PROBE_FAILED: ' + $_.Exception.Message)
        exit 2
    }
    $status = [int]$_.Exception.Response.StatusCode
    $auth = [string]$_.Exception.Response.Headers['WWW-Authenticate']
}
if ($status -eq 401 -and $auth -like 'Basic realm=*') {
    Write-Output 'PROBE_OK: external WebAdmin reachable; HTTP 401 Basic authentication enforced'
    exit 0
}
Write-Output ('PROBE_FAILED: unexpected status=' + $status + ' auth=' + $auth)
exit 1
