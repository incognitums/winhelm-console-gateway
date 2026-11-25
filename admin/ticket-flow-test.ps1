#Regression test for the app-window launch ticket (run against an isolated admin instance).
# Proves: wrong/missing/reused ticket is rejected, the first use sets a Strict HttpOnly cookie
# carrying the launcher's token, and the API is still gated by cookie + Host + Origin.
[CmdletBinding()]
param(
    [int]    $Port = 18781,
    [string] $TicketPath,
    [string] $TokenPath,
    [string] $LogFingerprint
)

$ErrorActionPreference = 'Stop'

$ticket = (Get-Content -LiteralPath $TicketPath -Raw).Trim()
$token  = (Get-Content -LiteralPath $TokenPath -Raw).Trim()
$base   = "http://127.0.0.1:$Port"

$results = [System.Collections.Generic.List[object]]::new()
function Rec([string] $name, [bool] $ok, [string] $detail) {
    $results.Add([pscustomobject]@{ check = $name; ok = $ok; detail = $detail })
}

# A client that never follows a redirect: Invoke-WebRequest -MaximumRedirection 0 throws
# instead of returning the 302, which would hide the status we are trying to assert.
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
# UseCookies must be off. With the default jar, the Set-Cookie from __launch is replayed on
# every later request and the "no credential" cases would pass for the wrong reason.
$handler.UseCookies = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(10)

function Send([string] $url, [hashtable] $headers) {
    $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
    foreach ($k in $headers.Keys) { [void]$req.Headers.TryAddWithoutValidation($k, $headers[$k]) }
    $resp = $client.SendAsync($req).GetAwaiter().GetResult()
    $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $setCookie = @()
    if ($resp.Headers.Contains('Set-Cookie')) { $setCookie = @($resp.Headers.GetValues('Set-Cookie')) }
    [pscustomobject]@{
        Status    = [int]$resp.StatusCode
        Location  = if ($resp.Headers.Location) { $resp.Headers.Location.ToString() } else { $null }
        SetCookie = ($setCookie -join ' | ')
        Body      = $body
    }
}

# 0. the fingerprint in the log must be the hash of the ticket we handed over
$fp = ([System.BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($ticket))
    )).Replace('-', '').Substring(0, 12)
Rec 'fingerprint in log = sha256(ticket)[0..12]' ($LogFingerprint -eq $fp) "calc=$fp log=$LogFingerprint"

# 1-2. rejected tickets
$r = Send "$base/__launch?t=not-the-ticket-value" @{}
Rec 'wrong ticket -> 403' ($r.Status -eq 403) "status=$($r.Status)"

$r = Send "$base/__launch" @{}
Rec 'missing ticket -> 403' ($r.Status -eq 403) "status=$($r.Status)"

# 3. no cookie
$r = Send "$base/api/state" @{}
Rec 'api without cookie -> 401' ($r.Status -eq 401) "status=$($r.Status)"

# 4. first use of the real ticket
$r = Send "$base/__launch?t=$ticket" @{}
Rec 'correct ticket -> 302' ($r.Status -eq 302) "status=$($r.Status)"
Rec 'location is /' ($r.Location -eq '/') "location=$($r.Location)"
Rec 'cookie HttpOnly' ($r.SetCookie -match 'HttpOnly') $r.SetCookie
Rec 'cookie SameSite=Strict' ($r.SetCookie -match 'SameSite=Strict') 'SameSite=Strict'
Rec 'cookie carries launcher token' ($r.SetCookie -match [regex]::Escape($token)) 'token matched'
Rec 'cookie is not scoped to a path outside /' ($r.SetCookie -match 'Path=/') 'Path=/'

# 5. second use
$r = Send "$base/__launch?t=$ticket" @{}
Rec 'reused ticket -> 403' ($r.Status -eq 403) "status=$($r.Status)"

# 6-8. the API gate
$r = Send "$base/api/state" @{ Cookie = "admin_token=$token" }
Rec 'api with cookie -> 200' ($r.Status -eq 200) "status=$($r.Status) len=$($r.Body.Length)"

$r = Send "$base/api/state" @{ Cookie = 'admin_token=deadbeefdeadbeefdeadbeefdeadbeef' }
Rec 'api with wrong cookie -> 401' ($r.Status -eq 401) "status=$($r.Status)"

$r = Send "$base/api/state" @{ Cookie = "admin_token=$token"; Origin = 'http://evil.example' }
Rec 'cross-origin -> 403' ($r.Status -eq 403) "status=$($r.Status)"

$r = Send "$base/api/state" @{ Cookie = "admin_token=$token"; Host = 'evil.example' }
Rec 'wrong Host header -> 421' ($r.Status -eq 421) "status=$($r.Status)"

$r = Send "$base/api/state?token=$token" @{}
Rec 'token in query string is not accepted' ($r.Status -eq 401) "status=$($r.Status)"

$client.Dispose()

$results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
$pass = ($results | Where-Object { $_.ok }).Count
$fail = $results.Count - $pass
Write-Host "RESULT: pass=$pass fail=$fail"
if ($fail -gt 0) { exit 1 }
