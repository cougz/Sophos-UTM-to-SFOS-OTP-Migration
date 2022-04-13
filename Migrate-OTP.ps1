##  Script name:   Migrate-OTP.ps1
##  Created on:    t.b.a
##  Version:       1.0
##  Author:        Tim Seiffert
##  Purpose:       Migrate OTP Tokens from Sophos UTM to Sophos XG(S) Firewall

#Willkommensgruß

#Abfrage Variablen
$utm_webadmin = Read-Host "Wie lautet die Adresse des WebAdmin der UTM? Bitte in folgendem Format angeben, z.B. 172.16.16.16:4444"
$utm_api_key = Read-Host "Bitte den API Key eingeben"
<# $utm_webadmin = "172.17.17.44:4444"
$utm_api_key = "FdhgRhatOXcfgVlMQKnUFgayBnOShbis" #>

#URI's bauen
$uri_utm_api_otp = "https://" + $utm_webadmin + "/api/objects/authentication/otp_token/"
$uri_utm_api_user = "https://" + $utm_webadmin + "/api/objects/aaa/user/"

#API Header
$authorization_header_plain = "token:" + $utm_api_key
$authorization_header_base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($authorization_header_plain))
$headers=@{}
$headers.Add("Accept", "application/json")
$headers.Add("Authorization", "Basic $authorization_header_base64")

#Ignore self signed certs
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#API Call OTP Token
$response = Invoke-RestMethod -Uri $uri_utm_api_otp -Method GET -Headers $headers
$hashtable = @{}

foreach ($name in $response.name) {
        for ($i = 0; $i -lt $response.name.count; $i++){
            $uri_utm_api_user_ref = $uri_utm_api_user + $response.user[$i]
            $response2 = Invoke-RestMethod -Uri $uri_utm_api_user_ref -Method GET -Headers $headers
        }
        $hashtable.Add($name, $response2.name)
}

if ($hashtable.Count -ne 0){
    $hashtable = $hashtable.GetEnumerator() | Sort-Object -Property @{e={$_.name}}
    $hashtable | ForEach-Object{
        Write-Host "`n`n`nToken" -ForegroundColor Yellow 
        Write-Host $_.Key
        Write-Host "`nUser" -ForegroundColor Yellow
        Write-Host $_.Value
    }
    Write-Host "`n`n...done!" -ForegroundColor Green
}