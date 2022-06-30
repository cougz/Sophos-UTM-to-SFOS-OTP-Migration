##  Script name:   Migrate-OTP.ps1
##  Created on:    06/29/2022
##  Version:       1.0
##  Author:        Tim Seiffert
##  Purpose:       Migrate OTP Tokens from Sophos UTM to Sophos XG(S) Firewall

#Willkommensgruß
Write-Host "`nWillkommen beim automatisierten OTP Migrationsskript UTM -> XG !`n`n" -ForegroundColor Yellow

#Abfrage Variablen
$utm_webadmin = Read-Host "Wie lautet die Adresse des WebAdmin der UTM? Bitte in folgendem Format angeben, z.B. 172.16.16.16:4444"
$utm_api_key = Read-Host "Bitte den API Key eingeben"
$XG_webadmin = Read-Host "Wie lautet die Adresse des WebAdmin der XG? Bitte in folgendem Format angeben, z.B. 172.16.16.16:4444"
$XG_api_user = Read-Host "Bitte den API Benutzer eingeben"
$XG_api_password = Read-Host "Bitte das API Benutzerpasswort eingeben" -AsSecureString

#Codierung XG Credentials
$XG_api_password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($XG_api_password))

#URI's bauen
$random = Get-Random -Maximum 999999999999 -Minimum 100000000000
$uri_utm_api_otp = "https://" + $utm_webadmin + "/api/objects/authentication/otp_token/"
$uri_utm_api_user = "https://" + $utm_webadmin + "/api/objects/aaa/user/"
$uri_xg_api_otp_enable = "https://" + $xg_webadmin +"/webconsole/APIController?reqxml=<Request><Login><Username>" + $xg_api_user + "</Username><Password>" + $xg_api_password + "</Password></Login><Set operation=`"Update`"><OTPSettings><otp>1</otp><otpUserPortal>1</otpUserPortal><otpSSLVPN>1</otpSSLVPN><otpIPsec>1</otpIPsec></OTPSettings></Set></Request>"


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

#API Call Get OTP Token UTM
Write-Host "Export wird durchgeführt..." -ForegroundColor yellow
$response = Invoke-RestMethod -Uri $uri_utm_api_otp -Method GET -Headers $headers
$hashtable = @{}

for ($i = 0; $i -lt $response.name.count; $i++){
    $uri_utm_api_user_ref = $uri_utm_api_user + $response.user[$i]
    $response2 = Invoke-RestMethod -Uri $uri_utm_api_user_ref -Method GET -Headers $headers
    $hashtable.Add($response.name[$i], $response2.name)
}

if ($hashtable.Count -ne 0){
    $hashtable = $hashtable.GetEnumerator() | Sort-Object -Property @{e={$_.name}}
    $hashtable | ForEach-Object{
        Write-Host "`nToken" -ForegroundColor Yellow 
        Write-Host $_.Key
        Write-Host "`nUser" -ForegroundColor Yellow
        Write-Host $_.Value
        Write-Host "`n----------------------------------------------------" -ForegroundColor Yellow
    }
    Write-Host "`n`n...done!`n`n" -ForegroundColor Green
}

#API Call Add OTP Token XG
Write-Host "Import auf XG wird durchgeführt..." -ForegroundColor yellow
$response = Invoke-RestMethod -Uri $uri_xg_api_otp_enable -Method GET
Write-Host "OTP wird aktiviert...`n"  -ForegroundColor Yellow
Write-Host "`nStatuscode: " $response.response.OTPSettings.Status.code "`n" $response.response.OTPSettings.Status.'#text'-ForegroundColor Yellow
Write-Host "`n----------------------------------------------------" -ForegroundColor Yellow

if ($hashtable.Count -ne 0){
$hashtable | ForEach-Object {
    $random = Get-Random -Maximum 999999999999 -Minimum 100000000000
    $uri_xg_api_otp_add_token = "https://" + $xg_webadmin +"/webconsole/APIController?reqxml=<Request><Login><Username>" + $xg_api_user + "</Username><Password>" + $xg_api_password + "</Password></Login><Set operation=`"Add`"><OTPTokens><secret>" + $_.Key + "</secret><user>" + $_.Value + " </user><autoCreated>1</autoCreated><active>1</active><tokenid>" + $random + "</tokenid></OTPTokens></Set></Request>"
    $response = Invoke-RestMethod -Uri $uri_xg_api_otp_add_token -Method GET
    #    Write-Host "Debug:" $uri_xg_api_otp_add_token
    Write-Host "Response zum API Request`nToken"  -ForegroundColor Yellow 
    Write-Host $_.Key
    Write-Host "`nUser" -ForegroundColor Yellow
    Write-Host $_.Value
    Write-Host "`nStatuscode: " $response.response.OTPTokens.Status.code "`n" $response.response.OTPTokens.Status.'#text'-ForegroundColor Yellow
    Write-Host "`n----------------------------------------------------" -ForegroundColor Yellow
}
Write-Host "`n`n...done!" -ForegroundColor Green
}