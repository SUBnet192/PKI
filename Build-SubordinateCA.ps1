<#
.SYNOPSIS
  Build Subordinate CA in a two-tier PKI infrastructure

.DESCRIPTION
  Automate the installation and configuration of a Subordinate Certificate Authority using
  the Microsoft PKI Services. This is designed to be executed on a Server Core instance.

.INPUTS
  None

.OUTPUTS
  None

.NOTES
  Version:        1.0.1
  Author:         Marc Bouchard
  Creation Date:  2021/01/30
  Purpose/Change: Initial script development
  
.EXAMPLE
  Install from Github using:
  Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/PKI/master/Build-SubordinateCA.ps1" | Invoke-Expression
#>

#-------------------------------------------------------[ INIT ]----------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "Stop"

Clear-Host
Write-Host "Build-SubordinateCA.ps1 - v1.0" -Foreground Green
Write-Host "[INIT] Configure WinRM" -ForegroundColor Cyan
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force  | Out-Null

Write-Host "[INIT] Adding required Windows Features" -ForegroundColor Cyan
Add-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Mgmt-Service -IncludeManagementTools | Out-Null

#----------------------------------------------------[ Declarations ]-----------------------------------------------------

# Change this to a local repository if you prefer
$CAPolicyLocation = "https://raw.githubusercontent.com/SUBnet192/PKI/master/capolicy.inf.subordinate"

#----------------------------------------------------[ Execution ]-----------------------------------------------------

Write-Host "[EXEC] Retrieving CAPolicy.inf" -ForegroundColor Green
Invoke-WebRequest -usebasicparsing -Uri $CAPolicyLocation -Outfile "C:\Windows\CAPolicy.inf"

do {
    Write-Host "[EXEC] Opening CAPolicy.inf with Notepad" -ForegroundColor Green
    Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
    Write-Host "`n"
    Get-Content C:\Windows\CAPolicy.inf
    Write-Host "`n"
    Write-Host '[PROMPT] Are you satisfied with the contents of CAPolicy.inf? [y/n] ' -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "[EXEC] Install and configure AD Certificate Services" -ForegroundColor Green
do {
    Write-Host '[PROMPT] Enter the Common Name for the Subordinate CA (ex: Corp-Subordinate-CA): ' -NoNewline -ForegroundColor Yellow
    $SubordinateCAName = Read-Host
    Write-Host "[PROMPT] Are you satisfied with the CA Name '$SubordinateCAName'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null
Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName $SubordinateCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force | Out-Null
Install-AdcsWebEnrollment -Force | Out-Null

# Get Root CA server name
do {
    Write-Host '[PROMPT] Enter the Name for the Root CA server: ' -NoNewline -ForegroundColor Yellow
    $OfflineRootCAServer = Read-Host
    Write-Host "[PROMPT] Are you satisfied with this server name: '$OfflineRootCAServer'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$OfflineRootCACreds = Get-Credential -Message "Please provide Root CA credentials."

Write-Host "[EXEC] Mapping X: to share on Root CA" -ForegroundColor Green
New-PSDrive -Name "X" -Root "\\$OfflineRootCAServer\CertConfig" -PSProvider "FileSystem" -Credential $OfflineRootCACreds | Out-Null

# Copy request from Subordinate CA to Root CA
Write-Host "[EXEC] Copy Certificate Request to X:" -ForegroundColor Green
Copy-Item C:\*.REQ -Destination X:\ | Out-Null

Write-Host "[EXEC] Triggering remote execution of certificate request" -ForegroundColor Green

Invoke-Command $OfflineRootCAServer -credential $OfflineRootCACreds -scriptblock {
    # Initialize variables
    Write-Host "[REMOTE] Initialize variables" -ForegroundColor Magenta
    $OfflineRootCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
    $OfflineRootCAServer = hostname
    $SubordinateCAReq = Get-ChildItem "C:\CAConfig\*.req"
    
    # Submit CSR from Subordinate CA to the Root CA
    Write-Host "[DEBUG] ORCAServer:$OfflineRootCAServer" -ForegroundColor Yellow
    Write-Host "[DEBUG] ORCAName:$OfflineRootCAName" -ForegroundColor Yellow
    Write-Host "[DEBUG] SubordinateCAReq:$SubordinateCAReq" -ForegroundColor Yellow
    Write-Host "[REMOTE] Submitting Subordinate certificate request to Root CA" -ForegroundColor Magenta
    certreq -config $OfflineRootCAServer\$OfflineRootCAName -submit -attrib "CertificateTemplate:SubCA" $SubordinateCAReq.Fullname | Out-Null
    
    # Authorize Certificate Request
    Write-Host "[REMOTE] Issuing Subordinate certificate" -ForegroundColor Magenta
    certutil -resubmit 2 | Out-Null
    
    # Retrieve Subordinate CA certificate
    Write-Host "[REMOTE] Retrieving/Exporting Subordinate certificate" -ForegroundColor Magenta
    certreq -config $OfflineRootCAServer\$OfflineRootCAName -retrieve 2 "C:\CAConfig\SubordinateCA.crt"
    
    # Rename Root CA certificate (remove server name)
    Write-Host "[REMOTE] Correcting certificate filename and cleanup" -ForegroundColor Magenta
    $Source = "C:\CAConfig\$OfflineRootCAServer" + "_" + "$OfflineRootCAName.crt"
    $Target = "$OfflineRootCAName.crt"
    Rename-Item $Source $Target  | Out-Null
    Remove-Item C:\CAConfig\*.REQ | Out-Null
}

# Copy certificate/CRL from Root CA to Subordinate CA
Write-Host "[EXEC] Copy certificates and CRL from Root CA to Subordinate CA" -ForegroundColor Green
Copy-Item X:\*.CRT -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null
Copy-Item X:\*.CRL -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null

$RootCACert = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crt" -exclude "SubordinateCA.crt"
$RootCACRL = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crl"

# Publish Root CA certificate to AD
Write-Host "[EXEC] Publish Root CA certificate to AD" -ForegroundColor Green
certutil.exe -dsPublish -f $RootCACert.FullName RootCA  | Out-Null

# Publish Root CA certificates to Subordinate server
Write-Host "[EXEC] Add Root CA certificate to Subordinate CA server" -ForegroundColor Green
certutil.exe -addstore -f root $RootCACert.FullName  | Out-Null
certutil.exe -addstore -f root $RootCACRL.FullName | Out-Null

Write-Host "[EXEC] Install Subordinate CA certificate to server" -ForegroundColor Green
certutil.exe -installcert C:\Windows\System32\CertSrv\CertEnroll\SubordinateCA.crt | Out-Null

Write-Host "[EXEC] Customizing AD Certificate Services" -ForegroundColor Green

do {
    Write-Host '[PROMPT] Enter the URL where the CRL files will be located (ex: pki.mycompany.com): ' -NoNewline -ForegroundColor Yellow
    $URL = Read-Host
    Write-Host "[PROMPT] Are you satisfied with the URL '$URL'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "[EXEC] Setting up CRL distribution points" -ForegroundColor Green
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { 
    Remove-CACrlDistributionPoint $crl.uri -Force  | Out-Null
}

Add-CACRLDistributionPoint -Uri "C:\Windows\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force  | Out-Null
Add-CACRLDistributionPoint -Uri "http://$URL/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force  | Out-Null

Get-CAAuthorityInformationAccess | where { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force  | Out-Null
Add-CAAuthorityInformationAccess -Uri "http://$URL/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force  | Out-Null

Write-Host "[EXEC] Setting default values for issued certificates" -ForegroundColor Green
certutil.exe -setreg CA\CRLPeriodUnits 2  | Out-Null
certutil.exe -setreg CA\CRLPeriod "Weeks"  | Out-Null
certutil.exe -setreg CA\CRLDeltaPeriodUnits 1  | Out-Null
certutil.exe -setreg CA\CRLDeltaPeriod "Days"  | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriodUnits 12  | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriod "Hours"  | Out-Null
certutil.exe -setreg CA\ValidityPeriodUnits 1 | Out-Null
certutil.exe -setreg CA\ValidityPeriod "Years"  | Out-Null
certutil.exe -setreg CA\AuditFilter 127  | Out-Null
Write-Host "[EXEC] Restarting AD Certificate Services" -ForegroundColor Green
Restart-Service certsvc | Out-Null
Start-Sleep 5
Write-Host "[EXEC] Publishing CRL" -ForegroundColor Green
certutil -crl | Out-Null

# Rename Subordinate CA certificate (remove server name)
Write-Host "[EXEC] Correcting certificate filename and cleanup" -ForegroundColor Green
$OfflineRootCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
$FQDN = "$env:computername.$env:userdnsdomain"
$Source = "C:\Windows\System32\CertSrv\CertEnroll\$FQDN" + "_" + "$OfflineRootCAName.crt"
$Target = "$OfflineRootCAName.crt"
Rename-Item $Source $Target | Out-Null
Remove-Item C:\*.REQ | Out-Null

# Get the service
$webManagementService = Get-Service WMSVC -ErrorAction Stop | Out-Null
 
# Stop the WMSVC, if running
if ($webManagementService.Status -eq "Running") {
    Stop-Service WMSVC | Out-Null
}
 
# Modify the EnableRemoteManagement property in the Windows Registry
Write-Host "[EXEC] Setting the IIS EnableRemoteManagement property" -ForegroundColor Yellow
$enableRemoteManagement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement"
if ($enableRemoteManagement.EnableRemoteManagement -eq 0) {
    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement" -Value 1 -ErrorAction Stop  | Out-Null
}
 
# Ensure automatic start of the WMSVC service
Write-Host "[EXEC] Starting the WMSVC service and enabling automatic startup" -ForegroundColor Yellow
Start-Service WMSVC | Out-Null
Set-Service WMSVC -StartupType Automatic | Out-Null
