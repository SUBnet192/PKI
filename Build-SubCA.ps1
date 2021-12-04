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
  Version:        1.5
  Author:         Marc Bouchard
  Creation Date:  2021/03/04
.EXAMPLE
  Install from Github using:
  Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/PKI/master/Build-SubCA.ps1" | Invoke-Expression
#>

#------------------------------------------------------[ Initialization ]---------------------------------------------------------

$response = $null
$httpCRLPath = $null
$OID = $null
$SubordinateCAName = $null

#--------------------------------------------------------[ Declaration ]----------------------------------------------------------

Function Show-Disclaimer {
  Clear-Host
  Write-Host " .d8888b.           888            .d8888b.        d8888 " -ForegroundColor Yellow 
  Write-Host "d88P  Y88b          888           d88P  Y88b      d88888 " -ForegroundColor Yellow
  Write-Host "Y88b.               888           888    888     d88P888 " -ForegroundColor Yellow
  Write-Host " 'Y888b.   888  888 88888b.       888           d88P 888 " -ForegroundColor Yellow
  Write-Host "    'Y88b. 888  888 888 '88b      888          d88P  888 " -ForegroundColor Yellow
  Write-Host "      '888 888  888 888  888      888    888  d88P   888 " -ForegroundColor Yellow
  Write-Host "Y88b  d88P Y88b 888 888 d88P      Y88b  d88P d8888888888 " -ForegroundColor Yellow
  Write-Host " 'Y8888P'   'Y88888 88888P'        'Y8888P' d88P     888 " -ForegroundColor Yellow
  Write-Host ""
  Write-Host "IMPORTANT INFORMATION - PLEASE READ" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "This script is used to build an Enterprise Subordinate Certificate server in a 2-tier Microsoft PKI solution" -ForegroundColor Yellow
  Write-Host "Please REVIEW the contents of this script to ensure the default values provided meet your requirements." -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Tips:" -ForegroundColor Yellow
  Write-Host " - If running on a virtual machine, take a snapshot before starting, and another one at completion." -ForegroundColor Yellow
  Write-Host "   This allows you to either restart fresh or recover/revert if anything fails with the subordinate CA." -ForegroundColor Yellow
  Write-Host ""
  Write-Host -NoNewLine "Press any key to continue..." -ForegroundColor Yellow
  $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

Function Report-Status {
  Param(
    [parameter(Mandatory = $true)][String]$Msg,
    [parameter(Mandatory = $true)][INT]$Lvl,
    [parameter(Mandatory = $true)][String]$Color
  )
  Switch ($Lvl) {
    0 { Write-Host -Foreground $Color "[EXEC]" $Msg }
    1 { Write-Host -Foreground $Color "[QUERY]" $Msg }
  }
}

#---------------------------------------------------------[ Execution ]----------------------------------------------------------

Show-Disclaimer

Clear-Host
Report-Status "Building Subordinate CA" 0 Green

Report-Status "Configure WinRM" 0 Green
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force  | Out-Null

Report-Status "Configuring Auditing" 0 Green
auditpol /set /category:"Object Access" /failure:enable /success:enable | Out-Null


#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[ User Input ]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

$response = $null
[regex] $OIDRegex = "^\d{5}$"
do {
  # Query user for Subordinate CA Common Name
  Report-Status "Enter the Common Name for the Subordinate CA (ex: Corp-Sub-CA):" 1 Yellow
  $SubordinateCAName = Read-Host

  do {
    Report-Status "Please enter your 5 digit OID number:" 1 Yellow
    $OID = read-host
  } while ($OID -inotmatch $OIDRegex)

  Report-Status "Enter the URL where the CRL files will be located (ex: pki.mycompany.com): " 1 Yellow
  $httpCRLPath = Read-Host

  Report-Status "Enter the Name of the Root CA server" 1 Yellow
  $RootCAServer = Read-Host

  $RootCACreds = Get-Credential -Message "Credentials for the Root CA Server."

  Report-Status "You have provided the following information:" 1 Yellow
  Write-Host "CA Common Name: $SubordinateCAName"
  Write-Host "OID           : $OID"
  Write-Host "CRL URL path  : $httpCRLPath"
  Write-Host "Root CA Server: $RootCAServer"

  Report-Status "Are you satisfied with these answers? [y/n]" 1 Yellow
  $response = Read-Host
} until ($response -eq 'y')

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[ End User Input ]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Report-Status "Create CAPolicy file" 0 Green

#--------------------------
# CAPolicy.INF file content
#--------------------------

$CAPolicyInf = @"
[Version]
Signature="`$Windows NT$"
[PolicyStatementExtension]
Policies=InternalPolicy
[InternalPolicy]
OID= 1.3.6.1.4.1.$OID
Notice="Legal Policy Statement"
URL=http://$httpCRLPath/pki/cps.html
[Certsrv_Server]
RenewalKeyLength=4096
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=5
LoadDefaultTemplates=1
AlternateSignatureAlgorithm=1
"@

$CAPolicyInf | Out-File "C:\Windows\CAPolicy.inf" -Encoding utf8 -Force | Out-Null
Get-Content C:\Windows\CAPolicy.inf
Report-Status "Would you like to edit CAPolicy.Inf? [y/n]" 1 Yellow
$response = Read-Host
If ($response -eq "y") { Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf" }
$response = $null

Report-Status "Installing required Windows Features" 0 Green
Add-WindowsFeature -Name ADCS-Cert-Authority, ADCS-Web-Enrollment, Web-Mgmt-Service -IncludeManagementTools | Out-Null

Report-Status "Install and configure AD Certificate Services" 0 Green
Install-AdcsCertificationAuthority -CAType EnterpriseSubordinateCA -CACommonName $SubordinateCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force | Out-Null
Install-AdcsWebEnrollment -Force | Out-Null

Report-Status "Mapping X: to CertConfig share on Root CA" 0 Green
New-PSDrive -Name "X" -Root "\\$RootCAServer\CertConfig" -PSProvider "FileSystem" -Credential $RootCACreds | Out-Null

# Copy request from Subordinate CA to Root CA
Report-Status "Copy Certificate Request to X:" 0 Green
Copy-Item C:\*.REQ -Destination X:\ | Out-Null

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[ Remote Execution ]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Report-Status "Triggering remote execution of certificate request" 0 Green
Invoke-Command $RootCAServer -credential $RootCACreds -scriptblock {
  # Initialize variables
  Write-Host "[REMOTE] Initialize variables" -ForegroundColor Magenta
  $RootCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
  $RootCAServer = hostname
  $SubordinateCAReq = Get-ChildItem "C:\CAConfig\*.req"
    
  # Submit CSR from Subordinate CA to the Root CA
  Write-Host "[DEBUG] ORCAServer:$RootCAServer" -ForegroundColor Yellow
  Write-Host "[DEBUG] ORCAName:$RootCAName" -ForegroundColor Yellow
  Write-Host "[DEBUG] SubordinateCAReq:$SubordinateCAReq" -ForegroundColor Yellow
  Write-Host "[REMOTE] Submitting Subordinate certificate request to Root CA" -ForegroundColor Magenta
  certreq -config $RootCAServer\$RootCAName -submit -attrib "CertificateTemplate:SubCA" $SubordinateCAReq.Fullname | Out-Null

  # Authorize Certificate Request
  Write-Host "[REMOTE] Issuing Subordinate certificate" -ForegroundColor Magenta
  certutil -resubmit 2 | Out-Null

  # Retrieve Subordinate CA certificate
  Write-Host "[REMOTE] Retrieving/Exporting Subordinate certificate" -ForegroundColor Magenta
  certreq -config $RootCAServer\$RootCAName -retrieve 2 "C:\CAConfig\SubordinateCA.crt" | Out-Null

  # Rename Root CA certificate (remove server name)
  Write-Host "[REMOTE] Correcting certificate filename and cleanup" -ForegroundColor Magenta
  $Source = "C:\CAConfig\$RootCAServer" + "_" + "$RootCAName.crt"
  $Target = "$RootCAName.crt"
  Rename-Item $Source $Target  | Out-Null
  Remove-Item C:\CAConfig\*.REQ | Out-Null
}

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[ End Remote Execution ]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

# Copy certificate/CRL from Root CA to Subordinate CA
Report-Status "Copy certificates and CRL from Root CA to Subordinate CA" 0 Green

Copy-Item X:\*.CRT -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null
Copy-Item X:\*.CRL -Destination C:\Windows\system32\CertSrv\CertEnroll | Out-Null

$RootCACert = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crt" -exclude "SubordinateCA.crt"
$RootCACRL = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crl"

# Publish Root CA certificate to AD
Report-Status "Publish Root CA certificate to AD" 0 Green
certutil.exe -dsPublish -f $RootCACert.FullName RootCA  | Out-Null

# Publish Root CA certificates to Subordinate server
Report-Status "Add Root CA certificate to Subordinate CA server" 0 Green
certutil.exe -addstore -f root $RootCACert.FullName  | Out-Null
certutil.exe -addstore -f root $RootCACRL.FullName | Out-Null

Report-Status "Install Subordinate CA certificate to server" 0 Green
certutil.exe -installcert C:\Windows\System32\CertSrv\CertEnroll\SubordinateCA.crt | Out-Null

Report-Status "Customizing AD Certificate Services" 0 Green
Report-Status "Setting up CRL distribution points" 0 Green
$crllist = Get-CACrlDistributionPoint
foreach ($crl in $crllist) { 
  Remove-CACrlDistributionPoint $crl.uri -Force  | Out-Null
}

Add-CACRLDistributionPoint -Uri "C:\Windows\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force  | Out-Null
Add-CACRLDistributionPoint -Uri "http://$httpCRLPath/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force  | Out-Null

Get-CAAuthorityInformationAccess | where { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force  | Out-Null
Add-CAAuthorityInformationAccess -Uri "http://$httpCRLPath/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force  | Out-Null

Report-Status "Setting default values for issued certificates" 0 Green
certutil.exe -setreg CA\CRLPeriodUnits 2  | Out-Null
certutil.exe -setreg CA\CRLPeriod "Weeks"  | Out-Null
certutil.exe -setreg CA\CRLDeltaPeriodUnits 1  | Out-Null
certutil.exe -setreg CA\CRLDeltaPeriod "Days"  | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriodUnits 12  | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriod "Hours"  | Out-Null
certutil.exe -setreg CA\ValidityPeriodUnits 1 | Out-Null
certutil.exe -setreg CA\ValidityPeriod "Years"  | Out-Null
certutil.exe -setreg CA\AuditFilter 127  | Out-Null

Report-Status "Restarting AD Certificate Services" 0 Green
Restart-Service certsvc | Out-Null
Start-Sleep 5

Report-Status "Publishing CRL" 0 Green
certutil -crl | Out-Null

# Rename Subordinate CA certificate (remove server name)
Report-Status "Correcting certificate filename and cleanup" 0 Green
$RootCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
$FQDN = "$env:computername.$env:userdnsdomain"
$Source = "C:\Windows\System32\CertSrv\CertEnroll\$FQDN" + "_" + "$RootCAName.crt"
$Target = "$RootCAName.crt"
Rename-Item $Source $Target | Out-Null
Remove-Item C:\*.REQ | Out-Null

# Get the service
$webManagementService = Get-Service WMSVC -ErrorAction Stop | Out-Null
 
# Stop the WMSVC, if running
if ($webManagementService.Status -eq "Running") {
  Stop-Service WMSVC | Out-Null
}
# Enable double escaping as per BPA
c:\windows\system32\inetsrv\appcmd set config /section:requestfiltering /allowdoubleescaping:true

# Modify the EnableRemoteManagement property in the Windows Registry
Report-Status "Setting the IIS EnableRemoteManagement property" 0 Green
$enableRemoteManagement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement"
if ($enableRemoteManagement.EnableRemoteManagement -eq 0) {
  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name "EnableRemoteManagement" -Value 1 -ErrorAction Stop  | Out-Null
}
 
# Ensure automatic start of the WMSVC service
Report-Status "Starting the WMSVC service and enabling automatic startup" 0 Green
Start-Service WMSVC | Out-Null
Set-Service WMSVC -StartupType Automatic | Out-Null

# Final message
Report-Status "Subordinate CA Build Completed!" 0 Green
Report-Status "NOTE: Don't forget to remove any snapshots you created during this installation." 0 Green
