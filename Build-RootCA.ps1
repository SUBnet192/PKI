<#
.SYNOPSIS
  Build Root CA in a two-tier PKI infrastructure
.DESCRIPTION
  Automate the installation and configuration of a Root Certificate Authority using
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
  Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/PKI/master/Build-RootCA.ps1" | Invoke-Expression
#>

#------------------------------------------------------[ Initialization ]---------------------------------------------------------

$response = $null
$RootCAName = $null
$httpCRLPath = $null
$OID = $null

#--------------------------------------------------------[ Declaration ]----------------------------------------------------------

Function Show-Disclaimer {
  Clear-Host
  Write-Host "8888888b.                   888          .d8888b.        d8888 " -ForegroundColor Yellow
  Write-Host "888   Y88b                  888         d88P  Y88b      d88888 " -ForegroundColor Yellow
  Write-Host "888    888                  888         888    888     d88P888 " -ForegroundColor Yellow
  Write-Host "888   d88P .d88b.   .d88b.  888888      888           d88P 888 " -ForegroundColor Yellow
  Write-Host "8888888P' d88''88b d88''88b 888         888          d88P  888 " -ForegroundColor Yellow
  Write-Host "888 T88b  888  888 888  888 888         888    888  d88P   888 " -ForegroundColor Yellow
  Write-Host "888  T88b Y88..88P Y88..88P Y88b.       Y88b  d88P d8888888888 " -ForegroundColor Yellow
  Write-Host "888   T88b 'Y88P'   'Y88P'   'Y888       'Y8888P' d88P     888 " -ForegroundColor Yellow
  Write-Host ""
  Write-Host "IMPORTANT INFORMATION - PLEASE READ" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "This script is used to build a Root Certificate server in a 2-tier Microsoft PKI solution" -ForegroundColor Yellow
  Write-Host "Please REVIEW the contents of this script to ensure the default values provided meet your requirements." -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Tips:" -ForegroundColor Yellow
  Write-Host " - If running on a virtual machine, take a snapshot before starting, and another one at completion." -ForegroundColor Yellow
  Write-Host "   This allows you to either restart fresh or recover/revert if anything fails with the subordinate CA." -ForegroundColor Yellow
  Write-Host " - Once the subordinate CA is built and active, disconnect the network and shutdown the Root CA until needed again." -ForegroundColor Yellow
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
Report-Status "Building Root CA" 0 Green

Report-Status "Enable PS Remoting" 0 Green
Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null

Report-Status "Configuring Auditing" 0 Green
auditpol /set /category:"Object Access" /failure:enable /success:enable | Out-Null

#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=[ User Input ]=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

$response = $null
[regex] $OIDRegex = "^\d{5}$"
do {
  # Query user for Root CA Common Name
  Report-Status "Enter the Common Name for the Root CA (ex: Corp-Root-CA):" 1 Yellow
  $RootCAName = Read-Host

  do {
    Report-Status "Please enter your 5 digit OID number:" 1 Yellow
    $OID = read-host
  } while ($OID -inotmatch $OIDRegex)

  Report-Status "Enter the URL where the CRL files will be located (ex: pki.mycompany.com): " 1 Yellow
  $httpCRLPath = Read-Host

  Report-Status "You have provided the following information:" 1 Yellow
  Write-Host "CA Common Name: $RootCAName"
  Write-Host "OID           : $OID"
  Write-Host "CRL URL path  : $httpCRLPath"

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
RenewalValidityPeriodUnits=10
CRLPeriod=Years
CRLPeriodUnits=10
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=1
"@

$CAPolicyInf | Out-File "C:\Windows\CAPolicy.inf" -Encoding utf8 -Force | Out-Null
Get-Content C:\Windows\CAPolicy.inf
Report-Status "Would you like to edit CAPolicy.Inf? [y/n]" 1 Yellow
$response = Read-Host
If ($response -eq "y") { Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf" }
$response = $null

Report-Status "Installing required Windows Features" 0 Green
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools | Out-Null

Report-Status "Install and configure AD Certificate Services" 0 Green

# Configure Root CA
# Certificate Validity: 10 years
# Key Length: 4096
# Hash: SHA256

Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $RootCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -ValidityPeriod Years -ValidityPeriodUnits 10 -Force | Out-Null

Report-Status "Customizing AD Certificate Services" 0 Green
Get-CACrlDistributionPoint | Remove-CACrlDistributionPoint -Force | Out-Null

Add-CACRLDistributionPoint -Uri "$env:windir\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force | Out-Null
Add-CACRLDistributionPoint -Uri "C:\CAConfig\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force | Out-Null
Add-CACRLDistributionPoint -Uri "http://$httpCRLPath/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force | Out-Null

Get-CAAuthorityInformationAccess | where { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force | Out-Null
Add-CAAuthorityInformationAccess -Uri "http://$httpCRLPath/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force  | Out-Null

# Set Validity period and other settings of certificates generated by this CA
certutil.exe -setreg CA\CRLPeriodUnits 10 | Out-Null
certutil.exe -setreg CA\CRLPeriod "Years" | Out-Null
certutil.exe -setreg CA\ValidityPeriodUnits 5 | Out-Null
certutil.exe -setreg CA\ValidityPeriod "Years" | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriodUnits 3 | Out-Null
certutil.exe -setreg CA\CRLOverlapPeriod "Weeks" | Out-Null
certutil.exe -setreg CA\AuditFilter 127 | Out-Null
Report-Status "Restarting AD Certificate Services" 0 Green
Restart-Service certsvc | Out-Null
Start-Sleep 5
Report-Status "Publishing CRL" 0 Green
certutil -crl | Out-Null
Report-Status "Root CA Build Completed!" 0 Green
Report-Status "NOTE: Take a snapshot at this point before proceeding with the Subordinate CA installation." 0 Green
