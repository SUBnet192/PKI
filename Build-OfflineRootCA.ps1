<#
.SYNOPSIS
  Build Offline Root CA in a two-tier PKI infrastructure
.DESCRIPTION
  Automate the installation and configuration of a Root Certificate Authority using
  the Microsoft PKI Services. This is designed to be executed on a Server Core instance.
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Marc Bouchard
  Creation Date:  2021/01/30
  Purpose/Change: Initial script development
  
.EXAMPLE
  Install from Github using:
  Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/PKI/master/Build-OfflineRootCA.ps1" | Invoke-Expression
#>

#------------------------------------------------------[ Initialization ]---------------------------------------------------------

$response = $null
$OfflineCAName = $null
$httpCRLPath = $null
$OID = $null

#--------------------------------------------------------[ Declaration ]----------------------------------------------------------

Function Show-Disclaimer {
    Clear-Host
    Write-Host "IMPORTANT INFORMATION - PLEASE READ" -ForegroundColor Yellow
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host "This script is used to build an Offline Root Certificate server in a 2-tier Microsoft PKI solution" -ForegroundColor Yellow
    Write-Host "Please REVIEW the contents of this script to ensure the default values provided meet your requirements." -ForegroundColor Yellow
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host "Tips:" -ForegroundColor Yellow
    Write-Host " - If running on a virtual machine, take a snapshot before starting, and another one at completion." -ForegroundColor Yellow
    Write-Host "   This allows you to either restart fresh or recover/revert if anything fails with the subordinate CA." -ForegroundColor Yellow
    Write-Host " - Once the subordinate CA is built and active, disconnect the network and shutdown the Root CA until needed again." -ForegroundColor Yellow
    Write-Host "`n" -ForegroundColor Yellow
    Write-Host -NoNewLine "Press any key to continue..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

Function Report-Status {
    Param(
        [parameter(Mandatory=$true)][String]$Msg,
        [parameter(Mandatory=$true)][INT]$Lvl,
        [parameter(Mandatory=$true)][String]$Color
        )
        Switch ($Lvl)
        {
            0 { Write-Host -Foreground $Color "[EXEC] "$Msg }
            1 { Write-Host -Foreground $Color "[USER INPUT] " $Msg }
            2 { Write-Host -Foreground $Color "[...] " $Msg }
        }
    }

#---------------------------------------------------------[ Execution ]----------------------------------------------------------

Clear-Host
Show-Disclaimer
Report-Status "Building Offline Root CA" 0 Green

Report-Status "Enable PS Remoting" 0 Green
Enable-PSRemoting -SkipNetworkProfileCheck -Force

# Query user for OID number
[regex] $ssn4 = "^\d{4}$"
do
{
	$OID = read-host "Please enter your 5 digit OID number: "
} while ($OID -inotmatch $ssn4)

do {
    Report-Status "Enter the URL where the CRL files will be located (ex: pki.mycompany.com): " 1 Yellow
    $httpCRLPath = Read-Host
    Report-Status "Are you satisfied with the URL '$httpCRLPath'? [y/n]" 1 Yellow
    $response = Read-Host
} until ($response -eq 'y')
$response = $null

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

$CAPolicyInf | Out-File "C:\Windows\CAPolicy.inf" -Encoding utf8 -Force

Report-Status "Building Offline Root CA" 0 Green

do {
    Write-Host "... Editing CAPolicy.inf" -ForegroundColor Green
    Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
    write-host "`n"
    Get-Content C:\Windows\CAPolicy.inf
    write-host "`n"
    Write-Host 'Are you satisfied with the contents of CAPolicy.inf? [y/n] ' -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "... Install Windows Feature: AD Certificate Services" -ForegroundColor Green
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools

Write-Host "... Install and configure AD Certificate Services" -ForegroundColor Green
do {
    Write-Host 'Enter the Common Name for the Offline root CA (ex: Corp-Root-CA): ' -NoNewline -ForegroundColor Yellow
    $OfflineCAName = Read-Host
    Write-Host "Are you satisfied with the CA Name '$OfflineCAName'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

# Configure Offline Root CA
# Certificate Validity: 10 years
# Key Length: 4096
# Hash: SHA256

Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $OfflineCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -ValidityPeriod Years -ValidityPeriodUnits 10 -Force

Write-Host "... Customizing AD Certificate Services" -ForegroundColor Green

$crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force};

Add-CACRLDistributionPoint -Uri "$env:windir\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri "C:\CAConfig\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri "http://$httpCRLPath/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

Get-CAAuthorityInformationAccess | where {$_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*'} | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -Uri "http://$httpCRLPath/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force 

# Set Validity period and other settings of certificates generated by this CA
certutil.exe -setreg CA\ValidityPeriodUnits 5
certutil.exe -setreg CA\ValidityPeriod "Years"
certutil.exe -setreg CA\CRLOverlapPeriodUnits 3
certutil.exe -setreg CA\CRLOverlapPeriod "Weeks"
certutil.exe -setreg CA\AuditFilter 127
Write-Host "... Restarting AD Certificate Services" -ForegroundColor Green
Restart-Service certsvc
Start-Sleep 5
Write-Host "... Publishing CRL" -ForegroundColor Green
certutil -crl
