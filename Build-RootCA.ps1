<#
.SYNOPSIS
  Build Root CA in a two-tier PKI infrastructure
  
.DESCRIPTION
  Automate the installation and configuration of a Root Certificate Authority using
  the Microsoft PKI Services. This is designed to be executed on a Server Core instance.
  
  IMPORTANT OPERATIONAL NOTES:
  - This Root CA server must remain ONLINE and accessible during SubCA installation
  - PSRemoting is required to allow the SubCA server to remotely connect and retrieve certificates
  - The SubCA script (Build-SubCA.ps1) will connect to this Root CA via:
    * PSRemoting (Invoke-Command) to submit and process certificate requests
    * File share (\\RootCA\CertConfig) to transfer certificate files
  - After SubCA installation completes, the Root CA should be taken offline for security
  - The Root CA should only be brought online when:
    * Installing/issuing SubCA certificates
    * Renewing Root CA certificate
    * Revoking SubCA certificates
    * Publishing updated CRLs
  
.INPUTS
  None
  
.OUTPUTS
  None
  
.NOTES
  Version:        3.0
  Author:         Marc Bouchard
  Creation Date:  2021/03/04
  Last Modified:  2024/12/19
  
  Compatibility:
  - Windows Server 2012, 2012 R2, 2016, 2019, 2022, 2025
  - PowerShell 5.1 or later (Windows PowerShell 5.1 included by default)
  - All commands verified for Windows Server 2025 compatibility
  
  New Features (v3.0):
  - File-based logging for audit trails
  - Post-installation CA configuration validation
  - Automated CertConfig share creation
  - Progress indicators for long operations
  - HSM support (Hardware Security Module)
  - Configuration export/import
  - WhatIf support for safe testing
  - Verbose/Debug output support
  
  Security Enhancements:
  - SHA-384 hash algorithm (upgraded from SHA-256)
  - Configurable CRL period (1-2 years for offline CA)
  - Delta CRL enabled
  - Domain-joined validation
  - Network isolation checks
  - Automated backup functionality
  
  Operational Requirements:
  - Server must remain online during SubCA installation
  - PSRemoting must be enabled for SubCA certificate retrieval
  - CertConfig share (C:\CAConfig) must be accessible to SubCA server
  
.EXAMPLE
  Install from Github using:
  Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/PKI/master/Build-RootCA.ps1" | Invoke-Expression
  
.EXAMPLE
  Basic usage (PSRemoting enabled by default):
  .\Build-RootCA.ps1
  
.EXAMPLE
  Run with automatic backup:
  .\Build-RootCA.ps1 -CreateBackup
  
.EXAMPLE
  Run with custom backup path:
  .\Build-RootCA.ps1 -CreateBackup -BackupPath "D:\CA-Backup"
  
.EXAMPLE
  Disable PSRemoting (not recommended - required for SubCA installation):
  .\Build-RootCA.ps1 -EnablePSRemoting:$false
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Windows Server 2025 Compatibility Notes:
# - PowerShell 5.1 is included by default (PowerShell 7.x available separately)
# - Get-WindowsFeature/Install-WindowsFeature still work for ADCS (role/feature, not capability)
# - All ADCS cmdlets (Install-AdcsCertificationAuthority, etc.) are compatible
# - Get-CimInstance is the modern CIM cmdlet (preferred over Get-WmiObject)
# - Command-line tools (auditpol, certutil) remain available

#===========================================================================================================
# PARAMETER DEFINITIONS
#===========================================================================================================
# Minimal parameters for single-use script on Server Core
# All security settings use secure defaults (SHA-384, 4096-bit keys, etc.)
[CmdletBinding(SupportsShouldProcess)]
param(
    # REQUIRED: Enable PSRemoting for SubCA installation
    # The SubCA script requires PSRemoting to connect and retrieve certificates
    # Default: Enabled (required for SubCA installation)
    [Parameter(Mandatory=$false)]
    [switch]$EnablePSRemoting,
    
    # Optional: Create backup automatically after installation
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup,  # Default: Disabled (prompted if not specified)
    
    # Optional: Custom backup path (defaults to SystemDrive\CA-Backup if not specified)
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = $null
)

#===========================================================================================================
# HARDCODED SECURITY CONFIGURATION (Single-use script with secure defaults)
#===========================================================================================================
# These values are hardcoded for consistency and security best practices
# Modify these constants if you need different values (not recommended)
$script:HashAlgorithm = 'SHA384'              # SHA-384 (upgraded from SHA-256 for security)
$script:KeyLength = 4096                      # RSA 4096-bit keys (industry standard)
$script:CAValidityYears = 10                   # Root CA certificate valid for 10 years
$script:CRLPeriodYears = 1                     # CRL published annually (1-2 years for offline CA)
$script:CertificateValidityYears = 1            # Certificates valid for 1 year (1-2 years for offline CA)
$script:CryptoProvider = 'Software'             # Software KSP (use 'HSM' with HSMProviderName for HSM)
$script:HSMProviderName = $null                # HSM provider name (only used if CryptoProvider = 'HSM')
$script:DisableLogging = $false                # Logging enabled by default
$script:LogPath = $null                        # Auto-generated log path

#===========================================================================================================
# SCRIPT INITIALIZATION
#===========================================================================================================
# Initialize error handling and script-level variables
$ErrorActionPreference = 'Stop'  # Stop on all errors for better error handling
$Script:ExitCode = 0
$response = $null
$RootCAName = $null
$httpCRLPath = $null
$OID = $null
$Script:LogPath = $null
$Script:ProgressActivity = "Building Root CA"

# Initialize file-based logging (enabled by default)
if (-not $script:DisableLogging) {
    try {
        if ([string]::IsNullOrWhiteSpace($script:LogPath)) {
            $LogDir = Join-Path $env:ProgramData "PKI\Logs"
        }
        else {
            $LogDir = Split-Path $script:LogPath -Parent
        }
        
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force -ErrorAction Stop | Out-Null
        }
        
        if ([string]::IsNullOrWhiteSpace($script:LogPath)) {
            $Script:LogPath = Join-Path $LogDir "RootCA-Build-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        }
        else {
            $Script:LogPath = $script:LogPath
        }
        
        Start-Transcript -Path $Script:LogPath -Append -ErrorAction Stop
        Write-Host "Logging enabled: $Script:LogPath" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "Failed to initialize logging: $_"
        Write-Warning "Continuing without file logging..."
        $Script:LogPath = $null
    }
}

#===========================================================================================================
# FUNCTION DEFINITIONS
#===========================================================================================================

#-----------------------------------------------------------------------------------------------------------
# Function: Show-Disclaimer
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Displays disclaimer and waits for user confirmation
  
.DESCRIPTION
  Shows important information about the Root CA installation process, including:
  - Operational requirements (server must remain online during SubCA installation)
  - Security best practices (take offline after SubCA installation)
  - VM snapshot recommendations
#>
Function Show-Disclaimer {
  Clear-Host
  # ASCII art banner
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
  Write-Host "CRITICAL OPERATIONAL REQUIREMENTS:" -ForegroundColor Cyan
  Write-Host " - This Root CA server MUST remain ONLINE and accessible during SubCA installation" -ForegroundColor Yellow
  Write-Host " - PSRemoting must be enabled (use -EnablePSRemoting parameter) for SubCA to connect" -ForegroundColor Yellow
  Write-Host " - The SubCA script will remotely connect to this server to:" -ForegroundColor Yellow
  Write-Host "   * Submit certificate signing requests via PSRemoting (Invoke-Command)" -ForegroundColor Yellow
  Write-Host "   * Retrieve signed certificates via file share (\\RootCA\CertConfig)" -ForegroundColor Yellow
  Write-Host " - After SubCA installation completes, take this server OFFLINE for security" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Tips:" -ForegroundColor Yellow
  Write-Host " - If running on a virtual machine, take a snapshot before starting, and another one at completion." -ForegroundColor Yellow
  Write-Host "   This allows you to either restart fresh or recover/revert if anything fails with the subordinate CA." -ForegroundColor Yellow
  Write-Host " - Once the subordinate CA is built and active, disconnect the network and shutdown the Root CA." -ForegroundColor Yellow
  Write-Host " - Only bring the Root CA online when needed (issuing SubCA certs, renewals, revocations, CRL updates)" -ForegroundColor Yellow
  Write-Host ""
  Write-Host -NoNewLine "Press any key to continue..." -ForegroundColor Yellow
  $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

#-----------------------------------------------------------------------------------------------------------
# Function: Report-Status
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Outputs formatted status messages with color coding
  
.DESCRIPTION
  Provides consistent status reporting throughout the script.
  Level 0 = Execution messages, Level 1 = Query/Input prompts.
#>
Function Report-Status {
  Param(
    [parameter(Mandatory = $true)][String]$Msg,
    [parameter(Mandatory = $true)][INT]$Lvl,
    [parameter(Mandatory = $true)][String]$Color
  )
  
  # Log to file if logging is enabled
  if ($Script:LogPath) {
    try {
      $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      $logPrefix = if ($Lvl -eq 0) { "[EXEC]" } else { "[QUERY]" }
      $logMessage = "[$timestamp] $logPrefix $Msg"
      Add-Content -Path $Script:LogPath -Value $logMessage -ErrorAction SilentlyContinue
    }
    catch {
      # Silently fail logging to avoid disrupting script execution
    }
  }
  
  # Display to console
  Switch ($Lvl) {
    0 { Write-Host -Foreground $Color "[EXEC]" $Msg }
    1 { Write-Host -Foreground $Color "[QUERY]" $Msg }
  }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-Prerequisites
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Validates all prerequisites before script execution
  
.DESCRIPTION
  Checks for:
  - Administrator privileges (required for CA installation)
  - PowerShell version 5.1+ (required for ADCS cmdlets)
  - Windows Server OS (not client)
  - Domain-joined status (must NOT be domain-joined for Root CA)
  - Existing CA installation (idempotency check)
  - Required Windows features availability
#>
Function Test-Prerequisites {
  Report-Status "Checking prerequisites..." 0 Cyan
  
  # Verify administrator privileges (required for CA installation)
  try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
      throw "This script requires administrator privileges. Please run as Administrator."
    }
    Report-Status "Administrator privileges: OK" 0 Green
  }
  catch {
    Write-Error "Prerequisite check failed: $_"
    throw
  }
  
  # Verify PowerShell 5.1+ (required for ADCS cmdlets)
  try {
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
      throw "PowerShell version 5.1 or higher is required. Current version: $($psVersion.ToString())"
    }
    Report-Status "PowerShell version ($($psVersion.ToString())): OK" 0 Green
  }
  catch {
    Write-Error "Prerequisite check failed: $_"
    throw
  }
  
  # Verify Windows Server (not client OS)
  try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    if ($osInfo.ProductType -ne 3) {
      throw "This script must be run on Windows Server. Detected OS Type: $($osInfo.ProductType)"
    }
    Report-Status "Windows Server detected: OK" 0 Green
  }
  catch {
    Write-Error "Prerequisite check failed: $_"
    throw
  }
  
  # Root CA must NOT be domain-joined (security best practice)
  try {
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($computerInfo.PartOfDomain) {
      throw "CRITICAL: Root CA must NOT be domain-joined. Current domain: $($computerInfo.Domain). Root CA should be a standalone, workgroup server."
    }
    Report-Status "Server is not domain-joined: OK" 0 Green
  }
  catch {
    Write-Error "Prerequisite check failed: $_"
    throw
  }
  
  # Check if CA already installed (idempotency)
  try {
    $caService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
    if ($caService) {
      # Try to import ADCS module to check CA configuration
      if (Import-ADCSModule) {
        $caConfig = Get-CertificationAuthority -ErrorAction SilentlyContinue
        if ($caConfig) {
          Write-Warning "Certificate Authority is already installed and configured."
          Write-Warning "CA Name: $($caConfig.Name)"
          Write-Warning "CA Type: $($caConfig.CAType)"
          $response = Read-Host "Do you want to continue anyway? This may cause conflicts. [y/n]"
          if ($response -ne 'y') {
            throw "Script execution cancelled by user."
          }
        }
      }
      else {
        # Module not available - service exists but can't verify CA config
        # This is OK if we're checking before feature installation
        Write-Verbose "ADCS module not available yet - this is normal if CA feature isn't installed"
      }
    }
    Report-Status "CA installation check: OK" 0 Green
  }
  catch {
    if ($_.Exception.Message -like "*cancelled*") {
      throw
    }
    Write-Warning "Could not verify CA installation status: $_"
  }
  
  # Verify ADCS feature is available (Windows Server 2012-2025 compatible)
  try {
    # Check if ServerManager module is available (required for Get-WindowsFeature)
    # ServerManager module is included in all Windows Server versions (2012-2025)
    if (-not (Get-Module -ListAvailable -Name ServerManager -ErrorAction SilentlyContinue)) {
      throw "ServerManager module is not available. This script requires Windows Server with ServerManager module."
    }
    
    # Import ServerManager module if not already loaded
    if (-not (Get-Module -Name ServerManager -ErrorAction SilentlyContinue)) {
      Import-Module ServerManager -ErrorAction Stop
    }
    
    # Verify ADCS feature exists (compatible with Windows Server 2012-2025)
    $feature = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue
    if (-not $feature) {
      throw "ADCS-Cert-Authority feature is not available on this system. Ensure you are running Windows Server 2012 or later."
    }
    
    # Verify ADCS PowerShell module will be available after feature installation
    # This module is installed with ADCS-Cert-Authority feature
    Report-Status "Required Windows features available: OK" 0 Green
    Report-Status "ADCS PowerShell module will be available after feature installation" 0 Green
  }
  catch {
    Write-Error "Prerequisite check failed: $_"
    throw
  }
  
  Report-Status "All prerequisites met" 0 Green
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-InputValidation
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Validates user input: CA name, OID format, and CRL URL
  
.DESCRIPTION
  Validates:
  - CA Common Name: not empty, max 64 chars, alphanumeric + hyphens/underscores/dots/spaces only
  - OID: exactly 5 digits (IANA PEN format)
  - CRL URL: FQDN format (e.g., pki.company.com)
#>
Function Test-InputValidation {
  Param(
    [Parameter(Mandatory=$true)][string]$RootCAName,
    [Parameter(Mandatory=$true)][string]$OID,
    [Parameter(Mandatory=$true)][string]$httpCRLPath
  )
  
  $errors = @()
  
  # Validate CA Common Name: not empty, max 64 chars, alphanumeric + hyphens/underscores/dots/spaces only
  if ([string]::IsNullOrWhiteSpace($RootCAName)) {
    $errors += "CA Common Name cannot be empty."
  }
  elseif ($RootCAName.Length -gt 64) {
    $errors += "CA Common Name cannot exceed 64 characters. Current length: $($RootCAName.Length)"
  }
  elseif ($RootCAName -notmatch '^[a-zA-Z0-9\-_\.\s]+$') {
    $errors += "CA Common Name contains invalid characters. Only alphanumeric, hyphens, underscores, dots, and spaces are allowed."
  }
  
  # Validate OID: exactly 5 digits (IANA PEN format)
  if ($OID -notmatch '^\d{5}$') {
    $errors += "OID must be exactly 5 digits. Provided: $OID"
  }
  
  # Validate CRL URL: FQDN format (e.g., pki.company.com)
  if ([string]::IsNullOrWhiteSpace($httpCRLPath)) {
    $errors += "CRL URL path cannot be empty."
  }
  elseif ($httpCRLPath -notmatch '^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$') {
    $errors += "CRL URL path appears to be invalid. Expected format: pki.mycompany.com or similar FQDN."
  }
  
  if ($errors.Count -gt 0) {
    Write-Error "Input validation failed:`n$($errors -join "`n")"
    return $false
  }
  
  return $true
}

#-----------------------------------------------------------------------------------------------------------
# Function: Import-ADCSModule
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Safely imports the ADCSDeployment module if available
  
.DESCRIPTION
  Attempts to import the ADCSDeployment module which contains ADCS cmdlets.
  Returns $true if module is available and imported, $false otherwise.
  This is safe to call even if the module isn't available yet (e.g., before feature installation).
#>
Function Import-ADCSModule {
  try {
    # Check if module is available
    if (-not (Get-Module -ListAvailable -Name ADCSDeployment -ErrorAction SilentlyContinue)) {
      return $false
    }
    
    # Import if not already loaded
    if (-not (Get-Module -Name ADCSDeployment -ErrorAction SilentlyContinue)) {
      Import-Module ADCSDeployment -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Verify cmdlet is available
    if (Get-Command Get-CertificationAuthority -ErrorAction SilentlyContinue) {
      return $true
    }
    
    return $false
  }
  catch {
    return $false
  }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-CAInstalled
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Checks if CA service is running and configured (idempotency check)
  
.DESCRIPTION
  Verifies if Certificate Authority is already installed to allow safe script re-execution.
  Returns $true if CA service is running and CA configuration exists.
  Safely handles cases where ADCS module is not yet available.
#>
Function Test-CAInstalled {
  try {
    $caService = Get-Service -Name certsvc -ErrorAction SilentlyContinue
    if ($caService -and $caService.Status -eq 'Running') {
      # Import ADCS module if available (may not be available if CA isn't installed yet)
      if (Import-ADCSModule) {
        $caConfig = Get-CertificationAuthority -ErrorAction SilentlyContinue
        return ($null -ne $caConfig)
      }
      # If module not available but service is running, assume CA might be installed
      # but module not loaded (e.g., after reboot before module import)
      return $true
    }
    return $false
  }
  catch {
    return $false
  }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-CAPolicyExists
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Checks if CAPolicy.inf exists in SystemRoot (prevents overwriting existing config)
#>
Function Test-CAPolicyExists {
  return (Test-Path (Join-Path $env:SystemRoot "CAPolicy.inf"))
}

#-----------------------------------------------------------------------------------------------------------
# Function: Read-CAPolicyInf
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Reads and parses existing CAPolicy.inf file to extract configuration values
  
.DESCRIPTION
  Extracts OID and CRL URL from an existing CAPolicy.inf file.
  Returns a hashtable with OID and httpCRLPath if successfully parsed.
  Returns $null if file doesn't exist or cannot be parsed.
#>
Function Read-CAPolicyInf {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Path
  )
  
  try {
    if (-not (Test-Path $Path)) {
      return $null
    }
    
    $content = Get-Content $Path -Raw
    $result = @{}
    
    # Extract OID from line like "OID= 1.3.6.1.4.1.12345"
    if ($content -match 'OID\s*=\s*1\.3\.6\.1\.4\.1\.(\d{5})') {
      $result['OID'] = $matches[1]
    }
    
    # Extract CRL URL from line like "URL=http://pki.company.com/pki/cps.html"
    if ($content -match 'URL=http://([^/]+)') {
      $result['httpCRLPath'] = $matches[1]
    }
    
    # Return result only if both values were found
    if ($result.ContainsKey('OID') -and $result.ContainsKey('httpCRLPath')) {
      return $result
    }
    
    return $null
  }
  catch {
    Write-Verbose "Could not parse CAPolicy.inf: $_"
    return $null
  }
}

#-----------------------------------------------------------------------------------------------------------
# Function: New-CAPolicyInfContent
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Generates CAPolicy.inf content with security parameters
  
.DESCRIPTION
  Creates the CAPolicy.inf file content used by Windows CA during installation.
  This file defines CA policy, OID, CRL settings, and renewal parameters.
  Eliminates code duplication by centralizing the policy file generation.
#>
Function New-CAPolicyInfContent {
  param(
    [Parameter(Mandatory=$true)][string]$OID,
    [Parameter(Mandatory=$true)][string]$httpCRLPath,
    [Parameter(Mandatory=$false)][int]$KeyLength = 4096,
    [Parameter(Mandatory=$false)][int]$CAValidityYears = 10,
    [Parameter(Mandatory=$false)][int]$CRLPeriodYears = 1
  )
  
  return @"
[Version]
Signature="`$Windows NT$"
[PolicyStatementExtension]
Policies=InternalPolicy
[InternalPolicy]
OID= 1.3.6.1.4.1.$OID
Notice="Legal Policy Statement"
URL=http://$httpCRLPath/pki/cps.html
[Certsrv_Server]
RenewalKeyLength=$KeyLength
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=$CAValidityYears
CRLPeriod=Years
CRLPeriodUnits=$CRLPeriodYears
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=7
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=1
"@
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-OfflineCASecurity
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Validates offline CA security requirements: network isolation, remote services, firewall status
  
.DESCRIPTION
  Checks security posture for offline Root CA:
  - Network adapters (warns if active - should be disabled after SubCA installation)
  - Remote management services (WinRM, RemoteRegistry, Spooler)
  - Windows Firewall status
  
  NOTE: Network adapters and PSRemoting are expected to be active DURING SubCA installation,
        but should be disabled AFTER SubCA installation completes for security.
#>
Function Test-OfflineCASecurity {
  Report-Status "Checking offline CA security requirements..." 0 Cyan
  
  $warnings = @()
  
  # Check for active network adapters
  # NOTE: Active adapters are OK during SubCA installation, but should be disabled afterward
  try {
    $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    if ($adapters.Count -gt 0) {
      $warnings += "WARNING: Network adapters are enabled. Root CA should be offline after SubCA installation."
      $warnings += "  Network must remain active during SubCA installation, then disable after completion."
      foreach ($adapter in $adapters) {
        Write-Warning "  Active adapter: $($adapter.Name) - $($adapter.InterfaceDescription)"
      }
    }
    else {
      Report-Status "Network adapters: OK (no active adapters)" 0 Green
    }
  }
  catch {
    Write-Warning "Could not check network adapters: $_"
  }
  
  # Check remote management services (security risk for offline CA)
  $remoteServices = @('RemoteRegistry', 'WinRM', 'Spooler')
  foreach ($svcName in $remoteServices) {
    try {
      $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if ($service -and $service.Status -eq 'Running' -and $service.StartType -ne 'Disabled') {
        $warnings += "WARNING: $svcName service is running. Consider disabling for offline CA."
      }
    }
    catch {
      # Service doesn't exist - OK
    }
  }
  
  # Verify Windows Firewall is enabled (defense in depth)
  try {
    $fwProfile = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fwProfile) {
      $disabledProfiles = $fwProfile | Where-Object { $_.Enabled -eq $false }
      if ($disabledProfiles) {
        $warnings += "WARNING: Windows Firewall is disabled on some profiles. Enable for maximum security."
      }
      else {
        Report-Status "Windows Firewall: OK (enabled)" 0 Green
      }
    }
  }
  catch {
    Write-Warning "Could not check Windows Firewall: $_"
  }
  
  # Report results
  if ($warnings.Count -gt 0) {
    foreach ($warning in $warnings) {
      Write-Warning $warning
    }
    Report-Status "Security checks completed with warnings (see above)" 0 Yellow
  }
  else {
    Report-Status "Security checks passed" 0 Green
  }
  
  return $true
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-CAConfiguration
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Validates CA configuration after installation to ensure everything is properly configured
  
.DESCRIPTION
  Performs comprehensive validation of CA installation:
  - CA service status
  - CA configuration object
  - CRL distribution points
  - AIA entries
  - CRL files
  - CA certificate in store
#>
Function Test-CAConfiguration {
    Report-Status "Validating CA configuration..." 0 Cyan
    
    $errors = @()
    $warnings = @()
    
    # Verify CA service is running
    try {
        $service = Get-Service -Name certsvc -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            $errors += "Certificate Services is not running. Status: $($service.Status)"
        }
        else {
            Report-Status "CA Service: Running" 0 Green
        }
    }
    catch {
        $errors += "Could not verify CA service: $_"
    }
    
    # Verify CA object exists and is accessible
    try {
        # Ensure ADCS module is imported
        if (-not (Import-ADCSModule)) {
            $errors += "ADCS module is not available. Cannot verify CA configuration."
            return $false
        }
        
        $ca = Get-CertificationAuthority -ErrorAction Stop
        if (-not $ca) {
            $errors += "Could not retrieve CA configuration"
        }
        else {
            Report-Status "CA Configuration: Found ($($ca.Name))" 0 Green
        }
    }
    catch {
        $errors += "Could not retrieve CA configuration: $_"
        return $false
    }
    
    # Verify CRL distribution points (should have at least 2: local, CAConfig, HTTP)
    try {
        $cdps = Get-CACrlDistributionPoint -ErrorAction Stop
        if (-not $cdps -or $cdps.Count -lt 2) {
            $warnings += "Expected at least 2 CRL distribution points, found: $($cdps.Count)"
        }
        else {
            Report-Status "CRL Distribution Points: $($cdps.Count) configured" 0 Green
        }
    }
    catch {
        $warnings += "Could not verify CRL distribution points: $_"
    }
    
    # Verify AIA entries
    try {
        $aias = Get-CAAuthorityInformationAccess -ErrorAction Stop
        if (-not $aias -or $aias.Count -eq 0) {
            $warnings += "No AIA entries found"
        }
        else {
            Report-Status "AIA Entries: $($aias.Count) configured" 0 Green
        }
    }
    catch {
        $warnings += "Could not verify AIA entries: $_"
    }
    
    # Verify CRL files exist
    try {
        $crlPath = Join-Path $env:SystemRoot "System32\CertSrv\CertEnroll\*.crl"
        $crlFiles = Get-ChildItem $crlPath -ErrorAction SilentlyContinue
        if (-not $crlFiles) {
            $warnings += "No CRL files found in CertEnroll directory"
        }
        else {
            Report-Status "CRL Files: Found $($crlFiles.Count) file(s)" 0 Green
        }
    }
    catch {
        $warnings += "Could not verify CRL files: $_"
    }
    
    # Verify CA certificate exists in certificate store
    try {
        if ($ca) {
            $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
                $_.Subject -like "*CN=$($ca.Name)*" -or $_.Subject -like "*$($ca.Name)*"
            } | Select-Object -First 1
            if (-not $caCert) {
                $warnings += "CA certificate not found in certificate store"
            }
            else {
                Report-Status "CA Certificate: Found in certificate store" 0 Green
            }
        }
    }
    catch {
        $warnings += "Could not verify CA certificate: $_"
    }
    
    # Report results
    if ($errors.Count -gt 0) {
        Write-Error "CA Configuration Validation Failed:`n$($errors -join "`n")"
        return $false
    }
    
    if ($warnings.Count -gt 0) {
        foreach ($warning in $warnings) {
            Write-Warning $warning
        }
        Report-Status "CA Configuration: Valid with warnings" 0 Yellow
    }
    else {
        Report-Status "CA Configuration: Valid" 0 Green
    }
    
    return $true
}

#-----------------------------------------------------------------------------------------------------------
# Function: Export-CAConfiguration
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Exports CA configuration to JSON file for reuse or documentation
#>
Function Export-CAConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$AdditionalConfig = @{}
    )
    
    try {
        $config = @{
            RootCAName = $RootCAName
            OID = $OID
            httpCRLPath = $httpCRLPath
            HashAlgorithm = $script:HashAlgorithm
            KeyLength = $script:KeyLength
            CAValidityYears = $script:CAValidityYears
            CRLPeriodYears = $script:CRLPeriodYears
            CertificateValidityYears = $script:CertificateValidityYears
            CryptoProvider = $script:CryptoProvider
            HSMProviderName = $script:HSMProviderName
            ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ExportComputer = $env:COMPUTERNAME
        }
        
        # Merge additional configuration if provided
        foreach ($key in $AdditionalConfig.Keys) {
            $config[$key] = $AdditionalConfig[$key]
        }
        
        $config | ConvertTo-Json -Depth 3 | Out-File $Path -Encoding UTF8 -ErrorAction Stop
        Report-Status "Configuration exported to: $Path" 0 Green
        return $true
    }
    catch {
        Write-Error "Failed to export configuration: $_"
        return $false
    }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Import-CAConfiguration
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Imports CA configuration from JSON file (for reference/documentation)
#>
Function Import-CAConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    try {
        if (-not (Test-Path $Path)) {
            throw "Configuration file not found: $Path"
        }
        
        $config = Get-Content $Path -Raw | ConvertFrom-Json
        
        Write-Host ""
        Write-Host "Imported Configuration:" -ForegroundColor Cyan
        Write-Host "  CA Name: $($config.RootCAName)" -ForegroundColor Yellow
        Write-Host "  OID: $($config.OID)" -ForegroundColor Yellow
        Write-Host "  CRL URL: $($config.httpCRLPath)" -ForegroundColor Yellow
        Write-Host "  Hash Algorithm: $($config.HashAlgorithm)" -ForegroundColor Yellow
        Write-Host "  Key Length: $($config.KeyLength)" -ForegroundColor Yellow
        Write-Host "  CA Validity: $($config.CAValidityYears) years" -ForegroundColor Yellow
        Write-Host "  CRL Period: $($config.CRLPeriodYears) year(s)" -ForegroundColor Yellow
        Write-Host "  Certificate Validity: $($config.CertificateValidityYears) year(s)" -ForegroundColor Yellow
        Write-Host "  Crypto Provider: $($config.CryptoProvider)" -ForegroundColor Yellow
        if ($config.ExportDate) {
            Write-Host "  Exported: $($config.ExportDate) from $($config.ExportComputer)" -ForegroundColor Gray
        }
        Write-Host ""
        
        return $config
    }
    catch {
        Write-Error "Failed to import configuration: $_"
        throw
    }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Backup-CAKeys
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Backs up CA certificate, private key, and database
  
.DESCRIPTION
  Creates a secure backup of:
  - CA certificate with private key (PFX format, password-protected)
  - CA certificate without private key (CER format)
  - CA database (CertLog directory)
  - Backup manifest with metadata
  
  CRITICAL: Store backups in secure, offline location. Protect backup password separately.
#>
Function Backup-CAKeys {
  param([Parameter(Mandatory=$true)][string]$BackupPath)
  
  Report-Status "Creating CA backup..." 0 Cyan
  
  try {
    # Create backup directory if needed
    if (-not (Test-Path $BackupPath)) {
      New-Item -ItemType Directory -Path $BackupPath -Force -ErrorAction Stop | Out-Null
      Report-Status "Created backup directory: $BackupPath" 0 Green
    }
    
    # Import ADCS module and get CA configuration
    if (-not (Import-ADCSModule)) {
      throw "ADCS module is not available. Cannot create backup."
    }
    
    $caConfig = Get-CertificationAuthority -ErrorAction Stop
    if (-not $caConfig) {
      throw "Could not retrieve CA configuration"
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $caName = $caConfig.Name
    
    # Prompt for backup password (minimum 12 characters, stored separately)
    Write-Host ""
    Write-Host "CA BACKUP PASSWORD REQUIRED" -ForegroundColor Yellow
    Write-Host "Enter a strong password to protect the CA private key backup." -ForegroundColor Yellow
    Write-Host "IMPORTANT: Store this password securely and separately from the backup!" -ForegroundColor Red
    $backupPassword = Read-Host "Enter backup password" -AsSecureString
    $backupPasswordConfirm = Read-Host "Confirm backup password" -AsSecureString
    
    # Validate password match and strength (convert to plain text temporarily for validation)
    $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($backupPassword)
    $plainPassword1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
    $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($backupPasswordConfirm)
    $plainPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
    
    if ($plainPassword1 -ne $plainPassword2) {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
      throw "Passwords do not match"
    }
    
    if ($plainPassword1.Length -lt 12) {
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
      throw "Backup password must be at least 12 characters long"
    }
    
    # Clear plain text passwords from memory immediately
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
    Remove-Variable plainPassword1, plainPassword2 -ErrorAction SilentlyContinue
    
    # Find CA certificate
    $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
      $_.Subject -like "*CN=$caName*" -or $_.Subject -like "*$caName*"
    } | Select-Object -First 1
    
    if (-not $caCert) {
      throw "Could not find CA certificate in certificate store"
    }
    
    # Export CA certificate with private key (PFX)
    $pfxPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.pfx"
    Export-PfxCertificate -Cert $caCert -FilePath $pfxPath -Password $backupPassword -ErrorAction Stop
    Report-Status "CA certificate with private key exported: $pfxPath" 0 Green
    
    # Export CA certificate without private key (CER)
    $cerPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.cer"
    Export-Certificate -Cert $caCert -FilePath $cerPath -Type CERT -ErrorAction Stop
    Report-Status "CA certificate (public key) exported: $cerPath" 0 Green
    
    # Backup CA database
    $dbPath = Join-Path $env:SystemRoot "System32\CertLog"
    if (Test-Path $dbPath) {
      $dbBackupPath = Join-Path $BackupPath "CADatabase-$timestamp"
      Copy-Item -Path $dbPath -Destination $dbBackupPath -Recurse -Force -ErrorAction Stop
      Report-Status "CA database backed up to: $dbBackupPath" 0 Green
    }
    
    # Create backup manifest
    $manifestPath = Join-Path $BackupPath "Backup-Manifest-$timestamp.txt"
    $manifest = @"
Root CA Backup Manifest
=======================
Backup Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
CA Name: $caName
CA Type: $($caConfig.CAType)

Backup Files:
- PFX (Certificate + Private Key): RootCA-$caName-$timestamp.pfx
- CER (Certificate Only): RootCA-$caName-$timestamp.cer
- Database: CADatabase-$timestamp

IMPORTANT SECURITY NOTES:
- Store backups in secure, offline location
- Use multiple backup locations (different physical locations)
- Protect backup password (store separately from backups)
- Verify backup integrity before going offline
- Test restore procedures regularly

"@
    $manifest | Out-File $manifestPath -Encoding UTF8
    Report-Status "Backup manifest created: $manifestPath" 0 Green
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "CA BACKUP COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Backup Location: $BackupPath" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "CRITICAL SECURITY REMINDERS:" -ForegroundColor Red
    Write-Host "1. Store backups in secure, offline location" -ForegroundColor Yellow
    Write-Host "2. Use multiple backup locations" -ForegroundColor Yellow
    Write-Host "3. Protect backup password (store separately)" -ForegroundColor Yellow
    Write-Host "4. Verify backup integrity" -ForegroundColor Yellow
    Write-Host "5. Test restore procedures" -ForegroundColor Yellow
    Write-Host ""
  }
  catch {
    Write-Error "Failed to create CA backup: $_"
    throw
  }
}

#===========================================================================================================
# MAIN EXECUTION
#===========================================================================================================

try {
  #-----------------------------------------------------------------------------------------------------------
  # Phase 1: Initialization and Prerequisites
  #-----------------------------------------------------------------------------------------------------------
  Show-Disclaimer
  Clear-Host
  Report-Status "Building Root CA" 0 Green
  
  # Configuration import/export removed for single-use script simplicity

  # Initialize progress tracking
  $Script:ProgressPhases = @(
    "Checking Prerequisites",
    "Validating Security Requirements",
    "Collecting User Input",
    "Creating CAPolicy.inf",
    "Installing Windows Features",
    "Installing Certificate Authority",
    "Configuring CA Settings",
    "Publishing CRL",
    "Validating Configuration",
    "Creating Backup"
  )
  $Script:CurrentPhase = 0

  # Validate prerequisites and security requirements
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  Test-Prerequisites
  $Script:CurrentPhase++
  
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  Test-OfflineCASecurity
  $Script:CurrentPhase++

  # Display security configuration
  Write-Host ""
  Write-Host "Security Configuration:" -ForegroundColor Cyan
  Write-Host "  Hash Algorithm: $script:HashAlgorithm" -ForegroundColor Yellow
  Write-Host "  Key Length: $script:KeyLength bits" -ForegroundColor Yellow
  Write-Host "  CA Validity: $script:CAValidityYears years" -ForegroundColor Yellow
  Write-Host "  CRL Period: $script:CRLPeriodYears year(s)" -ForegroundColor Yellow
  Write-Host "  Certificate Validity: $script:CertificateValidityYears year(s)" -ForegroundColor Yellow
  Write-Host ""

  # Idempotency check: skip installation if CA already exists
  if (Test-CAInstalled) {
    Write-Warning "Certificate Authority appears to be already installed."
    $response = Read-Host "Do you want to continue with configuration changes? [y/n]"
    if ($response -ne 'y') {
      Report-Status "Script execution cancelled by user." 0 Yellow
      exit 0
    }
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 2: Network and Remote Access Configuration
  #-----------------------------------------------------------------------------------------------------------
  # PSRemoting Configuration - REQUIRED for SubCA Installation
  # The SubCA script (Build-SubCA.ps1) requires PSRemoting to:
  # 1. Connect to this Root CA server via Invoke-Command
  # 2. Remotely submit certificate signing requests (CSR)
  # 3. Process and authorize certificate requests on the Root CA
  # 4. Retrieve signed certificates back to the SubCA server
  #
  # IMPORTANT: This Root CA server MUST remain online and accessible during SubCA installation.
  # After SubCA installation completes, PSRemoting should be disabled for security.
  #
  # Default: Enable PSRemoting (required for SubCA installation)
  # User can disable with -EnablePSRemoting:$false if needed
  if (-not $PSBoundParameters.ContainsKey('EnablePSRemoting') -or $EnablePSRemoting) {
    Report-Status "Enabling PS Remoting (REQUIRED for SubCA installation)" 0 Green
    try {
      Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null
      Report-Status "PS Remoting enabled successfully" 0 Green
      Write-Host ""
      Write-Host "PSRemoting Status:" -ForegroundColor Cyan
      Write-Host "  PSRemoting is now ENABLED and ready for SubCA connection" -ForegroundColor Green
      Write-Host "  The SubCA script will use this to remotely process certificate requests" -ForegroundColor Yellow
      Write-Host "  After SubCA installation completes, disable PSRemoting for security" -ForegroundColor Yellow
      Write-Host ""
    }
    catch {
      Write-Error "Failed to enable PS Remoting: $_"
      Write-Error "PSRemoting is REQUIRED for SubCA installation. Please resolve this issue."
      throw
    }
  }
  else {
    Write-Host ""
    Write-Host "WARNING: PSRemoting is NOT enabled!" -ForegroundColor Red
    Write-Host "PSRemoting is REQUIRED for SubCA installation." -ForegroundColor Yellow
    Write-Host "The SubCA script needs to connect to this server to:" -ForegroundColor Yellow
    Write-Host "  - Submit certificate signing requests" -ForegroundColor Yellow
    Write-Host "  - Process and authorize certificate requests" -ForegroundColor Yellow
    Write-Host "  - Retrieve signed certificates" -ForegroundColor Yellow
    Write-Host ""
    $response = Read-Host "Do you want to enable PSRemoting now? [y/n]"
    if ($response -eq 'y') {
      try {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null
        Report-Status "PS Remoting enabled successfully" 0 Green
      }
      catch {
        Write-Error "Failed to enable PS Remoting: $_"
        throw
      }
    }
    else {
      Write-Warning "PSRemoting not enabled. SubCA installation will fail without it."
      Write-Warning "You can enable it later by running: Enable-PSRemoting -Force"
    }
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 3: Security Configuration
  #-----------------------------------------------------------------------------------------------------------
  # Enable object access auditing (required for CA security and compliance)
  # This ensures all CA operations are logged for audit purposes
  Report-Status "Configuring Auditing" 0 Green
  try {
    $null = auditpol /set /category:"Object Access" /failure:enable /success:enable 2>&1
    if ($LASTEXITCODE -ne 0) {
      throw "auditpol command failed with exit code $LASTEXITCODE"
    }
    Report-Status "Auditing configured successfully" 0 Green
  }
  catch {
    Write-Error "Failed to configure auditing: $_"
    throw
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 4: User Input Collection
  #-----------------------------------------------------------------------------------------------------------
  # Collect required information from user: CA name, OID, and CRL URL
  # If CAPolicy.inf exists, extract values from it to avoid re-prompting
  $Script:CurrentPhase = 2
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  
  $capolicyPath = Join-Path $env:SystemRoot "CAPolicy.inf"
  $existingCAPolicy = $null
  
  # Check if CAPolicy.inf exists and try to read values from it
  if (Test-CAPolicyExists) {
    Report-Status "CAPolicy.inf file found. Reading existing configuration..." 0 Cyan
    $existingCAPolicy = Read-CAPolicyInf -Path $capolicyPath
    
    if ($existingCAPolicy) {
      $OID = $existingCAPolicy['OID']
      $httpCRLPath = $existingCAPolicy['httpCRLPath']
      Report-Status "Extracted from existing CAPolicy.inf:" 0 Green
      Write-Host "  OID           : $OID" -ForegroundColor Yellow
      Write-Host "  CRL URL path  : $httpCRLPath" -ForegroundColor Yellow
      Write-Host ""
      
      # Try to get CA name from existing CA installation if available
      if (Import-ADCSModule) {
        $existingCA = Get-CertificationAuthority -ErrorAction SilentlyContinue
        if ($existingCA) {
          $RootCAName = $existingCA.Name
          Report-Status "CA Name retrieved from existing installation: $RootCAName" 0 Green
          Write-Host ""
          Report-Status "Using existing configuration. Proceeding with installation..." 0 Green
          # Skip user input collection
        }
        else {
          # CA not installed yet, still need CA name
          Report-Status "CA Name not found. Please provide CA Common Name:" 1 Yellow
          $RootCAName = (Read-Host).Trim()
        }
      }
      else {
        # Module not available, need CA name
        Report-Status "CA Name not available. Please provide CA Common Name:" 1 Yellow
        $RootCAName = (Read-Host).Trim()
      }
    }
    else {
      # CAPolicy.inf exists but couldn't be parsed - ask for input
      Write-Warning "CAPolicy.inf exists but could not be parsed. Please provide configuration values."
      $existingCAPolicy = $null
    }
  }
  
  # If no existing CAPolicy.inf or couldn't parse it, collect all input
  if (-not $existingCAPolicy) {
    $response = $null
    do {
      Report-Status "Enter the Common Name for the Root CA (ex: Corp-Root-CA):" 1 Yellow
      $RootCAName = (Read-Host).Trim()
      Write-Verbose "CA Common Name entered: $RootCAName"

      do {
        Report-Status "Please enter your 5 digit OID number:" 1 Yellow
        $OID = (Read-Host).Trim()
        Write-Verbose "OID entered: $OID"
      } while ($OID -notmatch "^\d{5}$")

      Report-Status "Enter the URL where the CRL files will be located (ex: pki.mycompany.com): " 1 Yellow
      $httpCRLPath = (Read-Host).Trim()
      Write-Verbose "CRL URL path entered: $httpCRLPath"

      # Validate all inputs before proceeding
      if (-not (Test-InputValidation -RootCAName $RootCAName -OID $OID -httpCRLPath $httpCRLPath)) {
        Report-Status "Please correct the errors above and try again." 0 Red
        continue
      }

      Report-Status "You have provided the following information:" 1 Yellow
      Write-Host "CA Common Name: $RootCAName"
      Write-Host "OID           : $OID"
      Write-Host "CRL URL path  : $httpCRLPath"
      Write-Verbose "User input validation passed"

      Report-Status "Are you satisfied with these answers? [y/n]" 1 Yellow
      $response = Read-Host
    } while ($response -ne 'y')
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 5: CAPolicy.inf Creation
  #-----------------------------------------------------------------------------------------------------------
  # Create CAPolicy.inf file - This file is read by Windows CA during installation
  # It defines CA policy, OID, CRL settings, and renewal parameters
  # Must be created BEFORE installing the CA role
  $Script:CurrentPhase = 3
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  Report-Status "Create CAPolicy file" 0 Green
  try {
    # Idempotency: Use existing file if it exists and was successfully parsed
    if ($existingCAPolicy) {
      Report-Status "Using existing CAPolicy.inf file (already configured)" 0 Green
      Write-Host "  File: $capolicyPath" -ForegroundColor Gray
      Write-Host "  OID: $OID" -ForegroundColor Gray
      Write-Host "  CRL URL: $httpCRLPath" -ForegroundColor Gray
    }
    else {
      # Create or update CAPolicy.inf
      if (Test-CAPolicyExists) {
        Write-Warning "CAPolicy.inf already exists at $capolicyPath"
        $response = Read-Host "Do you want to overwrite it with new values? [y/n]"
        if ($response -ne 'y') {
          Report-Status "Using existing CAPolicy.inf file" 0 Yellow
        }
        else {
          $CAPolicyInf = New-CAPolicyInfContent -OID $OID -httpCRLPath $httpCRLPath -KeyLength $script:KeyLength -CAValidityYears $script:CAValidityYears -CRLPeriodYears $script:CRLPeriodYears
          $CAPolicyInf | Out-File $capolicyPath -Encoding utf8 -Force -ErrorAction Stop
          Report-Status "CAPolicy.inf updated successfully" 0 Green
        }
      }
      else {
        $CAPolicyInf = New-CAPolicyInfContent -OID $OID -httpCRLPath $httpCRLPath -KeyLength $script:KeyLength -CAValidityYears $script:CAValidityYears -CRLPeriodYears $script:CRLPeriodYears
        $CAPolicyInf | Out-File $capolicyPath -Encoding utf8 -Force -ErrorAction Stop
        Report-Status "CAPolicy.inf created successfully" 0 Green
      }
    }

    # Display file and allow editing
    Get-Content $capolicyPath
    Report-Status "Would you like to edit CAPolicy.Inf? [y/n]" 1 Yellow
    $response = Read-Host
    If ($response -eq "y") {
      try {
        Start-Process -Wait -FilePath "notepad.exe" -ArgumentList $capolicyPath -ErrorAction Stop
      }
      catch {
        Write-Warning "Could not open notepad. Please edit $capolicyPath manually."
      }
    }
    $response = $null
  }
  catch {
    Write-Error "Failed to create CAPolicy.inf: $_"
    throw
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 6: Windows Feature Installation
  #-----------------------------------------------------------------------------------------------------------
  # Install ADCS-Cert-Authority feature (idempotent: skips if already installed)
  # This feature provides the Certificate Authority role and management tools
  # Compatible with Windows Server 2012, 2016, 2019, 2022, and 2025
  $Script:CurrentPhase = 4
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  Report-Status "Installing required Windows Features" 0 Green
  try {
    # Ensure ServerManager module is available and imported (required for Get-WindowsFeature)
    if (-not (Get-Module -ListAvailable -Name ServerManager -ErrorAction SilentlyContinue)) {
      throw "ServerManager module is not available. This script requires Windows Server with ServerManager module."
    }
    
    if (-not (Get-Module -Name ServerManager -ErrorAction SilentlyContinue)) {
      Import-Module ServerManager -ErrorAction Stop
    }
    
    # Check feature status (compatible with Windows Server 2012-2025)
    $feature = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction Stop
    if ($feature.InstallState -eq 'Installed') {
      Report-Status "ADCS-Cert-Authority feature is already installed" 0 Yellow
    }
    else {
      # Use Install-WindowsFeature (Server 2012-2025) - preferred method
      # Add-WindowsFeature is for Server 2008 R2 and earlier (legacy)
      if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
        Report-Status "Installing ADCS-Cert-Authority feature using Install-WindowsFeature..." 0 Green
        $installResult = Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop
      }
      elseif (Get-Command Add-WindowsFeature -ErrorAction SilentlyContinue) {
        # Fallback for older Server versions (2008 R2)
        Report-Status "Installing ADCS-Cert-Authority feature using Add-WindowsFeature (legacy)..." 0 Yellow
        $installResult = Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools -ErrorAction Stop
      }
      else {
        throw "Neither Install-WindowsFeature nor Add-WindowsFeature is available. This script requires Windows Server."
      }
      
      # Check installation result
      if ($installResult.RestartNeeded) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "RESTART REQUIRED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Windows feature installation requires a system restart to complete." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "NEXT STEPS:" -ForegroundColor Green
        Write-Host "1. Restart the server now" -ForegroundColor Yellow
        Write-Host "2. After restart, run the script again:" -ForegroundColor Yellow
        Write-Host "   .\Build-RootCA.ps1" -ForegroundColor White
        Write-Host "3. The script will detect the feature is already installed and continue" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The script will resume from where it left off after the restart." -ForegroundColor Cyan
        Write-Host ""
        $Script:ExitCode = 3010  # Standard Windows restart required exit code
        exit $Script:ExitCode
      }
      
      # Validate exit code (Success = 0, NoChangeNeeded = 1, SuccessWithRestart = 3010)
      $validExitCodes = @(0, 1, 3010, 'Success', 'NoChangeNeeded', 'SuccessRestartRequired')
      if ($installResult.ExitCode -notin $validExitCodes) {
        throw "Feature installation failed with exit code: $($installResult.ExitCode). Result: $($installResult | Out-String)"
      }
      
      Report-Status "Windows Features installed successfully" 0 Green
    }
  }
  catch {
    Write-Error "Failed to install Windows Features: $_"
    Write-Error "Ensure you are running on Windows Server 2012 or later with ServerManager module available."
    throw
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 7: Certificate Authority Installation
  #-----------------------------------------------------------------------------------------------------------
  # Install Standalone Root CA with security parameters
  # This creates the CA certificate and initializes the CA database
  # Idempotent: skips installation if CA already exists
  # Compatible with Windows Server 2012-2025
  $Script:CurrentPhase = 5
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  
  # Verify ADCS PowerShell module is available (installed with ADCS-Cert-Authority feature)
  # This module provides Install-AdcsCertificationAuthority and other ADCS cmdlets
  try {
    if (-not (Get-Module -ListAvailable -Name ADCSDeployment -ErrorAction SilentlyContinue)) {
      Write-Warning "ADCSDeployment module not found. It should be installed with ADCS-Cert-Authority feature."
      Write-Warning "Attempting to import module..."
    }
    
    # Import ADCSDeployment module if available (may not be available until after feature install)
    if (Get-Module -ListAvailable -Name ADCSDeployment -ErrorAction SilentlyContinue) {
      if (-not (Get-Module -Name ADCSDeployment -ErrorAction SilentlyContinue)) {
        Import-Module ADCSDeployment -ErrorAction SilentlyContinue
      }
    }
    
    # Verify Install-AdcsCertificationAuthority cmdlet is available
    if (-not (Get-Command Install-AdcsCertificationAuthority -ErrorAction SilentlyContinue)) {
      throw "Install-AdcsCertificationAuthority cmdlet is not available. Ensure ADCS-Cert-Authority feature is installed."
    }
  }
  catch {
    Write-Error "ADCS PowerShell module check failed: $_"
    Write-Error "The ADCSDeployment module should be available after installing ADCS-Cert-Authority feature."
    throw
  }
  
  if (Test-CAInstalled) {
    Report-Status "Certificate Authority is already installed. Skipping installation." 0 Yellow
    # Import ADCS module to get CA details
    if (Import-ADCSModule) {
      $existingCA = Get-CertificationAuthority -ErrorAction SilentlyContinue
      if ($existingCA) {
        Report-Status "Existing CA Name: $($existingCA.Name)" 0 Yellow
        Report-Status "Existing CA Type: $($existingCA.CAType)" 0 Yellow
      }
    }
  }
  else {
    Report-Status "Install and configure AD Certificate Services" 0 Green
    try {
      # Determine crypto provider based on configuration
      $cryptoProviderName = switch ($script:CryptoProvider) {
        'Software' { "RSA#Microsoft Software Key Storage Provider" }
        'HSM' { 
          if ($script:HSMProviderName) { 
            "RSA#$script:HSMProviderName" 
          } 
          else { 
            "RSA#Microsoft Platform Crypto Provider" 
          }
        }
        'Platform' { "RSA#Microsoft Platform Crypto Provider" }
        default { "RSA#Microsoft Software Key Storage Provider" }
      }
      
      Write-Verbose "Using Crypto Provider: $cryptoProviderName"
      Write-Debug "CA Installation Parameters:"
      Write-Debug "  CA Name: $RootCAName"
      Write-Debug "  Key Length: $script:KeyLength"
      Write-Debug "  Hash Algorithm: $script:HashAlgorithm"
      Write-Debug "  Validity Period: $script:CAValidityYears years"
      Write-Debug "  Crypto Provider: $cryptoProviderName"
      Report-Status "Crypto Provider: $script:CryptoProvider" 0 Cyan
      
      # Install Standalone Root CA with security parameters
      if ($PSCmdlet.ShouldProcess("Certificate Authority", "Install")) {
        Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $RootCAName -KeyLength $script:KeyLength -HashAlgorithm $script:HashAlgorithm -CryptoProviderName $cryptoProviderName -ValidityPeriod Years -ValidityPeriodUnits $script:CAValidityYears -Force -ErrorAction Stop | Out-Null
      }
      
      # Verify installation succeeded
      Start-Sleep -Seconds 3
      
      # Import ADCS module to verify installation
      if (-not (Import-ADCSModule)) {
        throw "ADCS module is not available after installation. Please verify ADCS-Cert-Authority feature is installed."
      }
      
      $verifyCA = Get-CertificationAuthority -ErrorAction SilentlyContinue
      if (-not $verifyCA) {
        throw "CA installation completed but could not verify CA configuration."
      }
      Report-Status "Certificate Authority installed and verified successfully" 0 Green
    }
    catch {
      Write-Error "Failed to install Certificate Authority: $_"
      Write-Error "Ensure the server is not domain-joined and ADCS-Cert-Authority feature is properly installed."
      throw
    }
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 8: CA Configuration
  #-----------------------------------------------------------------------------------------------------------
  # Configure CA: CRL distribution points, AIA entries, registry settings, and file share
  # This phase sets up the CA for certificate issuance and ensures SubCA can access required files
  $Script:CurrentPhase = 6
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  Report-Status "Customizing AD Certificate Services" 0 Green
  
  try {
    # Create CAConfig directory for CRL storage and certificate file sharing
    # IMPORTANT: This directory must be accessible to the SubCA server during SubCA installation
    # The SubCA script maps a drive to \\RootCA\CertConfig to retrieve certificate files
    $caConfigPath = "C:\CAConfig"
    if (-not (Test-Path $caConfigPath)) {
      New-Item -ItemType Directory -Path $caConfigPath -Force -ErrorAction Stop | Out-Null
      Report-Status "Created CAConfig directory" 0 Green
    }
    else {
      Report-Status "CAConfig directory already exists" 0 Yellow
    }
    
    # Create CertConfig SMB share for SubCA access (required for SubCA installation)
    try {
      $existingShare = Get-SmbShare -Name "CertConfig" -ErrorAction SilentlyContinue
      if ($existingShare) {
        Report-Status "CertConfig share already exists" 0 Yellow
        Write-Host "  Share Path: \\$env:COMPUTERNAME\CertConfig" -ForegroundColor Cyan
      }
      else {
        # Create SMB share with appropriate permissions for SubCA access
        # Grant FullAccess to Administrators (SubCA will use admin credentials)
        if ($PSCmdlet.ShouldProcess("CertConfig share", "Create")) {
          New-SmbShare -Name "CertConfig" -Path $caConfigPath -Description "Root CA Certificate Configuration Share - Required for SubCA Installation" -FullAccess "Administrators" -ErrorAction Stop | Out-Null
          Report-Status "CertConfig share created successfully" 0 Green
          Write-Host "  Share Path: \\$env:COMPUTERNAME\CertConfig" -ForegroundColor Cyan
          Write-Host "  Share Description: Root CA Certificate Configuration Share" -ForegroundColor Gray
          Write-Host "  Permissions: Administrators (Full Access)" -ForegroundColor Gray
        }
      }
    }
    catch {
      Write-Warning "Could not create CertConfig share: $_"
      Write-Warning "You may need to create the share manually: New-SmbShare -Name 'CertConfig' -Path '$caConfigPath' -FullAccess 'Administrators'"
      Write-Warning "The SubCA script requires access to \\$env:COMPUTERNAME\CertConfig"
    }

    # Remove default CRL distribution points, then add custom ones
    try {
      $existingCDPs = Get-CACrlDistributionPoint -ErrorAction Stop
      if ($existingCDPs) {
        $existingCDPs | Remove-CACrlDistributionPoint -Force -ErrorAction Stop | Out-Null
        Report-Status "Removed existing CRL distribution points" 0 Green
      }
    }
    catch {
      Write-Warning "Could not remove existing CRL distribution points: $_"
    }

    # Configure CRL distribution points: local, CAConfig, and HTTP
    try {
      Add-CACRLDistributionPoint -Uri "$env:windir\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force -ErrorAction Stop | Out-Null
      Add-CACRLDistributionPoint -Uri "$caConfigPath\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force -ErrorAction Stop | Out-Null
      Add-CACRLDistributionPoint -Uri "http://$httpCRLPath/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force -ErrorAction Stop | Out-Null
      Report-Status "CRL distribution points configured successfully" 0 Green
    }
    catch {
      Write-Error "Failed to configure CRL distribution points: $_"
      throw
    }

    # Remove default AIA entries, then add custom HTTP-based entry
    try {
      $existingAIAs = Get-CAAuthorityInformationAccess -ErrorAction Stop | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' }
      if ($existingAIAs) {
        $existingAIAs | Remove-CAAuthorityInformationAccess -Force -ErrorAction Stop | Out-Null
        Report-Status "Removed existing AIA entries" 0 Green
      }
    }
    catch {
      Write-Warning "Could not remove existing AIA entries: $_"
    }

    try {
      Add-CAAuthorityInformationAccess -Uri "http://$httpCRLPath/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force -ErrorAction Stop | Out-Null
      Report-Status "AIA entry configured successfully" 0 Green
    }
    catch {
      Write-Error "Failed to configure AIA entry: $_"
      throw
    }

    # Configure CA registry settings: CRL period, validity periods, audit
    Report-Status "Configuring CA registry settings" 0 Green
    try {
      $regSettings = @(
        @{Path = "CA\CRLPeriodUnits"; Value = "$script:CRLPeriodYears"},  # 1-2 years for offline CA
        @{Path = "CA\CRLPeriod"; Value = "Years"},
        @{Path = "CA\CRLDeltaPeriodUnits"; Value = "7"},  # Weekly delta CRL
        @{Path = "CA\CRLDeltaPeriod"; Value = "Days"},
        @{Path = "CA\CRLOverlapPeriodUnits"; Value = "2"},  # 2-week overlap
        @{Path = "CA\CRLOverlapPeriod"; Value = "Weeks"},
        @{Path = "CA\ValidityPeriodUnits"; Value = "$script:CertificateValidityYears"},  # 1-2 years for issued certs
        @{Path = "CA\ValidityPeriod"; Value = "Years"},
        @{Path = "CA\AuditFilter"; Value = "127"}  # All audit events (binary: 01111111)
      )

      foreach ($setting in $regSettings) {
        $null = certutil.exe -setreg $setting.Path $setting.Value 2>&1
        if ($LASTEXITCODE -ne 0) {
          throw "Failed to set registry value $($setting.Path)"
        }
      }
      Report-Status "CA registry settings configured successfully" 0 Green
    }
    catch {
      Write-Error "Failed to configure CA registry settings: $_"
      throw
    }

    #-----------------------------------------------------------------------------------------------------------
    # Phase 9: Service Restart and CRL Publication
    #-----------------------------------------------------------------------------------------------------------
    # Restart CA service to apply registry changes
    # Registry settings require service restart to take effect
    Report-Status "Restarting AD Certificate Services" 0 Green
    try {
      $service = Get-Service -Name certsvc -ErrorAction Stop
      if ($service.Status -eq 'Running') {
        Restart-Service -Name certsvc -ErrorAction Stop
      }
      else {
        Start-Service -Name certsvc -ErrorAction Stop
      }
      
      # Wait for service to reach running state (30 second timeout)
      $service.WaitForStatus('Running', (New-TimeSpan -Seconds 30))
      if ((Get-Service -Name certsvc).Status -ne 'Running') {
        throw "Certificate Services failed to start after restart"
      }
      Start-Sleep -Seconds 3  # Allow service to fully initialize
      Report-Status "Certificate Services restarted successfully" 0 Green
    }
    catch {
      Write-Error "Failed to restart Certificate Services: $_"
      throw
    }

    # Publish initial CRL
    $Script:CurrentPhase = 7
    Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
    Report-Status "Publishing CRL" 0 Green
    try {
      $null = certutil -crl 2>&1
      if ($LASTEXITCODE -ne 0) {
        throw "CRL publication failed with exit code $LASTEXITCODE"
      }
      Report-Status "CRL published successfully" 0 Green
    }
    catch {
      Write-Error "Failed to publish CRL: $_"
      throw
    }
    
    #-----------------------------------------------------------------------------------------------------------
    # Phase 9.5: Post-Installation Configuration Validation
    #-----------------------------------------------------------------------------------------------------------
    # Validate CA configuration to ensure everything is properly configured
    $Script:CurrentPhase = 8
    Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
    if (-not (Test-CAConfiguration)) {
      Write-Warning "CA configuration validation completed with warnings or errors."
      Write-Warning "Please review the validation results above."
      $response = Read-Host "Continue anyway? [y/n]"
      if ($response -ne 'y') {
        throw "CA configuration validation failed. Please review and fix issues."
      }
    }

    #-----------------------------------------------------------------------------------------------------------
    # Phase 10: Backup Creation
    #-----------------------------------------------------------------------------------------------------------
    # Create backup of CA certificate, private key, and database
    # CRITICAL: Backups must be created before taking the server offline
    # Store backups in secure, offline location with password protection
    $Script:CurrentPhase = 9
    Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
    if ($CreateBackup) {
      try {
        if ([string]::IsNullOrWhiteSpace($BackupPath)) {
          $BackupPath = Join-Path $env:SystemDrive "CA-Backup"
        }
        Backup-CAKeys -BackupPath $BackupPath
      }
      catch {
        Write-Warning "Backup creation failed: $_"
        Write-Warning "CRITICAL: Manual backup is strongly recommended before going offline!"
        $response = Read-Host "Continue without backup? [y/n]"
        if ($response -ne 'y') {
          throw "Backup is required. Please fix backup issues and try again."
        }
      }
    }
    else {
      Write-Host ""
      Write-Host "WARNING: Backup was not created!" -ForegroundColor Red
      Write-Host "CRITICAL: Create a backup of the CA certificate and private key before going offline!" -ForegroundColor Yellow
      Write-Host "Use: Backup-CAKeys -BackupPath <path>" -ForegroundColor Yellow
      Write-Host ""
      $response = Read-Host "Do you want to create a backup now? [y/n]"
      if ($response -eq 'y') {
        try {
          if ([string]::IsNullOrWhiteSpace($BackupPath)) {
            $BackupPath = Join-Path $env:SystemDrive "CA-Backup"
          }
          Backup-CAKeys -BackupPath $BackupPath
        }
        catch {
          Write-Warning "Backup creation failed: $_"
        }
      }
    }
    
    # Configuration export removed for single-use script simplicity
    
    # Clear progress indicator
    Write-Progress -Activity $Script:ProgressActivity -Completed

    #-----------------------------------------------------------------------------------------------------------
    # Phase 11: Completion and Next Steps
    #-----------------------------------------------------------------------------------------------------------
    Report-Status "Root CA Build Completed!" 0 Green
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "ROOT CA INSTALLATION COMPLETE" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "NEXT STEPS FOR SUBCA INSTALLATION:" -ForegroundColor Cyan
    Write-Host "1. Ensure this Root CA server remains ONLINE and accessible" -ForegroundColor Yellow
    Write-Host "2. Verify PSRemoting is enabled (required for SubCA connection)" -ForegroundColor Yellow
    Write-Host "3. Verify CertConfig share (C:\CAConfig) is accessible to SubCA server" -ForegroundColor Yellow
    Write-Host "4. Run Build-SubCA.ps1 on the SubCA server" -ForegroundColor Yellow
    Write-Host "   - The SubCA script will connect to this server via PSRemoting" -ForegroundColor Yellow
    Write-Host "   - It will submit certificate requests and retrieve signed certificates" -ForegroundColor Yellow
    Write-Host "5. After SubCA installation completes, proceed with security hardening below" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "POST-INSTALLATION SECURITY CHECKLIST" -ForegroundColor Yellow
    Write-Host "(Complete AFTER SubCA installation)" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "[ ] Disable PSRemoting (no longer needed after SubCA installation)" -ForegroundColor Yellow
    Write-Host "[ ] Disable all network adapters (physical disconnection preferred)" -ForegroundColor Yellow
    Write-Host "[ ] Disable unnecessary services (Spooler, RemoteRegistry, etc.)" -ForegroundColor Yellow
    Write-Host "[ ] Enable BitLocker disk encryption (if supported)" -ForegroundColor Yellow
    Write-Host "[ ] Verify backups are stored in secure, offline location" -ForegroundColor Yellow
    Write-Host "[ ] Shutdown server and store in physically secure location" -ForegroundColor Yellow
    Write-Host "[ ] Document all access and operations" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT REMINDERS:" -ForegroundColor Cyan
    Write-Host "- This server must remain ONLINE during SubCA installation" -ForegroundColor Yellow
    Write-Host "- Take a VM snapshot now before proceeding with SubCA installation" -ForegroundColor Yellow
    Write-Host "- Only bring this server online when needed (SubCA certs, renewals, revocations, CRL updates)" -ForegroundColor Yellow
    Write-Host ""
    $Script:ExitCode = 0
  }
  catch {
    Write-Error "Failed during CA customization: $_"
    $Script:ExitCode = 1
    throw
  }
}
catch {
  Write-Error "Script execution failed: $_"
  Write-Error "Error details: $($_.Exception.Message)"
  Write-Error "Stack trace: $($_.ScriptStackTrace)"
  $Script:ExitCode = 1
  exit $Script:ExitCode
}
finally {
  # Stop transcript if logging was enabled
  if ($Script:LogPath) {
    try {
      Stop-Transcript -ErrorAction SilentlyContinue
      if ($Script:ExitCode -eq 0) {
        Write-Host "Log file saved: $Script:LogPath" -ForegroundColor Cyan
      }
    }
    catch {
      # Transcript may have already been stopped
    }
  }
  
  # Clear progress indicator
  Write-Progress -Activity $Script:ProgressActivity -Completed -ErrorAction SilentlyContinue
  
  if ($Script:ExitCode -eq 0) {
    Report-Status "Script completed successfully" 0 Green
  }
  else {
    Report-Status "Script completed with errors" 0 Red
    if ($Script:LogPath) {
      Write-Host "Check log file for details: $Script:LogPath" -ForegroundColor Yellow
    }
  }
}

exit $Script:ExitCode
