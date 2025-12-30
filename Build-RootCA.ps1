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
  Version:        3.5
  Author:         Marc Bouchard
  Creation Date:  2021/03/04
  Last Modified:  2025/12/30
  
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
  [Parameter(Mandatory = $false)]
  [switch]$EnablePSRemoting,
    
  # Optional: Create backup automatically after installation
  [Parameter(Mandatory = $false)]
  [switch]$CreateBackup,  # Default: Disabled (prompted if not specified)
    
  # Optional: Custom backup path (defaults to SystemDrive\CA-Backup if not specified)
  [Parameter(Mandatory = $false)]
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
# Function: Read-UserInput
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Enhanced user input prompt with better formatting and validation feedback
  
.DESCRIPTION
  Provides a user-friendly input prompt with:
  - Clear visual separation
  - Example values
  - Validation feedback
  - Help text
  - Better formatting
#>
Function Read-UserInput {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Prompt,
    
    [Parameter(Mandatory = $false)]
    [string]$Example = $null,
    
    [Parameter(Mandatory = $false)]
    [string]$HelpText = $null,
    
    [Parameter(Mandatory = $false)]
    [scriptblock]$Validation = $null,
    
    [Parameter(Mandatory = $false)]
    [string]$DefaultValue = $null
  )
  
  $inputValue = $null
  $isValid = $false
  
  do {
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "INPUT REQUIRED" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host $Prompt -ForegroundColor Yellow
    Write-Host ""
    
    if ($Example) {
      Write-Host "  Example: " -NoNewline -ForegroundColor Gray
      Write-Host $Example -ForegroundColor White
      Write-Host ""
    }
    
    if ($HelpText) {
      Write-Host "  ℹ " -NoNewline -ForegroundColor Cyan
      Write-Host $HelpText -ForegroundColor Gray
      Write-Host ""
    }
    
    if ($DefaultValue) {
      Write-Host "  Default: " -NoNewline -ForegroundColor Gray
      Write-Host $DefaultValue -ForegroundColor White
      Write-Host "  (Press Enter to use default)" -ForegroundColor DarkGray
      Write-Host ""
    }
    
    Write-Host "> " -NoNewline -ForegroundColor Green
    $inputValue = Read-Host
    
    # Use default if provided and input is empty
    if ([string]::IsNullOrWhiteSpace($inputValue) -and $DefaultValue) {
      $inputValue = $DefaultValue
      Write-Host "  Using default value: $DefaultValue" -ForegroundColor Gray
    }
    
    $inputValue = $inputValue.Trim()
    
    # Validate if validation scriptblock provided
    if ($Validation) {
      try {
        $validationResult = & $Validation $inputValue
        if ($validationResult -is [bool] -and $validationResult) {
          $isValid = $true
        }
        elseif ($validationResult -is [string]) {
          # Validation returned error message
          Write-Host ""
          Write-Host "  ✗ " -NoNewline -ForegroundColor Red
          Write-Host $validationResult -ForegroundColor Yellow
          Write-Host ""
        }
        else {
          $isValid = $true
        }
      }
      catch {
        Write-Host ""
        Write-Host "  ✗ " -NoNewline -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host ""
      }
    }
    else {
      # No validation, accept any non-empty input
      if (-not [string]::IsNullOrWhiteSpace($inputValue)) {
        $isValid = $true
      }
      else {
        Write-Host ""
        Write-Host "  ✗ " -NoNewline -ForegroundColor Red
        Write-Host "Input cannot be empty. Please provide a value." -ForegroundColor Yellow
        Write-Host ""
      }
    }
    
    if ($isValid) {
      Write-Host ""
      Write-Host "  ✓ " -NoNewline -ForegroundColor Green
      Write-Host "Accepted: " -NoNewline -ForegroundColor Gray
      Write-Host $inputValue -ForegroundColor White
      Write-Host ""
    }
    
  } while (-not $isValid)
  
  return $inputValue
}

#-----------------------------------------------------------------------------------------------------------
# Function: Read-UserConfirmation
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Enhanced confirmation prompt with better formatting
  
.DESCRIPTION
  Provides a user-friendly yes/no confirmation prompt with clear formatting
#>
Function Read-UserConfirmation {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Message,
    
    [Parameter(Mandatory = $false)]
    [string]$HelpText = $null,
    
    [Parameter(Mandatory = $false)]
    [bool]$DefaultYes = $false
  )
  
  $defaultText = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
  $response = $null
  
  Write-Host ""
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
  Write-Host "CONFIRMATION REQUIRED" -ForegroundColor Cyan
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
  Write-Host ""
  Write-Host $Message -ForegroundColor Yellow
  Write-Host ""
  
  if ($HelpText) {
    Write-Host "  ℹ " -NoNewline -ForegroundColor Cyan
    Write-Host $HelpText -ForegroundColor Gray
    Write-Host ""
  }
  
  do {
    Write-Host "  Continue? $defaultText " -NoNewline -ForegroundColor Cyan
    $response = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($response) -and $DefaultYes) {
      $response = 'y'
    }
    elseif ([string]::IsNullOrWhiteSpace($response)) {
      $response = 'n'
    }
    
    $response = $response.ToLower().Trim()
    
    if ($response -notin @('y', 'yes', 'n', 'no')) {
      Write-Host "  Please enter 'y' for yes or 'n' for no" -ForegroundColor Yellow
    }
  } while ($response -notin @('y', 'yes', 'n', 'no'))
  
  Write-Host ""
  
  return ($response -in @('y', 'yes'))
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
          $continue = Read-UserConfirmation `
            -Message "Do you want to continue anyway? This may cause conflicts." `
            -HelpText "Continuing may overwrite or conflict with existing CA configuration."
          if (-not $continue) {
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
    
    # Verify ADCS PowerShell modules will be available after feature installation
    # ADCSDeployment and ADCSAdministration modules are installed with ADCS-Cert-Authority feature
    Report-Status "Required Windows features available: OK" 0 Green
    Report-Status "ADCS PowerShell modules (ADCSDeployment, ADCSAdministration) will be available after feature installation" 0 Green
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
    [Parameter(Mandatory = $true)][string]$RootCAName,
    [Parameter(Mandatory = $true)][string]$OID,
    [Parameter(Mandatory = $true)][string]$httpCRLPath
  )
  
  $errors = @()
  
  # Validate CA Common Name: not empty, max 64 chars, alphanumeric + hyphens/underscores/dots/spaces only
  if ([string]::IsNullOrWhiteSpace($RootCAName)) {
    $errors += "CA Common Name cannot be empty."
  }
  elseif ($RootCAName.Length -gt 64) {
    $errors += "CA Common Name cannot exceed 64 characters. Current length: $($RootCAName.Length)"
  }
  elseif ($RootCAName -notmatch '^[a-zA-Z0-9_\.\s-]+$') {
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
  else {
    # Simplified FQDN validation - basic pattern matching to avoid PowerShell parsing issues
    # Allow alphanumeric, hyphens, dots; must start and end with alphanumeric
    $isValid = $true
    
    # Basic checks: length, characters, and structure
    if ($httpCRLPath.Length -lt 3 -or $httpCRLPath.Length -gt 255) {
      $isValid = $false
    }
    elseif ($httpCRLPath -notmatch '^[a-zA-Z0-9]' -or $httpCRLPath -notmatch '[a-zA-Z0-9]$') {
      # Must start and end with alphanumeric
      $isValid = $false
    }
    elseif ($httpCRLPath -match '[^a-zA-Z0-9.-]') {
      # Contains invalid characters (only alphanumeric, dots, hyphens allowed)
      $isValid = $false
    }
    elseif ($httpCRLPath -match '\.\.' -or $httpCRLPath -match '--' -or $httpCRLPath.StartsWith('.') -or $httpCRLPath.StartsWith('-')) {
      # No consecutive dots, consecutive hyphens, or starting with dot/hyphen
      $isValid = $false
    }
    
    if (-not $isValid) {
      $errors += "CRL URL path appears to be invalid. Expected format: pki.mycompany.com or similar FQDN."
    }
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
  Safely imports ADCS PowerShell modules if available with retry logic
  
.DESCRIPTION
  Attempts to import both ADCSDeployment and ADCSAdministration modules which contain ADCS cmdlets.
  - ADCSDeployment: Contains Install-AdcsCertificationAuthority, Get-CertificationAuthority
  - ADCSAdministration: Contains Get-CACrlDistributionPoint, Add-CACRLDistributionPoint, Get-CAAuthorityInformationAccess, etc.
  
  Includes retry logic for post-reboot scenarios where modules may not be immediately available.
  Returns $true if both modules are available and imported, $false otherwise.
  This is safe to call even if the modules are not available yet, for example before feature installation.
#>
Function Import-ADCSModule {
  param(
    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 5,
    
    [Parameter(Mandatory = $false)]
    [int]$RetryDelaySeconds = 3
  )
  
  try {
    $retryCount = 0
    $requiredModules = @('ADCSDeployment', 'ADCSAdministration')
    
    while ($retryCount -lt $MaxRetries) {
      # Refresh module list (important after reboot)
      if ($retryCount -gt 0) {
        Write-Verbose "Refreshing module list (attempt $($retryCount + 1)/$MaxRetries)..."
        # Force refresh by clearing module cache
        Get-Module -ListAvailable -Refresh -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds $RetryDelaySeconds
      }
      
      $allModulesAvailable = $true
      $importedModules = @()
      
      # Check and import each required module
      foreach ($moduleName in $requiredModules) {
        $moduleAvailable = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
        if ($moduleAvailable) {
          Write-Verbose "$moduleName module found in module list"
          
          # Import if not already loaded
          if (-not (Get-Module -Name $moduleName -ErrorAction SilentlyContinue)) {
            Write-Verbose "Importing $moduleName module..."
            Import-Module $moduleName -ErrorAction Stop
          }
          else {
            Write-Verbose "$moduleName module already loaded"
          }
          
          $importedModules += $moduleName
        }
        else {
          Write-Verbose "$moduleName module not found in module list (attempt $($retryCount + 1)/$MaxRetries)"
          $allModulesAvailable = $false
        }
      }
      
      # Verify key cmdlets are available from both modules
      if ($allModulesAvailable) {
        $deploymentCmdlet = Get-Command Get-CertificationAuthority -ErrorAction SilentlyContinue
        $administrationCmdlet = Get-Command Get-CACrlDistributionPoint -ErrorAction SilentlyContinue
        
        if ($deploymentCmdlet -and $administrationCmdlet) {
          Write-Verbose "All ADCS modules and cmdlets verified successfully"
          Write-Verbose "  Imported modules: $($importedModules -join ', ')"
          return $true
        }
        else {
          Write-Verbose "Modules imported but some cmdlets not available yet"
          if (-not $deploymentCmdlet) {
            Write-Verbose "  Missing: Get-CertificationAuthority (from ADCSDeployment)"
          }
          if (-not $administrationCmdlet) {
            Write-Verbose "  Missing: Get-CACrlDistributionPoint (from ADCSAdministration)"
          }
        }
      }
      
      $retryCount++
    }
    
    Write-Verbose "Failed to import ADCS modules after $MaxRetries attempts"
    Write-Verbose "Required modules: $($requiredModules -join ', ')"
    Write-Verbose "Available modules: $((Get-Module -ListAvailable -Name $requiredModules -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) -join ', ')"
    return $false
  }
  catch {
    Write-Verbose "Error importing ADCS modules: $_"
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
# Function: Test-PostRebootScenario
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Detects if script is being run after a reboot (post-reboot scenario)
  
.DESCRIPTION
  Returns $true if:
  - CAPolicy.inf exists (configuration was started)
  - ADCS feature is installed (reboot completed feature installation)
  - CA is NOT fully installed yet (installation was interrupted)
  
  This indicates the script should skip the disclaimer and resume installation.
#>
Function Test-PostRebootScenario {
  try {
    # Check if CAPolicy.inf exists (indicates previous execution)
    if (-not (Test-CAPolicyExists)) {
      return $false
    }
    
    # Check if ADCS feature is installed (indicates post-reboot)
    try {
      if (-not (Get-Module -ListAvailable -Name ServerManager -ErrorAction SilentlyContinue)) {
        return $false
      }
      
      if (-not (Get-Module -Name ServerManager -ErrorAction SilentlyContinue)) {
        Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
      }
      
      $feature = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue
      if ($feature -and $feature.InstallState -eq 'Installed') {
        # Feature is installed, check if CA is fully configured
        if (-not (Test-CAInstalled)) {
          # CAPolicy.inf exists, feature installed, but CA not configured = post-reboot scenario
          return $true
        }
      }
    }
    catch {
      # If we can't check, assume not post-reboot
      return $false
    }
    
    return $false
  }
  catch {
    return $false
  }
}

#-----------------------------------------------------------------------------------------------------------
# Function: Test-CAPolicyInfComplete
#-----------------------------------------------------------------------------------------------------------
<#
.SYNOPSIS
  Validates that CAPolicy.inf file is complete and properly formatted
  
.DESCRIPTION
  Checks that CAPolicy.inf contains all required sections and values:
  - [Version] section
  - [PolicyStatementExtension] section
  - [InternalPolicy] section with OID and URL
  - [Certsrv_Server] section with required settings
  
  Returns $true if file is complete, $false otherwise.
#>
Function Test-CAPolicyInfComplete {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  
  try {
    if (-not (Test-Path $Path)) {
      return $false
    }
    
    $content = Get-Content $Path -Raw
    
    # Check for required sections
    $requiredSections = @(
      '\[Version\]',
      '\[PolicyStatementExtension\]',
      '\[InternalPolicy\]',
      '\[Certsrv_Server\]'
    )
    
    foreach ($section in $requiredSections) {
      if ($content -notmatch $section) {
        Write-Verbose "CAPolicy.inf missing required section: $section"
        return $false
      }
    }
    
    # Check for required values in [InternalPolicy]
    if ($content -notmatch 'OID\s*=\s*1\.3\.6\.1\.4\.1\.\d{5}') {
      Write-Verbose "CAPolicy.inf missing or invalid OID"
      return $false
    }
    
    if ($content -notmatch 'URL=http://[^\s]+') {
      Write-Verbose "CAPolicy.inf missing or invalid URL"
      return $false
    }
    
    # Check for required values in [Certsrv_Server]
    if ($content -notmatch 'RenewalKeyLength=\d+') {
      Write-Verbose "CAPolicy.inf missing RenewalKeyLength"
      return $false
    }
    
    if ($content -notmatch 'RenewalValidityPeriod=Years') {
      Write-Verbose "CAPolicy.inf missing RenewalValidityPeriod"
      return $false
    }
    
    if ($content -notmatch 'RenewalValidityPeriodUnits=\d+') {
      Write-Verbose "CAPolicy.inf missing RenewalValidityPeriodUnits"
      return $false
    }
    
    if ($content -notmatch 'CRLPeriod=Years') {
      Write-Verbose "CAPolicy.inf missing CRLPeriod"
      return $false
    }
    
    if ($content -notmatch 'CRLPeriodUnits=\d+') {
      Write-Verbose "CAPolicy.inf missing CRLPeriodUnits"
      return $false
    }
    
    return $true
  }
  catch {
    Write-Verbose "Error validating CAPolicy.inf: $_"
    return $false
  }
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
    [Parameter(Mandatory = $true)]
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
    [Parameter(Mandatory = $true)][string]$OID,
    [Parameter(Mandatory = $true)][string]$httpCRLPath,
    [Parameter(Mandatory = $false)][int]$KeyLength = 4096,
    [Parameter(Mandatory = $false)][int]$CAValidityYears = 10,
    [Parameter(Mandatory = $false)][int]$CRLPeriodYears = 1
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
    [Parameter(Mandatory = $true)]
    [string]$Path,
        
    [Parameter(Mandatory = $false)]
    [hashtable]$AdditionalConfig = @{}
  )
    
  try {
    $config = @{
      RootCAName               = $RootCAName
      OID                      = $OID
      httpCRLPath              = $httpCRLPath
      HashAlgorithm            = $script:HashAlgorithm
      KeyLength                = $script:KeyLength
      CAValidityYears          = $script:CAValidityYears
      CRLPeriodYears           = $script:CRLPeriodYears
      CertificateValidityYears = $script:CertificateValidityYears
      CryptoProvider           = $script:CryptoProvider
      HSMProviderName          = $script:HSMProviderName
      ExportDate               = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
      ExportComputer           = $env:COMPUTERNAME
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
    [Parameter(Mandatory = $true)]
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
  param([Parameter(Mandatory = $true)][string]$BackupPath)
  
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
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host " CA BACKUP PASSWORD REQUIRED" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Enter a strong password to protect the CA private key backup." -ForegroundColor White
    Write-Host ""
    Write-Host "  ⚠ " -NoNewline -ForegroundColor Red
    Write-Host "IMPORTANT: Store this password securely and separately from the backup!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Requirements:" -ForegroundColor Cyan
    Write-Host "    • Minimum 12 characters" -ForegroundColor Gray
    Write-Host "    • Use a strong, unique password" -ForegroundColor Gray
    Write-Host "    • Store password separately from backup files" -ForegroundColor Gray
    Write-Host ""
    
    $passwordMatch = $false
    do {
      Write-Host "  Enter backup password: " -NoNewline -ForegroundColor Yellow
      $backupPassword = Read-Host -AsSecureString
      
      Write-Host "  Confirm backup password: " -NoNewline -ForegroundColor Yellow
      $backupPasswordConfirm = Read-Host -AsSecureString
      
      # Validate password match and strength (convert to plain text temporarily for validation)
      $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($backupPassword)
      $plainPassword1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
      $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($backupPasswordConfirm)
      $plainPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
      
      $validationError = $null
      
      if ($plainPassword1 -ne $plainPassword2) {
        $validationError = "Passwords do not match. Please try again."
      }
      elseif ($plainPassword1.Length -lt 12) {
        $validationError = "Backup password must be at least 12 characters long. Current length: $($plainPassword1.Length)"
      }
      
      # Clear plain text passwords from memory immediately
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
      [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
      Remove-Variable plainPassword1, plainPassword2 -ErrorAction SilentlyContinue
      
      if ($validationError) {
        Write-Host ""
        Write-Host "  ✗ " -NoNewline -ForegroundColor Red
        Write-Host $validationError -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Please try again." -ForegroundColor Gray
        Write-Host ""
      }
      else {
        Write-Host ""
        Write-Host "  ✓ " -NoNewline -ForegroundColor Green
        Write-Host "Password accepted" -ForegroundColor Gray
        Write-Host ""
        $passwordMatch = $true
      }
    } while (-not $passwordMatch)
    
    # Find CA certificate - try multiple methods to locate it
    Write-Verbose "Searching for CA certificate with name: $caName"
    $caCert = $null
    
    # Method 1: Search by CA name in Subject
    $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
      $_.Subject -like "*CN=$caName*" -or $_.Subject -like "*$caName*"
    } | Select-Object -First 1
    
    # Method 2: If not found, try to get certificate from CA configuration
    if (-not $caCert) {
      Write-Verbose "Certificate not found by name, trying to get from CA configuration..."
      try {
        $caCertThumbprint = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName" -Name "CACertHash" -ErrorAction SilentlyContinue).CACertHash
        if ($caCertThumbprint) {
          $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $caCertThumbprint } | Select-Object -First 1
        }
      }
      catch {
        Write-Verbose "Could not get certificate from registry: $_"
      }
    }
    
    # Method 3: Get the most recent certificate in the My store (should be the CA cert if only one)
    if (-not $caCert) {
      Write-Verbose "Trying to get most recent certificate from My store..."
      $allCerts = Get-ChildItem Cert:\LocalMachine\My | Sort-Object NotBefore -Descending
      if ($allCerts.Count -eq 1) {
        $caCert = $allCerts[0]
        Write-Verbose "Using only certificate found in My store: $($caCert.Subject)"
      }
      elseif ($allCerts.Count -gt 1) {
        Write-Warning "Multiple certificates found in My store. Attempting to identify CA certificate..."
        # Try to find certificate that has CA extensions
        foreach ($cert in $allCerts) {
          $extensions = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -like "*CA*" -or $_.Oid.Value -eq "2.5.29.19" }
          if ($extensions) {
            $caCert = $cert
            Write-Verbose "Found CA certificate by extension: $($caCert.Subject)"
            break
          }
        }
      }
    }
    
    if (-not $caCert) {
      Write-Error "Available certificates in LocalMachine\My store:"
      Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
        Write-Error "  Subject: $($_.Subject), Thumbprint: $($_.Thumbprint)"
      }
      throw "Could not find CA certificate in certificate store. CA Name: $caName"
    }
    
    Write-Verbose "Found CA certificate: $($caCert.Subject), Thumbprint: $($caCert.Thumbprint)"
    
    # Verify certificate has private key
    if (-not $caCert.HasPrivateKey) {
      throw "CA certificate found but does not have a private key. Cannot export PFX file."
    }
    
    # Export CA certificate with private key (PFX)
    $pfxPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.pfx"
    try {
      Export-PfxCertificate -Cert $caCert -FilePath $pfxPath -Password $backupPassword -ErrorAction Stop
      if (-not (Test-Path $pfxPath)) {
        throw "PFX file was not created at $pfxPath"
      }
      $pfxSize = (Get-Item $pfxPath).Length
      $pfxSizeKB = [math]::Round($pfxSize / 1024, 2)
      $pfxSizeMsg = $pfxPath + " (" + $pfxSizeKB.ToString() + " KB)"
      Report-Status "CA certificate with private key exported: $pfxSizeMsg" 0 Green
    }
    catch {
      Write-Error "Failed to export PFX certificate: $_"
      throw
    }
    
    # Export CA certificate without private key (CER)
    $cerPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.cer"
    try {
      Export-Certificate -Cert $caCert -FilePath $cerPath -Type CERT -ErrorAction Stop
      if (-not (Test-Path $cerPath)) {
        throw "CER file was not created at $cerPath"
      }
      $cerSize = (Get-Item $cerPath).Length
      $cerSizeKB = [math]::Round($cerSize / 1024, 2)
      $cerSizeMsg = $cerPath + " (" + $cerSizeKB.ToString() + " KB)"
      Report-Status "CA certificate (public key) exported: $cerSizeMsg" 0 Green
    }
    catch {
      Write-Error "Failed to export CER certificate: $_"
      throw
    }
    
    # Backup CA database
    $dbPath = Join-Path $env:SystemRoot "System32\CertLog"
    if (Test-Path $dbPath) {
      try {
        $dbBackupPath = Join-Path $BackupPath "CADatabase-$timestamp"
        Copy-Item -Path $dbPath -Destination $dbBackupPath -Recurse -Force -ErrorAction Stop
        if (-not (Test-Path $dbBackupPath)) {
          throw "Database backup directory was not created at $dbBackupPath"
        }
        $dbSize = (Get-ChildItem $dbBackupPath -Recurse | Measure-Object -Property Length -Sum).Sum
        $dbSizeKB = [math]::Round($dbSize / 1024, 2)
        $dbSizeMsg = $dbBackupPath + " (" + $dbSizeKB.ToString() + " KB)"
        Report-Status "CA database backed up to: $dbSizeMsg" 0 Green
      }
      catch {
        Write-Warning "Failed to backup CA database: $_"
        Write-Warning "Continuing with certificate backup only..."
      }
    }
    else {
      Write-Warning "CA database path not found: $dbPath"
      Write-Warning "Database backup skipped. This may be normal if CA was just installed."
    }
    
    # Create backup manifest
    $manifestPath = Join-Path $BackupPath "Backup-Manifest-$timestamp.txt"
    $manifest = @"
Root CA Backup Manifest
=======================
Backup Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
CA Name: $caName
CA Type: $($caConfig.CAType)
Certificate Subject: $($caCert.Subject)
Certificate Thumbprint: $($caCert.Thumbprint)

Backup Files:
- PFX (Certificate + Private Key): RootCA-$caName-$timestamp.pfx
- CER (Certificate Only): RootCA-$caName-$timestamp.cer
- Database: CADatabase-$timestamp

File Verification:
$(if (Test-Path $pfxPath) { $pfxManifestSize = (Get-Item $pfxPath).Length; $pfxManifestSizeKB = [math]::Round($pfxManifestSize / 1024, 2); $pfxManifestMsg = $pfxManifestSizeKB.ToString() + " KB"; "- PFX file exists: YES (" + $pfxManifestMsg + ")" } else { "- PFX file exists: NO" })
$(if (Test-Path $cerPath) { $cerManifestSize = (Get-Item $cerPath).Length; $cerManifestSizeKB = [math]::Round($cerManifestSize / 1024, 2); $cerManifestMsg = $cerManifestSizeKB.ToString() + " KB"; "- CER file exists: YES (" + $cerManifestMsg + ")" } else { "- CER file exists: NO" })
$(if (Test-Path (Join-Path $BackupPath "CADatabase-$timestamp")) { "- Database backup exists: YES" } else { "- Database backup exists: NO" })

IMPORTANT SECURITY NOTES:
- Store backups in secure, offline location
- Use multiple backup locations (different physical locations)
- Protect backup password (store separately from backups)
- Verify backup integrity before going offline
- Test restore procedures regularly

"@
    try {
      $manifest | Out-File $manifestPath -Encoding UTF8 -ErrorAction Stop
      if (-not (Test-Path $manifestPath)) {
        throw "Manifest file was not created"
      }
      Report-Status "Backup manifest created: $manifestPath" 0 Green
    }
    catch {
      Write-Warning "Failed to create backup manifest: $_"
    }
    
    # Verify all backup files exist
    Write-Host ""
    Report-Status "Verifying backup files..." 0 Cyan
    $allFilesExist = $true
    if (-not (Test-Path $pfxPath)) {
      Write-Error "PFX file missing: $pfxPath"
      $allFilesExist = $false
    }
    if (-not (Test-Path $cerPath)) {
      Write-Error "CER file missing: $cerPath"
      $allFilesExist = $false
    }
    
    if (-not $allFilesExist) {
      throw "Backup verification failed. Some files were not created."
    }
    
    Report-Status "All backup files verified successfully" 0 Green
    
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
  # Detect post-reboot scenario (skip disclaimer if resuming after reboot)
  $isPostReboot = Test-PostRebootScenario
  $capolicyPath = Join-Path $env:SystemRoot "CAPolicy.inf"
  
  if ($isPostReboot) {
    # Post-reboot scenario: Skip disclaimer, validate INF file, and resume
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "RESUMING ROOT CA INSTALLATION" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Report-Status "Detected post-reboot scenario. Resuming installation..." 0 Cyan
    Write-Host ""
    
    # Validate CAPolicy.inf is complete
    if (Test-CAPolicyInfComplete -Path $capolicyPath) {
      Report-Status "CAPolicy.inf file validated: Complete and properly formatted" 0 Green
      Write-Host "  File: $capolicyPath" -ForegroundColor Gray
    }
    else {
      Write-Error "CAPolicy.inf file exists but is incomplete or corrupted."
      Write-Error "File location: $capolicyPath"
      Write-Error ""
      Write-Error "Please review the file and fix any issues, or delete it to start fresh."
      throw "CAPolicy.inf validation failed. Cannot resume installation."
    }
    Write-Host ""
  }
  else {
    # First run: Show disclaimer
    Show-Disclaimer
    Clear-Host
  }
  
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
    $continue = Read-UserConfirmation `
      -Message "Do you want to continue with configuration changes?" `
      -HelpText "The script will proceed with configuration updates to the existing CA."
    if (-not $continue) {
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
    $enableNow = Read-UserConfirmation `
      -Message "Do you want to enable PSRemoting now?" `
      -HelpText "PSRemoting is required for SubCA installation. It can be disabled after SubCA installation completes." `
      -DefaultYes $true
    if ($enableNow) {
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
          $RootCAName = Read-UserInput `
            -Prompt "CA Name not found. Please provide the Common Name for the Root CA:" `
            -Example "Corp-Root-CA" `
            -HelpText "This will be the display name of your Root Certificate Authority" `
            -Validation {
            param($value)
            if ([string]::IsNullOrWhiteSpace($value)) {
              return "CA Common Name cannot be empty."
            }
            if ($value.Length -gt 64) {
              return "CA Common Name cannot exceed 64 characters. Current length: $($value.Length)"
            }
            if ($value -notmatch '^[a-zA-Z0-9_\.\s-]+$') {
              return "CA Common Name contains invalid characters. Only alphanumeric, hyphens, underscores, dots, and spaces are allowed."
            }
            return $true
          }
        }
      }
      else {
        # Module not available, need CA name
        $RootCAName = Read-UserInput `
          -Prompt "CA Name not available. Please provide the Common Name for the Root CA:" `
          -Example "Corp-Root-CA" `
          -HelpText "This will be the display name of your Root Certificate Authority" `
          -Validation {
          param($value)
          if ([string]::IsNullOrWhiteSpace($value)) {
            return "CA Common Name cannot be empty."
          }
          if ($value.Length -gt 64) {
            return "CA Common Name cannot exceed 64 characters. Current length: $($value.Length)"
          }
          if ($value -notmatch '^[a-zA-Z0-9_\.\s-]+$') {
            return "CA Common Name contains invalid characters. Only alphanumeric, hyphens, underscores, dots, and spaces are allowed."
          }
          return $true
        }
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
    $confirmed = $false
    
    do {
      Write-Host ""
      Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
      Write-Host " ROOT CA CONFIGURATION" -ForegroundColor Cyan
      Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
      Write-Host ""
      Write-Host "Please provide the following information to configure your Root CA:" -ForegroundColor White
      Write-Host ""
      
      # Collect CA Common Name
      $RootCAName = Read-UserInput `
        -Prompt "Enter the Common Name for the Root CA:" `
        -Example "Corp-Root-CA" `
        -HelpText "This will be the display name of your Root Certificate Authority. Maximum 64 characters." `
        -Validation {
        param($value)
        if ([string]::IsNullOrWhiteSpace($value)) {
          return "CA Common Name cannot be empty."
        }
        if ($value.Length -gt 64) {
          return "CA Common Name cannot exceed 64 characters. Current length: $($value.Length)"
        }
        if ($value -notmatch '^[a-zA-Z0-9_\.\s-]+$') {
          return "CA Common Name contains invalid characters. Only alphanumeric, hyphens, underscores, dots, and spaces are allowed."
        }
        return $true
      }
      
      # Collect OID
      $OID = Read-UserInput `
        -Prompt "Enter your 5-digit OID (Private Enterprise Number from IANA):" `
        -Example "12345" `
        -HelpText "This is your IANA-assigned Private Enterprise Number (PEN). Must be exactly 5 digits." `
        -Validation {
        param($value)
        if ($value -notmatch '^\d{5}$') {
          return "OID must be exactly 5 digits. Provided: $value"
        }
        return $true
      }
      
      # Collect CRL URL
      $httpCRLPath = Read-UserInput `
        -Prompt "Enter the URL where CRL files will be located:" `
        -Example "pki.mycompany.com" `
        -HelpText "This is the FQDN where your CRL files will be published. Clients will access CRLs at http://[this-url]/certenroll/" `
        -Validation {
        param($value)
        if ([string]::IsNullOrWhiteSpace($value)) {
          return "CRL URL path cannot be empty."
        }
        # Simplified FQDN validation - basic pattern matching to avoid PowerShell parsing issues
        # Allow alphanumeric, hyphens, dots; must start and end with alphanumeric
        $isValid = $true
          
        # Basic checks: length, characters, and structure
        if ($value.Length -lt 3 -or $value.Length -gt 255) {
          $isValid = $false
        }
        elseif ($value -notmatch '^[a-zA-Z0-9]' -or $value -notmatch '[a-zA-Z0-9]$') {
          # Must start and end with alphanumeric
          $isValid = $false
        }
        elseif ($value -match '[^a-zA-Z0-9.-]') {
          # Contains invalid characters (only alphanumeric, dots, hyphens allowed)
          $isValid = $false
        }
        elseif ($value -match '\.\.' -or $value -match '--' -or $value.StartsWith('.') -or $value.StartsWith('-')) {
          # No consecutive dots, consecutive hyphens, or starting with dot/hyphen
          $isValid = $false
        }
          
        if (-not $isValid) {
          return "CRL URL path appears to be invalid. Expected format: pki.mycompany.com or similar FQDN."
        }
        return $true
      }
      
      # Display summary and confirm
      Write-Host ""
      Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
      Write-Host " CONFIGURATION SUMMARY" -ForegroundColor Green
      Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
      Write-Host ""
      Write-Host "  CA Common Name: " -NoNewline -ForegroundColor Gray
      Write-Host $RootCAName -ForegroundColor White
      Write-Host "  OID           : " -NoNewline -ForegroundColor Gray
      Write-Host $OID -ForegroundColor White
      Write-Host "  CRL URL Path  : " -NoNewline -ForegroundColor Gray
      Write-Host $httpCRLPath -ForegroundColor White
      Write-Host ""
      
      $confirmed = Read-UserConfirmation `
        -Message "Are you satisfied with these values?" `
        -HelpText "If yes, the script will proceed with CA installation using these values."
      
      Write-Verbose "User input validation passed"
      
    } while (-not $confirmed)
  }

  #-----------------------------------------------------------------------------------------------------------
  # Phase 5: CAPolicy.inf Creation
  #-----------------------------------------------------------------------------------------------------------
  # Create CAPolicy.inf file - This file is read by Windows CA during installation
  # It defines CA policy, OID, CRL settings, and renewal parameters
  # Must be created BEFORE installing the CA role
  $Script:CurrentPhase = 3
  Write-Progress -Activity $Script:ProgressActivity -Status $Script:ProgressPhases[$Script:CurrentPhase] -PercentComplete (($Script:CurrentPhase / $Script:ProgressPhases.Count) * 100)
  
  # In post-reboot scenario, INF file is already validated - skip creation/editing
  if ($isPostReboot -and (Test-CAPolicyInfComplete -Path $capolicyPath)) {
    Report-Status "Using existing CAPolicy.inf file (validated in post-reboot check)" 0 Green
    Write-Host "  File: $capolicyPath" -ForegroundColor Gray
    if ($existingCAPolicy) {
      Write-Host "  OID: $OID" -ForegroundColor Gray
      Write-Host "  CRL URL: $httpCRLPath" -ForegroundColor Gray
    }
    # Skip file display and editing prompts in post-reboot scenario
  }
  else {
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
          $overwrite = Read-UserConfirmation `
            -Message "Do you want to overwrite the existing CAPolicy.inf file with new values?" `
            -HelpText "The existing file will be replaced with the new configuration."
        
          if (-not $overwrite) {
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

      # Display file and allow editing (skip in post-reboot scenario)
      if (-not $isPostReboot) {
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host " CAPolicy.inf FILE CONTENTS" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Get-Content $capolicyPath | ForEach-Object {
          Write-Host "  $_" -ForegroundColor Gray
        }
        Write-Host ""
        
        $editFile = Read-UserConfirmation `
          -Message "Would you like to edit CAPolicy.inf?" `
          -HelpText "This will open the file in Notepad for manual editing."
        
        if ($editFile) {
          try {
            Start-Process -Wait -FilePath "notepad.exe" -ArgumentList $capolicyPath -ErrorAction Stop
            Report-Status "CAPolicy.inf editing completed" 0 Green
          }
          catch {
            Write-Warning "Could not open notepad. Please edit $capolicyPath manually."
          }
        }
      }
    }
    catch {
      Write-Error "Failed to create CAPolicy.inf: $_"
      throw
    }
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
  
  # Verify ADCS PowerShell modules are available (installed with ADCS-Cert-Authority feature)
  # ADCSDeployment: Provides Install-AdcsCertificationAuthority, Get-CertificationAuthority
  # ADCSAdministration: Provides Get-CACrlDistributionPoint, Add-CACRLDistributionPoint, Get-CAAuthorityInformationAccess, etc.
  # After reboot, modules may need time to become available - use retry logic
  Report-Status "Verifying ADCS PowerShell modules availability..." 0 Cyan
  try {
    # Try to import module with retry logic (important after reboot)
    if (-not (Import-ADCSModule -MaxRetries 5 -RetryDelaySeconds 3)) {
      Write-Host ""
      Write-Host "========================================" -ForegroundColor Yellow
      Write-Host "ADCS MODULE NOT AVAILABLE" -ForegroundColor Yellow
      Write-Host "========================================" -ForegroundColor Yellow
      Write-Host ""
      Write-Host "The ADCS PowerShell module is not available even though the feature is installed." -ForegroundColor Cyan
      Write-Host ""
      Write-Host "TROUBLESHOOTING STEPS:" -ForegroundColor Green
      Write-Host "1. Close this PowerShell session and open a NEW PowerShell window" -ForegroundColor Yellow
      Write-Host "   (The module may require a fresh PowerShell session after reboot)" -ForegroundColor Gray
      Write-Host "2. Run the script again in the new PowerShell session" -ForegroundColor Yellow
      Write-Host "3. If still not available, verify the feature installation:" -ForegroundColor Yellow
      Write-Host "   Get-WindowsFeature ADCS-Cert-Authority" -ForegroundColor White
      Write-Host "4. Manually import the modules to test:" -ForegroundColor Yellow
      Write-Host "   Import-Module ADCSDeployment" -ForegroundColor White
      Write-Host "   Import-Module ADCSAdministration" -ForegroundColor White
      Write-Host "5. Verify both modules are installed:" -ForegroundColor Yellow
      Write-Host "   Get-Module -ListAvailable -Name ADCSDeployment,ADCSAdministration" -ForegroundColor White
      Write-Host ""
      throw "ADCS PowerShell modules are not available. Both ADCSDeployment and ADCSAdministration modules are required. Please restart PowerShell and try again."
    }
    
    # Verify Install-AdcsCertificationAuthority cmdlet is available
    if (-not (Get-Command Install-AdcsCertificationAuthority -ErrorAction SilentlyContinue)) {
      throw "Install-AdcsCertificationAuthority cmdlet is not available. Ensure ADCS-Cert-Authority feature is installed."
    }
    
    Report-Status "ADCS PowerShell modules verified and ready" 0 Green
    Write-Verbose "  ADCSDeployment: $(if (Get-Module ADCSDeployment) { 'Loaded' } else { 'Not loaded' })"
    Write-Verbose "  ADCSAdministration: $(if (Get-Module ADCSAdministration) { 'Loaded' } else { 'Not loaded' })"
  }
  catch {
    Write-Error "ADCS PowerShell modules check failed: $_"
    Write-Error "Both ADCSDeployment and ADCSAdministration modules should be available after installing ADCS-Cert-Authority feature with -IncludeManagementTools."
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
      
      # Import ADCS module to verify installation (with retry after installation)
      Report-Status "Verifying CA installation..." 0 Cyan
      if (-not (Import-ADCSModule -MaxRetries 3 -RetryDelaySeconds 2)) {
        Write-Host ""
        Write-Host "WARNING: ADCS module not immediately available after CA installation." -ForegroundColor Yellow
        Write-Host "This may be normal. Attempting to verify CA installation..." -ForegroundColor Yellow
        Write-Host ""
        
        # Try one more time with longer delay
        Start-Sleep -Seconds 5
        if (-not (Import-ADCSModule -MaxRetries 2 -RetryDelaySeconds 5)) {
          Write-Host ""
          Write-Host "========================================" -ForegroundColor Yellow
          Write-Host "ADCS MODULE NOT AVAILABLE" -ForegroundColor Yellow
          Write-Host "========================================" -ForegroundColor Yellow
          Write-Host ""
          Write-Host "The CA installation may have completed, but the modules are not available." -ForegroundColor Cyan
          Write-Host "Please close this PowerShell session and open a NEW one, then verify:" -ForegroundColor Yellow
          Write-Host "  Import-Module ADCSDeployment" -ForegroundColor White
          Write-Host "  Import-Module ADCSAdministration" -ForegroundColor White
          Write-Host "  Get-CertificationAuthority" -ForegroundColor White
          Write-Host ""
          throw "ADCS modules are not available after installation. Both ADCSDeployment and ADCSAdministration are required. Please restart PowerShell and verify CA installation."
        }
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
        @{Path = "CA\CRLPeriodUnits"; Value = "$script:CRLPeriodYears" },  # 1-2 years for offline CA
        @{Path = "CA\CRLPeriod"; Value = "Years" },
        @{Path = "CA\CRLDeltaPeriodUnits"; Value = "7" },  # Weekly delta CRL
        @{Path = "CA\CRLDeltaPeriod"; Value = "Days" },
        @{Path = "CA\CRLOverlapPeriodUnits"; Value = "2" },  # 2-week overlap
        @{Path = "CA\CRLOverlapPeriod"; Value = "Weeks" },
        @{Path = "CA\ValidityPeriodUnits"; Value = "$script:CertificateValidityYears" },  # 1-2 years for issued certs
        @{Path = "CA\ValidityPeriod"; Value = "Years" },
        @{Path = "CA\AuditFilter"; Value = "127" }  # All audit events (binary: 01111111)
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
      $continue = Read-UserConfirmation `
        -Message "Continue anyway despite validation warnings/errors?" `
        -HelpText "The CA may not be fully configured. Review the validation results above before continuing."
      if (-not $continue) {
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
        $continue = Read-UserConfirmation `
          -Message "Continue without backup?" `
          -HelpText "WARNING: Proceeding without backup is not recommended. The CA private key will not be backed up." `
          -DefaultYes $false
        if (-not $continue) {
          throw "Backup is required. Please fix backup issues and try again."
        }
      }
    }
    else {
      Write-Host ""
      Write-Host "WARNING: Backup was not created!" -ForegroundColor Red
      Write-Host "CRITICAL: Create a backup of the CA certificate and private key before going offline!" -ForegroundColor Yellow
      Write-Host ""
      $createBackup = Read-UserConfirmation `
        -Message "Do you want to create a backup now?" `
        -HelpText "This will create a password-protected backup of the CA certificate, private key, and database." `
        -DefaultYes $true
      if ($createBackup) {
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
    
    #-----------------------------------------------------------------------------------------------------------
    # Phase 11: Automatic Configuration Backup
    #-----------------------------------------------------------------------------------------------------------
    # Automatically export configuration to JSON file for documentation and future reference
    # This is done automatically after successful installation
    Report-Status "Creating configuration backup..." 0 Cyan
    try {
      $configBackupDir = Join-Path $env:ProgramData "PKI\Config"
      if (-not (Test-Path $configBackupDir)) {
        New-Item -ItemType Directory -Path $configBackupDir -Force -ErrorAction Stop | Out-Null
      }
      
      $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
      $configBackupPath = Join-Path $configBackupDir "RootCA-Config-$timestamp.json"
      
      # Ensure configuration variables are set (try to get from CA if not set)
      if ([string]::IsNullOrWhiteSpace($RootCAName) -or [string]::IsNullOrWhiteSpace($OID) -or [string]::IsNullOrWhiteSpace($httpCRLPath)) {
        Write-Verbose "Some configuration variables are missing, attempting to retrieve from CA or CAPolicy.inf..."
        
        # Try to get from CA configuration
        if (Import-ADCSModule) {
          $caConfig = Get-CertificationAuthority -ErrorAction SilentlyContinue
          if ($caConfig -and [string]::IsNullOrWhiteSpace($RootCAName)) {
            $RootCAName = $caConfig.Name
            Write-Verbose "Retrieved CA Name from CA configuration: $RootCAName"
          }
        }
        
        # Try to get from CAPolicy.inf
        $capolicyPath = Join-Path $env:SystemRoot "CAPolicy.inf"
        if (Test-Path $capolicyPath) {
          $existingCAPolicy = Read-CAPolicyInf -Path $capolicyPath
          if ($existingCAPolicy) {
            if ([string]::IsNullOrWhiteSpace($OID)) {
              $OID = $existingCAPolicy['OID']
              Write-Verbose "Retrieved OID from CAPolicy.inf: $OID"
            }
            if ([string]::IsNullOrWhiteSpace($httpCRLPath)) {
              $httpCRLPath = $existingCAPolicy['httpCRLPath']
              Write-Verbose "Retrieved CRL URL from CAPolicy.inf: $httpCRLPath"
            }
          }
        }
      }
      
      # Get additional CA configuration if available
      $additionalConfig = @{}
      if (Import-ADCSModule) {
        $caConfig = Get-CertificationAuthority -ErrorAction SilentlyContinue
        if ($caConfig) {
          $additionalConfig['CAName'] = $caConfig.Name
          $additionalConfig['CAType'] = $caConfig.CAType
          $additionalConfig['CAStatus'] = 'Installed'
          $additionalConfig['CertificateThumbprint'] = $caConfig.CertificateThumbprint
        }
      }
      
      # Export configuration
      if (Export-CAConfiguration -Path $configBackupPath -AdditionalConfig $additionalConfig) {
        Report-Status "Configuration backup created successfully" 0 Green
        Write-Host "  Location: $configBackupPath" -ForegroundColor Gray
        Write-Host "  This file contains all CA configuration parameters for documentation and reference." -ForegroundColor Gray
      }
      else {
        throw "Export-CAConfiguration returned false"
      }
    }
    catch {
      Write-Warning "Failed to create configuration backup: $_"
      Write-Warning "Configuration backup is optional but recommended for documentation."
      Write-Verbose "Configuration backup error details: $($_.Exception.Message)"
    }
    
    # Clear progress indicator
    Write-Progress -Activity $Script:ProgressActivity -Completed

    #-----------------------------------------------------------------------------------------------------------
    # Phase 12: Completion and Next Steps
    #-----------------------------------------------------------------------------------------------------------
    Report-Status "Root CA Build Completed!" 0 Green
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host " ROOT CA INSTALLATION COMPLETE" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "AUTOMATED TASKS COMPLETED:" -ForegroundColor Cyan
    Write-Host "  ✓ CA installed and configured" -ForegroundColor Green
    Write-Host "  ✓ PSRemoting enabled (required for SubCA)" -ForegroundColor Green
    Write-Host "  ✓ CertConfig share created (\\$env:COMPUTERNAME\CertConfig)" -ForegroundColor Green
    Write-Host "  ✓ Configuration backup created" -ForegroundColor Green
    if ($CreateBackup -or (Test-Path (Join-Path $env:SystemDrive "CA-Backup"))) {
      Write-Host "  ✓ CA certificate and key backup created" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " NEXT STEPS FOR SUBCA INSTALLATION" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Ensure this Root CA server remains ONLINE and accessible" -ForegroundColor Yellow
    Write-Host "2. Verify connectivity from SubCA server:" -ForegroundColor Yellow
    Write-Host "   - PSRemoting: Test-WSMan -ComputerName $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "   - File Share: Test-Path \\$env:COMPUTERNAME\CertConfig" -ForegroundColor White
    Write-Host "3. Run Build-SubCA.ps1 on the SubCA server" -ForegroundColor Yellow
    Write-Host "   - The SubCA script will connect via PSRemoting" -ForegroundColor Gray
    Write-Host "   - It will submit certificate requests and retrieve signed certificates" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host " POST-SUBCA INSTALLATION SECURITY HARDENING" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After SubCA installation completes, perform these security steps:" -ForegroundColor White
    Write-Host ""
    Write-Host "  [ ] Disable PSRemoting (no longer needed)" -ForegroundColor Yellow
    Write-Host "      Disable-PSRemoting -Force" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [ ] Disable network adapters (physical disconnection preferred)" -ForegroundColor Yellow
    Write-Host "      Get-NetAdapter | Disable-NetAdapter -Confirm:$false" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [ ] Disable unnecessary services" -ForegroundColor Yellow
    Write-Host "      Get-Service Spooler,RemoteRegistry | Set-Service -StartupType Disabled" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [ ] Shutdown and store server in physically secure location" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT REMINDERS:" -ForegroundColor Cyan
    Write-Host "  • This server MUST remain ONLINE during SubCA installation" -ForegroundColor Yellow
    Write-Host "  • Take a VM snapshot now before proceeding with SubCA installation" -ForegroundColor Yellow
    Write-Host "  • Only bring this server online when needed:" -ForegroundColor Yellow
    Write-Host "    - SubCA certificate issuance/renewal" -ForegroundColor Gray
    Write-Host "    - Root CA certificate renewal" -ForegroundColor Gray
    Write-Host "    - Certificate revocation" -ForegroundColor Gray
    Write-Host "    - CRL publication" -ForegroundColor Gray
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
