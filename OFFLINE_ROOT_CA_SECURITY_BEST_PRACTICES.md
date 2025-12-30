# Offline Root CA - Security Best Practices & Recommendations

## Executive Summary

For an **offline Root Certificate Authority**, security is paramount. This document provides specific recommendations for hardening the Root CA server and configuring secure parameters.

---

## 🔐 CRITICAL SECURITY PARAMETERS

### 1. **Cryptographic Parameters**

#### Current Configuration Analysis:
- **Key Length**: 4096 bits ✅ (Good)
- **Hash Algorithm**: SHA256 ⚠️ (Consider upgrading)
- **CA Validity**: 10 years ✅ (Appropriate for Root CA)

#### Recommendations:

```powershell
# RECOMMENDED: Use SHA-384 or SHA-512 for Root CA
# SHA-256 is acceptable but SHA-384/SHA-512 provides better future-proofing
$HashAlgorithm = 'SHA384'  # or 'SHA512' for maximum security

# Key Length: 4096 is good, but consider 8192 for maximum security
# Note: 8192-bit keys have significant performance impact
$KeyLength = 4096  # Current is good, 8192 for maximum security

# Validity Period: 10 years is appropriate for offline Root CA
$CAValidityYears = 10  # ✅ Good
```

**Rationale**:
- **SHA-384/SHA-512**: Provides better resistance to future cryptographic attacks
- **4096-bit RSA**: Current industry standard, provides ~112-128 bits of security
- **8192-bit RSA**: Maximum security but 4x slower operations
- **10-year validity**: Appropriate for offline Root CA (rarely accessed)

---

### 2. **Key Storage Provider**

#### Current Configuration:
```powershell
-CryptoProviderName "RSA#Microsoft Software Key Storage Provider"
```

#### Security Recommendation:

**Option A: Software KSP (Current - Acceptable for Offline CA)**
```powershell
# Current implementation is acceptable for offline CA
# Keys are stored in Windows Certificate Store (encrypted at rest)
-CryptoProviderName "RSA#Microsoft Software Key Storage Provider"
```

**Option B: Hardware Security Module (HSM) - RECOMMENDED for Production**
```powershell
# For maximum security, use HSM
-CryptoProviderName "RSA#Microsoft Platform Crypto Provider"
# Or specific HSM provider:
-CryptoProviderName "RSA#YourHSMProvider"
```

**HSM Benefits**:
- Keys never leave hardware
- Tamper-resistant
- FIPS 140-2 Level 3+ compliance
- Better audit trail

**Recommendation**: For production Root CA, strongly consider HSM. For lab/testing, software KSP is acceptable.

---

### 3. **Network Isolation & Physical Security**

#### Script Enhancements Needed:

```powershell
Function Test-OfflineCASecurity {
    <#
    .SYNOPSIS
        Validates security requirements for offline Root CA
    #>
    
    $warnings = @()
    $errors = @()
    
    # Check network adapters
    $adapters = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
    if ($adapters.Count -gt 0) {
        $warnings += "WARNING: Network adapters are enabled. Root CA should be offline after setup."
        $warnings += "  Consider disabling network adapters after SubCA certificate is issued."
    }
    
    # Check if domain-joined (should NOT be)
    $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerInfo.PartOfDomain) {
        $errors += "CRITICAL: Root CA must NOT be domain-joined. Current domain: $($computerInfo.Domain)"
    }
    
    # Check for remote management services
    $remoteServices = @('RemoteRegistry', 'WinRM', 'Spooler')
    foreach ($svc in $remoteServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running' -and $service.StartType -ne 'Disabled') {
            $warnings += "WARNING: $svc service is running. Consider disabling for offline CA."
        }
    }
    
    # Check Windows Firewall
    $fwProfile = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($fwProfile) {
        $disabledProfiles = $fwProfile | Where-Object { $_.Enabled -eq $false }
        if ($disabledProfiles) {
            $warnings += "WARNING: Windows Firewall is disabled on some profiles. Enable for maximum security."
        }
    }
    
    if ($errors.Count -gt 0) {
        Write-Error "Security validation failed:`n$($errors -join "`n")"
        return $false
    }
    
    if ($warnings.Count -gt 0) {
        foreach ($warning in $warnings) {
            Write-Warning $warning
        }
    }
    
    return $true
}
```

---

## 🛡️ SECURITY HARDENING RECOMMENDATIONS

### 4. **Disable Unnecessary Services**

Add to script after CA installation:

```powershell
Function Disable-UnnecessaryServices {
    <#
    .SYNOPSIS
        Disables services not needed for offline Root CA
    #>
    
    $servicesToDisable = @(
        'Spooler',           # Print Spooler - not needed
        'RemoteRegistry',    # Remote Registry - security risk
        'WSearch',           # Windows Search - not needed
        'Themes',            # Themes - not needed on Server Core
        'AudioSrv',          # Windows Audio - not needed
        'Browser',           # Computer Browser - not needed
        'SSDP',              # SSDP Discovery - not needed
        'upnphost'           # UPnP - security risk
    )
    
    foreach ($serviceName in $servicesToDisable) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -eq 'Running') {
                    Stop-Service -Name $serviceName -Force -ErrorAction Stop
                }
                Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                Write-Verbose "Disabled service: $serviceName"
            }
        }
        catch {
            Write-Warning "Could not disable service $serviceName : $_"
        }
    }
}
```

---

### 5. **Windows Firewall Configuration**

```powershell
Function Configure-Firewall {
    <#
    .SYNOPSIS
        Configures Windows Firewall for offline Root CA
    #>
    
    # Enable firewall on all profiles
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    
    # Block all inbound connections by default (Root CA should be offline anyway)
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    
    # Allow only essential outbound (for initial setup, then disable network)
    # Note: After setup, network should be physically disconnected
}
```

---

### 6. **Audit Configuration**

#### Current Configuration:
```powershell
certutil.exe -setreg CA\AuditFilter 127
```

#### Explanation:
- **127** = All audit events enabled (binary: 01111111)
  - Bit 0: Start/Stop CA service
  - Bit 1: Backup/Restore CA database
  - Bit 2: Change CA configuration
  - Bit 3: Change CA security settings
  - Bit 4: Issue/Manage certificate requests
  - Bit 5: Revoke certificates
  - Bit 6: Retrieve archived keys
  - Bit 7: (Reserved)

**This is CORRECT** ✅ - All audit events should be enabled for Root CA.

#### Additional Audit Recommendations:

```powershell
# Enable detailed object access auditing
auditpol /set /category:"Object Access" /failure:enable /success:enable

# Enable account management auditing
auditpol /set /category:"Account Management" /failure:enable /success:enable

# Enable policy change auditing
auditpol /set /category:"Policy Change" /failure:enable /success:enable

# Enable privilege use auditing
auditpol /set /category:"Privilege Use" /failure:enable /success:enable
```

---

### 7. **Certificate Validity Periods**

#### Current Configuration Analysis:

```powershell
# Root CA Certificate: 10 years ✅ GOOD
RenewalValidityPeriodUnits=10

# Issued Certificates: 5 years
CA\ValidityPeriodUnits = 5
```

#### Recommendations for Offline Root CA:

| Certificate Type | Current | Recommended | Rationale |
|-----------------|---------|-------------|-----------|
| Root CA | 10 years | 10-15 years | Offline CA rarely accessed, longer validity reduces risk |
| SubCA Certificate | N/A | 5-7 years | Balance between security and operational overhead |
| End-Entity Certificates | 5 years | 1-2 years | Shorter validity allows faster response to compromise |

**Recommendation**: Current settings are reasonable. Consider:
- Root CA: 10-15 years (offline, low risk)
- Issued certs: 1-2 years (better security posture)

---

### 8. **CRL Configuration for Offline CA**

#### Current Configuration:
```powershell
CRLPeriod=Years
CRLPeriodUnits=10
CRLDeltaPeriod=Days
CRLDeltaPeriodUnits=0  # Delta CRL disabled
```

#### Security Analysis:

**Issues for Offline CA**:
1. **10-year CRL period** is too long - CRLs should be published more frequently
2. **Delta CRL disabled** - Consider enabling for better security
3. **CRL Overlap**: 3 weeks is reasonable

#### Recommendations:

```powershell
# For OFFLINE Root CA, CRL considerations:
# - Root CA rarely issues/revokes certificates
# - CRL can be published less frequently
# - But should still be accessible when needed

# RECOMMENDED for Offline Root CA:
CRLPeriod = "Years"
CRLPeriodUnits = 1-2  # Publish CRL every 1-2 years (not 10!)
CRLDeltaPeriod = "Days"
CRLDeltaPeriodUnits = 7  # Enable delta CRL weekly
CRLOverlapPeriod = "Weeks"
CRLOverlapPeriodUnits = 2  # 2-week overlap is good
```

**Rationale**:
- Offline Root CA issues few certificates
- CRL should be published periodically (1-2 years) for validation
- Delta CRL helps with revocation efficiency
- Overlap ensures no gaps in validation

---

### 9. **Backup & Key Protection**

#### Critical: Add Backup Function

```powershell
Function Backup-CAKeys {
    <#
    .SYNOPSIS
        Backs up CA private key and certificate
        CRITICAL: Store backups in secure, offline location
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory=$true)]
        [SecureString]$Password
    )
    
    # Create backup directory
    if (-not (Test-Path $BackupPath)) {
        New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $caName = (Get-CertificationAuthority).Name
    
    # Backup CA certificate and private key
    $certPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.pfx"
    
    # Export CA certificate with private key
    $caCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*CN=$caName*" }
    if ($caCert) {
        Export-PfxCertificate -Cert $caCert -FilePath $certPath -Password $Password
        
        # Also export as .cer (public key only)
        $cerPath = Join-Path $BackupPath "RootCA-$caName-$timestamp.cer"
        Export-Certificate -Cert $caCert -FilePath $cerPath -Type CERT
        
        Write-Host "CA backup created: $certPath" -ForegroundColor Green
        Write-Host "WARNING: Store backup in secure, offline location!" -ForegroundColor Yellow
        Write-Host "WARNING: Protect backup password!" -ForegroundColor Yellow
    }
    
    # Backup CA database
    $dbPath = Join-Path $env:SystemRoot "System32\CertLog"
    $dbBackupPath = Join-Path $BackupPath "CADatabase-$timestamp"
    Copy-Item -Path $dbPath -Destination $dbBackupPath -Recurse -Force
    
    Write-Host "CA database backed up to: $dbBackupPath" -ForegroundColor Green
}
```

**Backup Best Practices**:
1. **Multiple backups** in different physical locations
2. **Encrypted storage** (BitLocker, encrypted USB drives)
3. **Offline storage** (not on network)
4. **Password protection** (strong passwords, stored separately)
5. **Regular verification** (test restore procedures)

---

### 10. **Access Control & User Management**

#### Recommendations:

```powershell
Function Configure-CAAccessControl {
    <#
    .SYNOPSIS
        Configures access control for CA operations
    #>
    
    # Limit who can manage CA
    # Only specific administrators should have CA management rights
    
    # Disable default administrator account (if possible)
    # Use dedicated service accounts with minimal privileges
    
    # Enable Local Security Policy:
    # - Require strong passwords
    # - Account lockout after failed attempts
    # - Disable guest account
    # - Enable UAC
    
    # Configure CA permissions (requires manual configuration):
    # - CA Admins: Only specific security group
    # - Certificate Managers: Only specific security group
    # - Backup Operators: Only specific security group
}
```

---

### 11. **Operational Security Procedures**

#### Post-Installation Checklist:

```powershell
Function Get-PostInstallationChecklist {
    <#
    .SYNOPSIS
        Provides post-installation security checklist
    #>
    
    $checklist = @"
    
    OFFLINE ROOT CA - POST-INSTALLATION SECURITY CHECKLIST
    ======================================================
    
    [ ] 1. Verify CA is NOT domain-joined
    [ ] 2. Disable all network adapters (physical disconnection preferred)
    [ ] 3. Disable unnecessary services (Spooler, RemoteRegistry, etc.)
    [ ] 4. Enable Windows Firewall (block all inbound)
    [ ] 5. Create secure backups of CA certificate and private key
    [ ] 6. Store backups in secure, offline location (multiple locations)
    [ ] 7. Document backup password (store separately from backups)
    [ ] 8. Verify audit logging is enabled and working
    [ ] 9. Remove or disable default administrator account (if possible)
    [ ] 10. Configure strong password policy
    [ ] 11. Enable BitLocker disk encryption (if supported)
    [ ] 12. Document physical location and access controls
    [ ] 13. Create runbook for CA operations (issuing SubCA cert, etc.)
    [ ] 14. Test backup restore procedure
    [ ] 15. Shutdown server after SubCA certificate is issued
    [ ] 16. Store server in physically secure location
    [ ] 17. Document who has access and when CA was last accessed
    
    SECURITY NOTES:
    - Root CA should only be powered on when:
      * Issuing SubCA certificate
      * Renewing Root CA certificate
      * Revoking SubCA certificate
      * Publishing updated CRL
    - All CA operations should be logged and audited
    - Physical access should be restricted and logged
    - Consider using HSM for production environments
    
    "@
    
    Write-Host $checklist
}
```

---

## 📋 RECOMMENDED SCRIPT ENHANCEMENTS

### 12. **Enhanced Security Parameters**

Add to script parameters:

```powershell
[CmdletBinding()]
param(
    # Security Parameters
    [Parameter(Mandatory=$false)]
    [ValidateSet('SHA256', 'SHA384', 'SHA512')]
    [string]$HashAlgorithm = 'SHA384',  # Upgraded from SHA256
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(2048, 4096, 8192)]
    [int]$KeyLength = 4096,  # Current is good
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(10, 15)]
    [int]$CAValidityYears = 10,  # Current is good
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 2)]
    [int]$CRLPeriodYears = 1,  # Changed from 10 to 1-2 years
    
    [Parameter(Mandatory=$false)]
    [switch]$UseHSM = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableNetworkAfterSetup = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableBitLocker = $false
)
```

---

### 13. **Updated Registry Settings**

```powershell
# RECOMMENDED settings for Offline Root CA
$regSettings = @(
    @{Path = "CA\CRLPeriodUnits"; Value = "1"},           # Changed from 10 to 1 year
    @{Path = "CA\CRLPeriod"; Value = "Years"},
    @{Path = "CA\CRLDeltaPeriodUnits"; Value = "7"},      # Enable delta CRL (weekly)
    @{Path = "CA\CRLDeltaPeriod"; Value = "Days"},
    @{Path = "CA\CRLOverlapPeriodUnits"; Value = "2"},  # 2-week overlap
    @{Path = "CA\CRLOverlapPeriod"; Value = "Weeks"},
    @{Path = "CA\ValidityPeriodUnits"; Value = "1"},    # Issued certs: 1 year (better security)
    @{Path = "CA\ValidityPeriod"; Value = "Years"},
    @{Path = "CA\AuditFilter"; Value = "127"},           # All audit events (current is good)
    @{Path = "CA\CRLFlags"; Value = "CRLF_PUBLISH_EXPIRED_CRLS"}  # Publish expired CRLs
)
```

---

## 🎯 PRIORITY RECOMMENDATIONS SUMMARY

### Immediate (Before Production):
1. ✅ **Upgrade Hash Algorithm** to SHA-384 or SHA-512
2. ✅ **Reduce CRL Period** from 10 years to 1-2 years
3. ✅ **Enable Delta CRL** (currently disabled)
4. ✅ **Add domain-joined check** (must NOT be domain-joined)
5. ✅ **Add network isolation checks**
6. ✅ **Implement backup function** for CA keys

### High Priority:
7. ✅ **Disable unnecessary services** after setup
8. ✅ **Configure Windows Firewall** (block all inbound)
9. ✅ **Enable comprehensive auditing** (beyond current)
10. ✅ **Add post-installation security checklist**

### Medium Priority:
11. ✅ **Consider HSM** for production environments
12. ✅ **Reduce issued certificate validity** to 1-2 years
13. ✅ **Add access control configuration**
14. ✅ **Document operational procedures**

---

## 🔒 SECURITY COMPLIANCE

### FIPS 140-2 Considerations:
- Use FIPS-compliant algorithms (SHA-384/SHA-512, RSA 4096+)
- Consider FIPS-validated HSM for Level 3+ compliance
- Ensure Windows is in FIPS mode if required

### Common Criteria:
- Comprehensive audit logging ✅ (current)
- Access controls
- Key protection
- Physical security

### NIST Guidelines:
- SP 800-57: Key management (current key lengths are compliant)
- SP 800-63: Digital identity guidelines
- SP 800-88: Media sanitization (for decommissioning)

---

## 📝 IMPLEMENTATION CHECKLIST

- [ ] Update script to use SHA-384/SHA-512
- [ ] Add domain-joined validation
- [ ] Add network isolation checks
- [ ] Implement backup function
- [ ] Add service disable function
- [ ] Update CRL period settings
- [ ] Enable delta CRL
- [ ] Add post-installation checklist
- [ ] Document operational procedures
- [ ] Test backup/restore procedures

---

## 🚨 CRITICAL WARNINGS

1. **NEVER** connect Root CA to production network after SubCA certificate is issued
2. **ALWAYS** create multiple encrypted backups before going offline
3. **VERIFY** backup passwords are stored separately and securely
4. **DOCUMENT** all CA operations (who, what, when, why)
5. **TEST** restore procedures before going offline
6. **PHYSICALLY SECURE** the server (locked room, access logs)
7. **LIMIT ACCESS** to only essential personnel
8. **AUDIT** all access and operations

---

## 📚 REFERENCES

- Microsoft: [Best Practices for Offline Root CA](https://docs.microsoft.com/en-us/windows-server/identity/ad-cs/deploy/offline-root-ca)
- NIST SP 800-57: Key Management Guidelines
- NIST SP 800-63: Digital Identity Guidelines
- FIPS 140-2: Security Requirements for Cryptographic Modules

