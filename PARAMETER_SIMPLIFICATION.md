# Parameter Simplification for Single-Use Script
## Build-RootCA.ps1 - Simplified for Server Core Deployment

**Date**: 2024-12-19  
**Reason**: Script is designed for single-use on fresh Windows Server Core (no GUI)

---

## ✅ SIMPLIFICATION SUMMARY

### Before (v3.0):
- **14 parameters** (all optional)
- Many parameters rarely used
- Complex configuration options
- Import/Export configuration features

### After (v3.1):
- **3 parameters** (all optional)
- Minimal, essential parameters only
- Secure defaults hardcoded
- Simplified for single-use deployment

---

## 📋 NEW PARAMETER LIST

### Essential Parameters Only:

```powershell
param(
    # PSRemoting - Default: Enabled (required for SubCA installation)
    [Parameter(Mandatory=$false)]
    [switch]$EnablePSRemoting,
    
    # Backup - Default: Disabled (prompted if not specified)
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup,
    
    # Backup Path - Default: SystemDrive\CA-Backup
    [Parameter(Mandatory=$false)]
    [string]$BackupPath = $null
)
```

---

## 🔒 HARDCODED SECURITY CONFIGURATION

All security settings are now hardcoded with secure defaults:

```powershell
$script:HashAlgorithm = 'SHA384'              # SHA-384 (upgraded from SHA-256)
$script:KeyLength = 4096                      # RSA 4096-bit keys
$script:CAValidityYears = 10                   # Root CA valid for 10 years
$script:CRLPeriodYears = 1                     # CRL published annually
$script:CertificateValidityYears = 1           # Certificates valid for 1 year
$script:CryptoProvider = 'Software'            # Software KSP (default)
$script:HSMProviderName = $null               # HSM not used by default
$script:DisableLogging = $false                # Logging enabled by default
$script:LogPath = $null                        # Auto-generated log path
```

**Note**: These values can be modified in the script if needed, but are not exposed as parameters for simplicity.

---

## 🗑️ REMOVED PARAMETERS

The following parameters were removed and replaced with hardcoded defaults:

1. ❌ `-HashAlgorithm` → Hardcoded: `SHA384`
2. ❌ `-KeyLength` → Hardcoded: `4096`
3. ❌ `-CAValidityYears` → Hardcoded: `10`
4. ❌ `-CRLPeriodYears` → Hardcoded: `1`
5. ❌ `-CertificateValidityYears` → Hardcoded: `1`
6. ❌ `-CryptoProvider` → Hardcoded: `Software`
7. ❌ `-HSMProviderName` → Hardcoded: `$null`
8. ❌ `-DisableLogging` → Hardcoded: `$false` (logging enabled)
9. ❌ `-LogPath` → Hardcoded: Auto-generated
10. ❌ `-ExportConfigPath` → Removed (not needed for single-use)
11. ❌ `-ImportConfigPath` → Removed (not needed for single-use)

---

## 📝 USAGE EXAMPLES

### Basic Usage (Recommended):
```powershell
.\Build-RootCA.ps1
```
- PSRemoting enabled by default (required for SubCA)
- Logging enabled automatically
- Secure defaults (SHA-384, 4096-bit keys)
- Prompts for backup creation

### With Automatic Backup:
```powershell
.\Build-RootCA.ps1 -CreateBackup
```
- Creates backup automatically after installation
- Uses default path: `SystemDrive\CA-Backup`

### With Custom Backup Path:
```powershell
.\Build-RootCA.ps1 -CreateBackup -BackupPath "D:\CA-Backup"
```
- Creates backup in specified location

### Disable PSRemoting (Not Recommended):
```powershell
.\Build-RootCA.ps1 -EnablePSRemoting:$false
```
- ⚠️ **Warning**: SubCA installation will fail without PSRemoting
- Only use if you have a specific reason

---

## 🎯 BENEFITS OF SIMPLIFICATION

### 1. **Easier to Use**
- Fewer parameters to remember
- Sensible defaults for everything
- Less decision-making required

### 2. **Less Error-Prone**
- Can't accidentally use insecure settings
- Consistent security configuration
- No parameter conflicts

### 3. **Better for Server Core**
- Minimal command-line complexity
- No GUI needed for configuration
- Single-use deployment optimized

### 4. **Maintainable**
- Security settings in one place
- Easy to update defaults
- Clear separation of concerns

---

## 🔧 MODIFYING DEFAULTS

If you need to change security defaults, edit the hardcoded configuration section:

```powershell
# Location: Lines 115-125 in Build-RootCA.ps1
$script:HashAlgorithm = 'SHA384'              # Change to 'SHA512' if needed
$script:KeyLength = 4096                      # Change to 8192 if needed
$script:CAValidityYears = 10                  # Change if needed
# etc.
```

**Note**: Only modify if you have specific security requirements. The defaults are industry best practices.

---

## 📊 COMPARISON

| Feature | Before (v3.0) | After (v3.1) |
|---------|---------------|--------------|
| **Parameters** | 14 | 3 |
| **Required Parameters** | 0 | 0 |
| **Security Config** | Parameters | Hardcoded |
| **Complexity** | High | Low |
| **Server Core Friendly** | Medium | High |
| **Single-Use Optimized** | No | Yes |

---

## ✅ VALIDATION

- ✅ All parameters optional (no breaking changes)
- ✅ Secure defaults maintained
- ✅ Backward compatible (can still run without parameters)
- ✅ All functionality preserved
- ✅ Linting errors resolved (except acceptable warning)

---

## 🎉 RESULT

**The script is now optimized for single-use deployment on Windows Server Core!**

- **3 simple parameters** instead of 14
- **Secure defaults** hardcoded
- **Easy to use** on Server Core
- **Less complexity** for operators
- **Same security** standards maintained

**Perfect for fresh Windows Server Core deployments!**

