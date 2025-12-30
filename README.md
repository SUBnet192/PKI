# Microsoft PKI 2-Tier Infrastructure

[![Windows Server](https://img.shields.io/badge/Windows%20Server-2012%20%7C%202016%20%7C%202019%20%7C%202022%20%7C%202025-blue)](https://www.microsoft.com/windows-server)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)](https://docs.microsoft.com/powershell)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Automated deployment scripts for building a Microsoft PKI 2-tier infrastructure (Root CA + Enterprise Subordinate CA) on Windows Server Core.

## 📋 Overview

This project provides PowerShell scripts to automate the deployment of a complete Microsoft PKI infrastructure in approximately **15 minutes**. Designed for organizations that need to quickly establish PKI for:
- **LDAPS** (LDAP over SSL/TLS)
- **Certificate-based authentication**
- **Code signing**
- **Document signing**
- **Email encryption**
- **VPN certificates**
- And other certificate-based security solutions

### Why This Project?

After working on ransomware recovery and infrastructure improvements, I noticed that **PKI infrastructure is consistently missing** at customer locations. This project was created to fill that gap with a reliable, automated solution.

---

## 🏗️ Architecture

### Two-Tier PKI Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Root CA (Offline)                        │
│  - Standalone CA (not domain-joined)                       │
│  - Valid for 10 years                                       │
│  - Only online during SubCA installation                    │
│  - Taken offline after deployment                           │
└───────────────────────┬─────────────────────────────────────┘
                        │ Issues certificate to
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Enterprise Subordinate CA (Online)             │
│  - Domain-joined Enterprise CA                              │
│  - Valid for 5 years                                        │
│  - Issues certificates to domain members                    │
│  - Valid for 1 year (configurable)                         │
└─────────────────────────────────────────────────────────────┘
```

### Key Features

- ✅ **Automated deployment** - Minimal manual intervention
- ✅ **Server Core optimized** - Designed for headless deployment
- ✅ **Security best practices** - SHA-384, 4096-bit keys, proper CRL configuration
- ✅ **Comprehensive logging** - Full audit trail
- ✅ **Post-installation validation** - Ensures proper configuration
- ✅ **Backup automation** - Secure backup of CA keys
- ✅ **Windows Server 2025 compatible** - Tested on all modern Windows Server versions

---

## 📦 Prerequisites

### Before You Begin

1. **Obtain an OID (Object Identifier)**
   - Register at: https://pen.iana.org/pen/PenApplication.page
   - You'll receive a 5-digit PEN (Private Enterprise Number)
   - This is required for the CA policy OID

2. **DNS Configuration**
   - Create a DNS CNAME record (e.g., `pki.company.com`) pointing to your Enterprise Subordinate CA server
   - This will be used for CRL and AIA distribution points

3. **Server Requirements**
   - **Root CA Server:**
     - Windows Server 2012/2016/2019/2022/2025 (Server Core recommended)
     - **NOT domain-joined** (standalone/workgroup)
     - Administrator access
     - Network connectivity (temporary, for SubCA installation)
   
   - **Subordinate CA Server:**
     - Windows Server 2012/2016/2019/2022/2025 (Server Core recommended)
     - **Domain-joined** (required for Enterprise CA)
     - Domain administrator access
     - Network connectivity to Root CA

4. **Network Configuration**
   - Both servers need network connectivity during deployment
   - Root CA can be disconnected after SubCA installation completes
   - Ensure firewall allows PSRemoting (WinRM) between servers

---

## 🚀 Quick Start

### Step 1: Prepare Servers

1. Deploy two Windows Server Core instances
2. Configure IP addresses and basic networking
3. **Root CA**: Ensure it's **NOT** domain-joined
4. **SubCA**: Ensure it's domain-joined and you're logged in with a domain account

### Step 2: Deploy Root CA

```powershell
# On Root CA server (not domain-joined)
.\Build-RootCA.ps1
```

**Script Parameters:**
- `-EnablePSRemoting` - Enable PSRemoting (default: enabled, required for SubCA)
- `-CreateBackup` - Automatically create backup after installation
- `-BackupPath` - Custom backup path (default: `SystemDrive\CA-Backup`)

**Example with backup:**
```powershell
.\Build-RootCA.ps1 -CreateBackup
```

### Step 3: Deploy Subordinate CA

```powershell
# On SubCA server (domain-joined, domain admin account)
.\Build-SubCA.ps1
```

### Step 4: Post-Deployment

1. **Verify SubCA installation** completed successfully
2. **Take Root CA offline:**
   - Disable network adapters
   - Disable PSRemoting
   - Shutdown and store securely
3. **Verify certificate issuance** from SubCA

---

## 📖 Detailed Deployment Guide

### Root CA Deployment

The Root CA script will prompt you for:
1. **CA Common Name** (e.g., `Corp-Root-CA`)
2. **OID** (5-digit number from IANA)
3. **CRL URL** (e.g., `pki.company.com`)

**Security Configuration (Hardcoded):**
- Hash Algorithm: **SHA-384**
- Key Length: **4096 bits**
- CA Validity: **10 years**
- CRL Period: **1 year**
- Certificate Validity: **1 year**

**What the Script Does:**
1. ✅ Validates prerequisites (admin rights, Windows Server, not domain-joined)
2. ✅ Enables PSRemoting (required for SubCA connection)
3. ✅ Creates CAPolicy.inf with security settings
4. ✅ Installs ADCS-Cert-Authority feature
5. ✅ Installs Standalone Root CA
6. ✅ Configures CRL distribution points
7. ✅ Configures AIA entries
8. ✅ Creates CertConfig share (`\\RootCA\CertConfig`)
9. ✅ Publishes initial CRL
10. ✅ Validates CA configuration
11. ✅ Optionally creates backup

**Important Notes:**
- ⚠️ **Root CA must remain ONLINE during SubCA installation**
- ⚠️ **PSRemoting is required** - The SubCA script connects via PSRemoting
- ⚠️ **Scripts must run LOCALLY** - Not through remote PowerShell

### Subordinate CA Deployment

The SubCA script will:
1. Connect to Root CA via PSRemoting
2. Submit certificate request
3. Retrieve signed certificate
4. Install Enterprise Subordinate CA
5. Configure CRL and AIA distribution points

---

## 🔒 Security Considerations

### Root CA Security

The Root CA is designed to be **offline** after deployment:

1. **During Deployment:**
   - Network connectivity required
   - PSRemoting enabled
   - CertConfig share accessible

2. **After Deployment:**
   - ✅ Disable all network adapters
   - ✅ Disable PSRemoting
   - ✅ Disable unnecessary services
   - ✅ Enable BitLocker (if supported)
   - ✅ Store in physically secure location
   - ✅ Create and verify backups

3. **When to Bring Online:**
   - SubCA certificate renewal
   - Root CA certificate renewal
   - SubCA certificate revocation
   - CRL updates

### Security Features

- **Strong Cryptography:**
  - SHA-384 hash algorithm
  - 4096-bit RSA keys
  - Proper certificate validity periods

- **CRL Configuration:**
  - Annual CRL publication
  - Weekly delta CRL
  - 2-week CRL overlap period

- **Audit and Logging:**
  - Comprehensive file-based logging
  - All CA operations audited
  - Full deployment audit trail

---

## 📝 Certificate Validity Periods

| Certificate Type | Validity Period | Notes |
|-----------------|-----------------|-------|
| **Root CA** | 10 years | Hardcoded in script |
| **Subordinate CA** | 5 years | Configured during SubCA installation |
| **Issued Certificates** | 1 year | Configurable (1-2 years recommended) |

---

## 🛠️ Troubleshooting

### Common Issues

#### Issue: "Root CA must NOT be domain-joined"
**Solution:** Ensure the Root CA server is in a workgroup, not joined to a domain.

#### Issue: "PSRemoting is required"
**Solution:** The Root CA script enables PSRemoting by default. If disabled, run:
```powershell
Enable-PSRemoting -Force
```

#### Issue: "SubCA cannot connect to Root CA"
**Solution:** 
- Verify Root CA is online and accessible
- Check firewall rules (WinRM port 5985/5986)
- Verify CertConfig share is accessible: `\\RootCA\CertConfig`
- Test PSRemoting: `Test-WSMan -ComputerName RootCA`

#### Issue: "OID validation failed"
**Solution:** Ensure you enter exactly 5 digits (your IANA PEN number).

#### Issue: "CAPolicy.inf already exists"
**Solution:** The script will prompt to overwrite. Choose 'y' if you want to update it.

### Log Files

Log files are automatically created in:
```
C:\ProgramData\PKI\Logs\RootCA-Build-YYYYMMDD-HHMMSS.log
```

Check these logs for detailed error information.

---

## 📚 Additional Documentation

- **[PARAMETER_SIMPLIFICATION.md](PARAMETER_SIMPLIFICATION.md)** - Parameter documentation and simplification details
- **[SECURITY_IMPLEMENTATION_SUMMARY.md](SECURITY_IMPLEMENTATION_SUMMARY.md)** - Security enhancements and best practices
- **[OFFLINE_ROOT_CA_SECURITY_BEST_PRACTICES.md](OFFLINE_ROOT_CA_SECURITY_BEST_PRACTICES.md)** - Detailed security recommendations
- **[WINDOWS_SERVER_2025_COMPATIBILITY.md](WINDOWS_SERVER_2025_COMPATIBILITY.md)** - Compatibility information

---

## 🎥 Video Tutorial

<div align="left">
  <a href="https://www.youtube.com/watch?v=ixw1v1G5ods">
    <img 
      src="https://img.youtube.com/vi/ixw1v1G5ods/0.jpg" 
      alt="Root CA Installation Video" 
      style="width:100%;">
  </a>
</div>

---

## ⚙️ Script Parameters

### Build-RootCA.ps1

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-EnablePSRemoting` | Switch | Enabled | Enable PSRemoting (required for SubCA) |
| `-CreateBackup` | Switch | Disabled | Automatically create backup after installation |
| `-BackupPath` | String | `SystemDrive\CA-Backup` | Custom backup path |

**Example:**
```powershell
.\Build-RootCA.ps1 -CreateBackup -BackupPath "D:\CA-Backup"
```

### Build-SubCA.ps1

See script help for SubCA parameters:
```powershell
Get-Help .\Build-SubCA.ps1 -Full
```

---

## 🔄 Version History

### Version 3.1 (Current)
- Simplified parameters (3 instead of 14)
- Hardcoded secure defaults
- Optimized for single-use deployment
- Server Core friendly

### Version 3.0
- File-based logging
- Post-installation validation
- Automated CertConfig share
- Progress indicators
- HSM support
- Configuration export/import

### Version 2.x
- Security enhancements (SHA-384, proper CRL periods)
- Domain-joined validation
- Network isolation checks
- Automated backup

---

## 📋 Post-Deployment Checklist

### Root CA
- [ ] Verify CA installation completed successfully
- [ ] Verify backup created and tested
- [ ] Verify CertConfig share is accessible
- [ ] Verify PSRemoting is enabled
- [ ] Take VM snapshot (if virtualized)
- [ ] Proceed with SubCA installation
- [ ] After SubCA installation: Disable PSRemoting
- [ ] After SubCA installation: Disable network adapters
- [ ] After SubCA installation: Store server securely

### Subordinate CA
- [ ] Verify SubCA installation completed successfully
- [ ] Verify certificate issuance works
- [ ] Verify CRL distribution points are accessible
- [ ] Verify AIA entries are accessible
- [ ] Test certificate enrollment
- [ ] Document CA configuration

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## 📄 License

This project is licensed under the MIT License.

---

## 👤 Author

**Marc Bouchard**

- Created: 2021/03/04
- Last Updated: 2024/12/19
- Version: 3.1

---

## ⚠️ Important Notes

1. **These scripts must be run LOCALLY** on the servers, not through remote PowerShell
2. **Root CA must remain ONLINE** during SubCA installation
3. **PSRemoting is required** for SubCA to connect to Root CA
4. **Backup is critical** - Always create backups before taking Root CA offline
5. **Test in a lab environment** before deploying to production

---

## 🆘 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Review the troubleshooting section above
- Check log files for detailed error information

---

**Deploy a complete PKI infrastructure in 15 minutes!** 🚀
