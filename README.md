# PKI
Microsoft PKI 2-Tier infrastructure build

In the past year I have been working on ransomware recovery/infrastructure improvements post-incident. One thing that is always missing at each customer location is a PKI infrastructure, to implement LDAPs amongst other things.

Last year I attempted to do so with a DSC script but I didn't like the end result, so I rebuilt it from scratch over the past 2 weeks.

Steps:
- Obtain your own OID at https://pen.iana.org/pen/PenApplication.page
- Create a DNS CNAME named "pki" or something else for your Enterprise Subordinate CA.
- This is designed to be deployed on Server Core servers (Tested on Windows 2019 Core)
- Deploy 2 server core instances.
- One for the Root CA
- One for the Enterprise Subordinate CA
- Setup your IP information on both servers
  (Root CA is not supposed to be network attached. While there is a small risk, I would say that having it connected for the duration of the build and then shut down after the Subordinate is issued isn't a major concern.)
- On the Root CA server (not domain joined), run the Build-RootCA.ps1
- On the Subordinate CA server (domain joined, and logged in using a domain account), run the Build-SubCA.ps1
- Root CA certificate is valid for 10 years.
- Subordinate Enterprise CA certificate is valid for 5 years
- Issued certificates are valid for 1 year

There are some prompts during the installation, so it's not fully unattended, but all prompts are made at the beginning of the script.

End result is a working PKI infrastructure in 15 mins max (if you're starting from Windows virtual templates).

Video of the Root CA installation
<div align="left">
      <a href="https://www.youtube.com/watch?v=ixw1v1G5ods">
     <img 
      src="https://img.youtube.com/vi/ixw1v1G5ods/0.jpg" 
      alt="ORCA" 
      style="width:100%;">
      </a>
    </div>
