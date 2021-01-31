# PKI
Microsoft PKI 2-Tier infrastructure build

In the past year I have been working on ransomware recovery/infrastructure improvements post-incident. One thing that is always missing at each customer location is a PKI infrastructure, to implement LDAPs amongst other things.

Last year I attempted to do so with a DSC script but I didn't like the end result, so I rebuilt it from scratch over the past 2 weeks.

Steps:
- Obtain your own OID at https://pen.iana.org/pen/PenApplication.page
- Create a DNS CNAME named "pki" or something else for your Enterprise Subordinate CA.
- This is designed to be deployed on Server Core servers (Tested on Windows 2019 Core)
- Deploy 2 server core instances.
- One for the Offline Root CA
- One for the Enterprise Subordinate CA
- Setup your IP information on both servers
  (Offline Root CA is not supposed to be network attached at all as per definition. While there is a small risk, I would say that having it connected for the duration of the build and then shut down after the Subordinate is issued isn't a major concern.)
- Run the Setup-CoreBasics.ps1 first (this is a WIP)
- On the Offline Root CA server (not domain joined), run the Build-OfflineRootCA.ps1
- On the Subordinate CA server (domain joined, and logged in using a domain account), run the Build-SubordinateCA.ps1
- Offline Root CA certificate is valid for 20 years.
- Subordinate Enterprise CA certificate is valid for 10 years
- Issued certificates are valid for 1 year

There are some prompts during the installation, so it's not fully unattended (need to edit the CAPolicy.inf files on both servers to enter your OID and the policy statement URL for example)

End result is a working PKI infrastructure in 30 mins max (from server core build to functional).
