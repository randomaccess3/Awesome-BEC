# Awesome-BEC
Repository of attack and defensive information for Business Email Compromise investigations

## **Office365/AzureAD** 

* [ATT&CK O365](https://attack.mitre.org/matrices/enterprise/cloud/office365/)
* [ATT&CK Azure](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)

## Attack/Defend Research

|Description | Author | Link|
|-|-|-|
|| Lina Lau | [Backdoor Office 365 and Active Directory - Golden SAML](https://www.inversecos.com/2021/09/backdooring-office-365-and-active.html)
|| Lina Lau | [Office365 Attacks: Bypassing MFA, Achieving Persistence and More - Part I](https://www.inversecos.com/2021/09/office365-attacks-bypassing-mfa.html)
|| Lina Lau | [Attacks on Azure AD and M365: Pawning the cloud, PTA Skeleton Keys and more - PART II](https://www.inversecos.com/2021/10/attacks-on-azure-ad-and-m365-pawning.html)
|| Mike Felch and Steve Borosh | [Socially Acceptable Methods to Walk in the Front Door](https://www.slideshare.net/MichaelFelch/socially-acceptable-methods-to-walk-in-the-front-door)
|| Kuba Gretzky | [Evilginx2](https://github.com/kgretzky/evilginx2)
|| Mandiant | [Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)

## Investigation Research

|Description | Author | Link|
|-|-|-|
|| Devon Ackerman (SANS DFIR Summit 2018) | [A Planned Methodology for Forensically Sound IR in Office 365](https://www.youtube.com/watch?v=CubGixACC4E)
|| Matt Bromiley | [Business Email Compromise; Office 365 Making Sense of All the Noise](https://www.youtube.com/watch?v=JMFB4TodjkE)
|| PWC IR | [Business Email Compromise Guide](https://github.com/PwC-IR/Business-Email-Compromise-Guide)
|| Korstiann Stam (SANS DFIR Summit 2021) | [A Holistic Approach to Defending Business Email Compromise (BEC) Attacks](https://www.youtube.com/watch?v=sV-BzlHSyes)
|| M365 Internals | [Everything About Service Principals, Applications, And API Permissions](https://m365internals.com/2021/07/24/everything-about-service-principals-applications-and-api-permissions/)
|| M365 Internals | [What I Have Learned From Doing A Year Of Cloud Forensics In Azure AD](https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/)
|| M365 Internals | [Incident Response In A Microsoft Cloud Environment](https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/)
|| M365 Internals | [Incident Response Series: Reviewing Data In Azure AD For Investigation](https://m365internals.com/2021/03/16/incident-response-series-reviewing-data-in-azure-ad-for-investigation/)
|| M365 Internals | [Incident Response Series: Collecting And Analyzing Logs In Azure Ad](https://m365internals.com/2021/03/08/incident-response-series-collecting-and-analyzing-logs-in-azure-ad/)
|| Microsoft | [How automated investigation and response works in Microsoft Defender for Office 365](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/automated-investigation-response-office?view=o365-worldwide)
|| Microsoft | [Incident Response playbooks](https://docs.microsoft.com/en-us/security/compass/incident-response-playbooks)
|| Brendan Mccreesh | [Matching the O365 MachineID to a computer’s MachineGUID](https://digitalforensicsdotblog.wordpress.com/2020/08/18/matching-an-o365-machineid-to-a-computers-machineguid/)

## Datasets

|Description|URL|
|-|-|
|A dataset containing Office 365 Unified Audit Logs for security research and detection. | [O365 Dataset](https://github.com/invictus-ir/o365_dataset)|

## Tools

|Description|URL|
|-|-|
|Automate the security assessment of Microsoft Office 365 environments | [365Inspect by Soteria Security](https://github.com/soteria-security/365Inspect)|A set of functions that allow the DFIR analyst to collect logs relevant for Office 365 Business Email Compromise and Azure investigations | [DFIR-O365RC by ANSSI-FR](https://github.com/ANSSI-FR/DFIR-O365RC/archive/refs/heads/main.zip)|
| Queries configurations in the Azure AD/O365 tenant which can shed light on hard-to-find permissions and configuration settings in order to assist organizations in securing these environments | [CrowdStrike Reporting Tool for Azure (CRT)](https://github.com/CrowdStrike/CRT)|
|Aviary is a new dashboard that CISA and partners developed to help visualize and analyze outputs from its Sparrow detection tool released in December 2020|[Aviary/SPARROW by CISA](https://github.com/cisagov/Sparrow)
|The goal of the Hawk tool is to be a community lead tool and provides security support professionals with the tools they need to quickly and easily gather data from O365 and Azure.| [Hawk by T0pCyber](https://github.com/T0pCyber/hawk)
|This repository contains a PowerShell module for detecting artifacts that may be indicators of UNC2452 and other threat actor activity.|[Mandiant AzureAD Investigator](https://github.com/fireeye/Mandiant-Azure-AD-Investigator)|
|This project is to help faciliate testing and low-volume activity data acquisition from the Office 365 Management Activity API.|[O365 InvestigationTooling by Glen Scales](https://github.com/gscales/O365-InvestigationTooling)|
|MIA makes it possible to extract Sessions, MessageID(s) and find emails belonging to the MessageID(s)|[MIA-MailItemsAccessed by PwC IR](https://github.com/PwC-IR/MIA-MailItemsAccessed-)|
|This script makes it possible to extract log data out of an Office365 environment.|[Office 365 Extractor by JoeyRentenaar](https://github.com/JoeyRentenaar/Office-365-Extractor)|
|Invoke-AZExplorer is a set of functions that retrieve vital data from an Azure and 0365 environment used for intrusion analysis.|[Invoke-AZExplorer by Fernando Tomlinson](https://github.com/WiredPulse/Invoke-AZExplorer)|
|This script will process Microsoft Office365 Protection Center Audit Logs into a useable form to allow efficient fitlering and pivoting off events of interest.|[o365AuditParser by Ian Day](https://github.com/iandday/o365AuditParser)
|DART AzureAD IR Powershell Module|[AzureADIncidentResponse](https://www.powershellgallery.com/packages/AzureADIncidentResponse/4.0)
|Magnet AXIOM Cloud|[Magnet AXIOM Cloud](https://www.magnetforensics.com/products/magnet-axiom/cloud/)
|Metaspike Forensic Email Collector|[Metaspike Forensic Email Collector](https://www.metaspike.com/forensic-email-collector/)
|This [Splunk] app contains over 20 unique searches that will help you identify suspicious activity in your Office 365 and Azure environment.|[Blue-team-app-Office-365-and-Azure](https://github.com/invictus-ir/Blue-team-app-Office-365-and-Azure)
|Script to retrieve information via O365 and AzureAD with a valid cred|[o365recon by nyxgeek](https://github.com/nyxgeek/o365recon)
|A Powershell module to run threat hunting playbooks on data from Azure and O365 for Cloud Forensics purposes.|[AzureHunter by Darkquasar](https://github.com/darkquasar/AzureHunter)

## **Google Workspace**

[ATT&CK Google Workspace](https://attack.mitre.org/matrices/enterprise/cloud/googleworkspace/)

## Investigation Research

|Description | Author | Link|
|-|-|-|
|| Megan Roddie | [Automating Google Workspace Incident Response](https://www.youtube.com/watch?v=nW9u4IOD_6M)
|| Megan Roddie | [GSuite Digital Forensics and Incident Response](https://www.youtube.com/watch?v=pGn95-L8_sA)
|| Splunk Threat Research Team | [Investigating GSuite Phishing Attacks with Splunk](https://www.splunk.com/en_us/blog/security/investigating-gsuite-phishing-attacks-with-splunk.html)
|| Arman Gungor at Metaspike | [Investigating Message Read Status in Gmail & Google Workspace](https://www.metaspike.com/message-read-status-gmail-google-workspace/)
|| Arman Gungor at Metaspike | [Gmail History Records in Forensic Email Investigations](https://www.metaspike.com/gmail-history-records-forensic-email-investigations/)
* Arman Gungor at Metaspike | [Google Takeout and Vault in Email Forensics](https://www.metaspike.com/google-takeout-vault-email-forensics/)
