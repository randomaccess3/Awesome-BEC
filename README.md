# Awesome-BEC

Repository of attack and defensive information for Business Email Compromise investigations

## **Office365/AzureAD**

* [ATT&CK O365](https://attack.mitre.org/matrices/enterprise/cloud/office365/)
* [ATT&CK Azure](https://attack.mitre.org/matrices/enterprise/cloud/azuread/)
* [Microsoft Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/)
* [Microsoft 365 Licensing](https://m365maps.com/)
* [Microsoft Portals](https://msportals.io/)
* [Azure App IDs](https://github.com/Beercow/Azure-App-IDs)

### Attack/Defend Research

Author | Link|
|-|-|
Lina Lau | [Backdoor Office 365 and Active Directory - Golden SAML](https://www.inversecos.com/2021/09/backdooring-office-365-and-active.html)
Lina Lau | [Office365 Attacks: Bypassing MFA, Achieving Persistence and More - Part I](https://www.inversecos.com/2021/09/office365-attacks-bypassing-mfa.html)
Lina Lau | [Attacks on Azure AD and M365: Pawning the cloud, PTA Skeleton Keys and more - PART II](https://www.inversecos.com/2021/10/attacks-on-azure-ad-and-m365-pawning.html)
Mike Felch and Steve Borosh | [Socially Acceptable Methods to Walk in the Front Door](https://www.slideshare.net/MichaelFelch/socially-acceptable-methods-to-walk-in-the-front-door)
Mandiant | [Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
Andy Robbins at SpecterOps | [Azure Privilege Escalation via Service Principal Abuse](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5)
Emilian Cebuc & Christian Philipov at F-Secure|[Has anyone seen the principal?](https://www.youtube.com/watch?v=WauAoaKyeaw&t=12673s)
nyxgeek at TrustedSec |[Creating A Malicious Azure AD Oauth2 Application](https://www.trustedsec.com/blog/creating-a-malicious-azure-ad-oauth2-application/)
Lina Lau|[How to Backdoor Azure Applications and Abuse Service Principals](https://www.inversecos.com/2021/10/how-to-backdoor-azure-applications-and.html)
Lina Lau|[How to Detect Azure Active Directory Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)
Doug Bienstock at Mandiant|[PwnAuth](https://github.com/mandiant/PwnAuth)
Steve Borosh at Black Hills Information Secucirty|[Spoofing Microsoft 365 Like It’s 1995](https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/)
Avertium|[MITM Attacks - Evilproxy and Evilginx](https://www.avertium.com/resources/threat-reports/mitm-attacks-evilproxy-and-evilginx)
Aon Cyber Labs|[Bypassing MFA: A Forensic Look At Evilginx2 Phishing Kit](https://www.aon.com/cyber-solutions/aon_cyber_labs/bypassing-mfa-a-forensic-look-at-evilginx2-phishing-kit/)


### Investigation Research

Author | Link|
|-|-|
Devon Ackerman (SANS DFIR Summit 2018) | [A Planned Methodology for Forensically Sound IR in Office 365](https://www.youtube.com/watch?v=CubGixACC4E)
Matt Bromiley | [Business Email Compromise; Office 365 Making Sense of All the Noise](https://www.youtube.com/watch?v=JMFB4TodjkE)
PWC IR | [Business Email Compromise Guide](https://github.com/PwC-IR/Business-Email-Compromise-Guide)
Korstiann Stam (SANS DFIR Summit 2021) | [A Holistic Approach to Defending Business Email Compromise (BEC) Attacks](https://www.youtube.com/watch?v=sV-BzlHSyes)
M365 Internals | [Everything About Service Principals, Applications, And API Permissions](https://m365internals.com/2021/07/24/everything-about-service-principals-applications-and-api-permissions/)
M365 Internals | [What I Have Learned From Doing A Year Of Cloud Forensics In Azure AD](https://m365internals.com/2021/07/13/what-ive-learned-from-doing-a-year-of-cloud-forensics-in-azure-ad/)
M365 Internals | [Incident Response In A Microsoft Cloud Environment](https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/)
M365 Internals | [Incident Response Series: Reviewing Data In Azure AD For Investigation](https://m365internals.com/2021/03/16/incident-response-series-reviewing-data-in-azure-ad-for-investigation/)
M365 Internals | [Incident Response Series: Collecting And Analyzing Logs In Azure Ad](https://m365internals.com/2021/03/08/incident-response-series-collecting-and-analyzing-logs-in-azure-ad/)
Microsoft | [How automated investigation and response works in Microsoft Defender for Office 365](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/automated-investigation-response-office?view=o365-worldwide)
Microsoft | [Incident Response playbooks](https://docs.microsoft.com/en-us/security/compass/incident-response-playbooks)
Brendan Mccreesh | [Matching the O365 MachineID to a computer’s MachineGUID](https://digitalforensicsdotblog.wordpress.com/2020/08/18/matching-an-o365-machineid-to-a-computers-machineguid/)
BushidoToken| [Abused legitimate services](https://github.com/BushidoUK/Abused-Legitimate-Services)
Dave Herrald and Ryan Kovar (SANS CTI Summit 2019) |[How to Use and Create Threat Intelligence in an Office 365 World](https://www.youtube.com/watch?v=bznFYWcUjtc)
Mangatas Tondang | [Knocking on Clouds Door: Threat Hunting Powered by Azure AD Reports and Azula](https://www.youtube.com/watch?v=7HIj5I-O_Co)
Mathieu Saulnier|[IRP Phishing](https://gitlab.com/syntax-ir/playbooks/-/tree/main/IRP-Phishing)
Crypsis|[Securing O365 with PowerShell](https://cdn2.hubspot.net/hubfs/4266002/Securing%20O365%20With%20PowerShell.pdf)
Aon|[Microsoft 365: Identifying Mailbox Access](https://www.aon.com/cyber-solutions/aon_cyber_labs/microsoft-365-identifying-mailbox-access/)
Will Oram|[Responding to sophisticated attacks on Microsoft 365 and Azure AD](https://github.com/WillOram/AzureAD-incident-response)
Frankie Li, Ken Ma and Eric Leung at Dragon Advance Tech Consulting|[Microsoft 365 Forensics Playbook](https://dragonadvancetech.com/reports/M365%20Forensics%20Playbook_v3.pdf)
Christopher Romano and Vaishnav Murthy at Crowdstrike|[Cloudy with a Chance of Unclear Mailbox Sync: CrowdStrike Services Identifies Logging Inconsistencies in Microsoft 365](https://www.crowdstrike.com/blog/crowdstrike-services-identifies-logging-inconsistencies-in-microsoft-365/)
Megan Roddie at SANS|[Enterprise Cloud Forensics & Incident Response Poster](https://www.sans.org/posters/enterprise-cloud-forensics-incident-response-poster/)
Thirumalai Natarajan Muthiah & Anurag Khanna (SANS DFIR Summit 2022)|[Threat Hunting in Microsoft 365 Environment](https://www.youtube.com/watch?v=2A0faMIEp00)
Josh Lemon & Megan Roddie (SANS DFIR Summit 2022)|[DFIR Evidence Collection and Preservation for the Cloud](https://www.youtube.com/watch?v=1TyjsnqgC5o)
Microsoft|[Verify first-party Microsoft applications in sign-in reports](https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in)
Douglas Bienstock at Mandiant|[You Can’t Audit Me: APT29 Continues Targeting Microsoft 365](https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft)
Lina Lau|[How to Detect OAuth Access Token Theft in Azure](https://www.inversecos.com/2022/08/how-to-detect-oauth-access-token-theft.html)
Michel De Crevoisier at Red Canary|[Forward thinking: How adversaries abuse Office 365 email rules](https://redcanary.com/blog/o365-email-rules-mindmap/)
Emily Parrish at Microsoft|[Forensic artifacts in Office 365 and where to find them](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/forensic-artifacts-in-office-365-and-where-to-find-them/ba-p/3634865)
Justin Schoenfeld and Zach Diehl at Red Canary|[Cloud coverage: Detecting an email payroll diversion attack](https://redcanary.com/blog/email-payroll-diversion-attack/)
CrowdStrike|[Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign](https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/)
Aon|[SCL -1: The Dangerous Side Of Safe Senders](https://www.aon.com/cyber-solutions/aon_cyber_labs/scl-1-the-dangerous-side-of-safe-senders/)
Jon Hencinski|[Seven ways to spot a business email compromise in Office 365](https://expel.com/blog/seven-ways-to-spot-business-email-compromise-office-365/)
Emily Parrish at Microsoft|[Good UAL Hunting](https://techcommunity.microsoft.com/t5/microsoft-security-experts-blog/good-ual-hunting/ba-p/3718421)
Invictus Incident Respone|[Mastering Email Forwarding Rules in Microsoft 365](https://invictus-ir.medium.com/email-forwarding-rules-in-microsoft-365-295fcb63d4fb)
Microsoft Threat Intelligence|[DEV-1101 enables high-volume AiTM campaigns with open-source phishing kit](https://www.microsoft.com/en-us/security/blog/2023/03/13/dev-1101-enables-high-volume-aitm-campaigns-with-open-source-phishing-kit/)

### Secure configuration guidance

|Author|Link|
|-|-|
|NCSC Ireland|[Office 365 Secure Configuration Framework](https://www.ncsc.gov.ie/pdfs/NCSC_Office_365_Secure_Configuration_Framework.pdf)
|CISA|[Microsoft Office 365 Security Recommendations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-120a)

### Datasets

|Description| Author | Link |
|-|-|-|
|A dataset containing Office 365 Unified Audit Logs for security research and detection. | Invictus IR | [O365 Dataset](https://github.com/invictus-ir/o365_dataset)|

## **Google Workspace**

[ATT&CK Google Workspace](https://attack.mitre.org/matrices/enterprise/cloud/googleworkspace/)

### Investigation Research

|Description | Author | Link|
|-|-|-|
|| Megan Roddie (SANS DFIR Summit 2021) | [Automating Google Workspace Incident Response](https://www.youtube.com/watch?v=nW9u4IOD_6M)
|| Megan Roddie (BSides SATX) | [GSuite Digital Forensics and Incident Response](https://www.youtube.com/watch?v=pGn95-L8_sA)
|| Splunk Threat Research Team | [Investigating GSuite Phishing Attacks with Splunk](https://www.splunk.com/en_us/blog/security/investigating-gsuite-phishing-attacks-with-splunk.html)
|| Arman Gungor at Metaspike | [Investigating Message Read Status in Gmail & Google Workspace](https://www.metaspike.com/message-read-status-gmail-google-workspace/)
|| Arman Gungor at Metaspike | [Gmail History Records in Forensic Email Investigations](https://www.metaspike.com/gmail-history-records-forensic-email-investigations/)
|| Arman Gungor at Metaspike | [Google Takeout and Vault in Email Forensics](https://www.metaspike.com/google-takeout-vault-email-forensics/)
|| Megan Roddie at SANS | [Prevent, Detect, Respond An Intro to Google Workspace Security and Incident Response](https://www.youtube.com/watch?v=-90S8fMUprc)
||Korstiaan Stam (SANS DFIR Summit 2022)|[Detecting Malicious Actors in Google Workspace](https://www.youtube.com/watch?v=HzuVhbpO_go)
||Invictus IR|[Automated Forensic analysis of Google Workspace](https://invictus-ir.medium.com/automated-forensic-analysis-of-google-workspace-859ed50c5c92)

### Datasets

|Description| Author | Link |
|-|-|-|
|A dataset containing Google Workspace Logs for security research and detection. | Invictus Incident Response | [GWS Dataset](https://github.com/invictus-ir/gws_dataset)|

## Tools

### Adversary Emulation Tools

| Author | Link |
|-|-|
| MDSec | [o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)
| Daniel Chronlund| [Microsoft 365 Data Exfiltration – Attack and Defend](https://danielchronlund.com/2023/02/09/microsoft-365-data-exfiltration-attack-and-defend/)

### Phishing Toolkits

|Author | Link |
|-|-|
Kuba Gretzky | [Evilginx2](https://github.com/kgretzky/evilginx2)
Cult of Cornholio |[Solenya](https://github.com/CultCornholio/solenya)
Black Hills Information Security | [CredSniper](https://github.com/ustayready/CredSniper)
Mandiant | [ReelPhish](https://github.com/mandiant/ReelPhish)
Piotr Duszynski|[Modiishka](https://github.com/drk1wi/Modlishka)

### Investigation Tools

|Description|Author|Link|
|-|-|-|
|Automate the security assessment of Microsoft Office 365 environments |Soteria Security|[365Inspect](https://github.com/soteria-security/365Inspect)|
|A set of functions that allow the DFIR analyst to collect logs relevant for Office 365 Business Email Compromise and Azure investigations | ANSSI-FR | [DFIR-O365RC](https://github.com/ANSSI-FR/DFIR-O365RC/archive/refs/heads/main.zip)|
| Queries configurations in the Azure AD/O365 tenant which can shed light on hard-to-find permissions and configuration settings in order to assist organizations in securing these environments | CrowdStrike|[CrowdStrike Reporting Tool for Azure (CRT)](https://github.com/CrowdStrike/CRT)|
|Aviary is a new dashboard that CISA and partners developed to help visualize and analyze outputs from its Sparrow detection tool released in December 2020|CISA|[Aviary/SPARROW](https://github.com/cisagov/Sparrow)
|The goal of the Hawk tool is to be a community lead tool and provides security support professionals with the tools they need to quickly and easily gather data from O365 and Azure.|T0pCyber|[Hawk](https://github.com/T0pCyber/hawk)
|This repository contains a PowerShell module for detecting artifacts that may be indicators of UNC2452 and other threat actor activity.|Mandiant|[Mandiant AzureAD Investigator](https://github.com/fireeye/Mandiant-Azure-AD-Investigator)|
|This project is to help faciliate testing and low-volume activity data acquisition from the Office 365 Management Activity API.|Glen Scales|[O365 InvestigationTooling](https://github.com/gscales/O365-InvestigationTooling)|
|MIA makes it possible to extract Sessions, MessageID(s) and find emails belonging to the MessageID(s)|PwC IR|[MIA-MailItemsAccessed](https://github.com/PwC-IR/MIA-MailItemsAccessed-)|
|This script makes it possible to extract log data out of an Office365 environment.|JoeyRentenaar|[Office 365 Extractor](https://github.com/JoeyRentenaar/Office-365-Extractor)|
|Invoke-AZExplorer is a set of functions that retrieve vital data from an Azure and 0365 environment used for intrusion analysis.|Fernando Tomlinson|[Invoke-AZExplorer](https://github.com/WiredPulse/Invoke-AZExplorer)|
|This script will process Microsoft Office365 Protection Center Audit Logs into a useable form to allow efficient fitlering and pivoting off events of interest.|Ian Day|[o365AuditParser](https://github.com/iandday/o365AuditParser)
|DART AzureAD IR Powershell Module|Microsoft DART|[AzureADIncidentResponse](https://www.powershellgallery.com/packages/AzureADIncidentResponse/4.0)
|Magnet AXIOM Cloud|Magnet Forensics|[Magnet AXIOM Cloud](https://www.magnetforensics.com/products/magnet-axiom/cloud/)
|Metaspike Forensic Email Collector|Metaspike|[Metaspike Forensic Email Collector](https://www.metaspike.com/forensic-email-collector/)
|Metaspike Forensic Email Intelligence|Metaspike|[Metaspike Forensic Email Intelligence](https://www.metaspike.com/forensic-email-intelligence/)
|This [Splunk] app contains over 20 unique searches that will help you identify suspicious activity in your Office 365 and Azure environment.|Invictus IR|[Blue-team-app-Office-365-and-Azure](https://github.com/invictus-ir/Blue-team-app-Office-365-and-Azure)
|Script to retrieve information via O365 and AzureAD with a valid cred|nyxgeek|[o365recon](https://github.com/nyxgeek/o365recon)
|A Powershell module to run threat hunting playbooks on data from Azure and O365 for Cloud Forensics purposes.|Darkquasar|[AzureHunter](https://github.com/darkquasar/AzureHunter)
|SOF-ELK® is a “big data analytics” platform focused on the typical needs of computer forensic investigators/analysts and information security operations personnel.|Phil Hagen at SANS|[SOF-ELK](https://github.com/philhagen/sof-elk)
|A collection of scripts for finding threats in Office365|Martin Rothe|[Py365](https://github.com/mrrothe/py365)
|Parsing the O365 Unified Audit Log with Python|Koen Van Impe|[O365-python-parse](https://github.com/cudeso/tools/tree/master/O365-python-parse)
|Identifying phishing page toolkits|Brian Kondracki, Babak Amin Azad, Oleksii Starov, and Nick Nikiforakis|[Phoca](https://github.com/catching-transparent-phish/phoca)
|An Open Source PowerShell O365 Business Email Compromise Investigation Tool|intrepidtechie|[KITT-O365-Tool](https://github.com/intrepidtechie/KITT-O365-Tool)
|Tooling for assessing an Azure AD tenant state and configuration|Microsoft|[Microsoft Azure AD Assessment](https://github.com/AzureAD/AzureADAssessment)
|ROADtools is a framework to interact with Azure AD|Dirk-jan|[ROADtools](https://github.com/dirkjanm/ROADtools)
|Automated Audit Log Forensic Analysis for Google Workspace|Invictus IR|[ALFA](https://github.com/invictus-ir/ALFA)
|Tool aids hunting and Incident Response in Azure, Azure Active Directory, and Microsoft 365 Environments|CISA|[Untitled Goose](https://www.cisa.gov/news-events/alerts/2023/03/23/untitled-goose-tool-aids-hunt-and-incident-response-azure-azure-active-directory-and-microsoft-365)
|PowerShell module to collect logs and rules from M365|Invictus IR|[Welcome 👋 Microsoft Extractor Suite](https://invictus-ir.medium.com/welcome-microsoft-extractor-suite-e54a292e2c36)

### Assessment Tools

|Author|Link|
|-|-|
CISA|[ScubaGear M365 Secure Configuration Baseline Assessment Tool](https://github.com/cisagov/ScubaGear)
Gerenios|[AADInternals](https://github.com/Gerenios/AADInternals)

## Training

|Author/s|Link|
|-|-|
|David Cowen, Pierre Lidome, Josh Lemon and Megan Roddie at SANS|[FOR509: Enterprise Cloud Forensics and Incident Response](https://www.sans.org/cyber-security-courses/enterprise-cloud-forensics-incident-response/)
Lina Lau|[Attacking and Defending Azure & M365](https://training.xintra.org/attacking-and-defending-azure-m365)
