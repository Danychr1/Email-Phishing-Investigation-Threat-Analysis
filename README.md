# Email-Phishing-Investigation-Threat-Analysis

A real-world phishing email investigation demonstrating SOC Tier 1 workflows, indicator validation, and structured incident documentation using industry-standard open-source tools.

<img width="1452" height="980" alt="Screenshot 2026-02-04 at 2 02 07 PM" src="https://github.com/user-attachments/assets/f72a1a73-e311-4aea-8c69-2fa84f4eb8f3" />


## 🧠 Lab Overview

This project documents the analysis of a real phishing email crafted to impersonate a legitimate email verification request. Acting as a SOC analyst, I performed initial email triage by reviewing message headers, analyzing encoded content, inspecting embedded links, and extracting indicators of compromise (IOCs).

The investigation follows standard SOC procedures for identifying, validating, and documenting email-based threats, closely reflecting how phishing incidents are handled in operational security environments.

## 🛡️ Investigation Workflow (Step-by-Step SOC Process)

**Note** I am going to use a Windows (Virtual Machine) to perform  my analysis using Notepad++; however, you can use whatever text editor you prefer.  

### Step 1: Email Collection & Preservation

* Collected the suspicious email as a .eml file to preserve evidence

* Captured screenshots of the sender, subject, and rendered email body

* Avoided interacting with links or attachments

### Step 2: Visual Email Inspection

* Reviewed the email body for phishing indicators such as urgency, impersonation, and suspicious formatting

* Identified mismatched sender information and deceptive messaging

📁 [1_raw_email/](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/1_raw_email)

### Step 3: Email Header Analysis

* Extracted full email headers and analyzed them using MXToolbox

* Reviewed From, Return-Path, and Received fields

* Evaluated SPF, DKIM, and DMARC authentication results

* Identified sending IP addresses and mail server infrastructure


### Step 4: IP & Domain Reputation Validation

* Checked sending IPs and domains against reputation and blacklist databases

* Identified suspicious or previously reported infrastructure

📁 [2_header_analysis/](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/2_header_analysis)

### Step 5: Decoding Encoded Email Content

* Identified quoted-printable encoded content within the email

* Used CyberChef to decode and inspect hidden HTML and URLs

* Extracted obfuscated phishing links
  

### Step 6: Safe Phishing Link Analysis

* Submitted suspicious URLs to URLScan.io for behavioral analysis

* Reviewed redirect chains, page behavior, and visual evidence

* Confirmed credential harvesting behavior

📁 [3_link_analysis/](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/3_link_analysis)

### Step 7: IOC Extraction

* Extracted actionable indicators, including:

    - Malicious IP addresses

    - Domains and URLs

    - Sender email addresses

* Documented IOCs in a structured format



### Step 8: Incident Classification

* Classified the incident as Confirmed Phishing

* Identified attack vector as Phishing – Link

* Mapped activity to MITRE ATT&CK:

    - [TA0001](https://attack.mitre.org/tactics/TA0001/) – Initial Access

    - [T1566.002](https://attack.mitre.org/techniques/T1566/002/) – Phishing: Link


### Step 9: Reporting & Recommendations

* Documented findings in a concise incident summary

* Provided remediation recommendations, including:

  - Blocking malicious domains and IPs

  - Updating email security rules

  - User awareness guidance

📁 [4_findings/](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/4_findings)


## 🧰 Skills Demonstrated

- Email header parsing and sender authentication analysis

- IP address, domain, and URL reputation validation

- Decoding and inspection of quoted-printable email content

- Phishing URL analysis and threat confirmation

- IOC extraction, validation, and documentation

- Incident reporting and case documentation

- Structured GitHub repository organization

## 🛠️ Tools Used

- [MXToolbox](https://mxtoolbox.com/) – Email header analysis, SPF/DKIM checks, and blacklist validation

- [URLScan.io](https://urlscan.io/)  – Behavioral analysis of suspicious URLs, redirects, and page content

- [AbuseIPDB](https://www.abuseipdb.com/) – Reputation assessment of associated IP addresses and infrastructure
  
- [CyberChef](https://gchq.github.io/CyberChef/) – Decoding and analyzing encoded email content

- [Malware-traffic-analysis](https://www.malware-traffic-analysis.net/) – Source of real phishing email samples

- **GitHub**  – Investigation documentation and case management


## 📁 Repository Structure

1- [**raw_email/**](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/1_raw_email) – Original .eml file and rendered email screenshots

2- [**header_analysis/**](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/2_header_analysis) – Header inspection, IP reputation checks, and blacklist results

3- [**link_analysis/**](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/3_link_analysis) – Embedded link inspection and HTML analysis

4- [**findings/**](https://github.com/Danychr1/Email-Phishing-Investigation-Threat-Analysis/tree/main/4_findings) – Extracted IOCs and investigation summary

5- extras/ – Supplemental notes and supporting evidence

## 🔎 SOC Relevance

This lab demonstrates how a SOC analyst conducts structured email triage, validates malicious indicators, and documents findings for escalation or response. The project highlights practical experience with phishing detection, threat intelligence validation, and clear security reporting aligned with Tier 1 SOC responsibilities.

