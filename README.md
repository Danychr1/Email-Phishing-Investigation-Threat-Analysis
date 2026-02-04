# Email-Phishing-Investigation-Threat-Analysis

A real-world phishing email investigation demonstrating SOC Tier 1 workflows, indicator validation, and structured incident documentation using industry-standard open-source tools.

## 🧠 Lab Overview

This project documents the analysis of a real phishing email crafted to impersonate a legitimate email verification request. Acting as a SOC analyst, I performed initial email triage by reviewing message headers, analyzing encoded content, inspecting embedded links, and extracting indicators of compromise (IOCs).

The investigation follows standard SOC procedures for identifying, validating, and documenting email-based threats, closely reflecting how phishing incidents are handled in operational security environments.

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

- [URLScan.io](https://urlscan.io/) – Behavioral analysis and reputation assessment of suspicious URLs

- [CyberChef](https://gchq.github.io/CyberChef/) – Decoding and analyzing encoded email content

- [Malware-traffic-analysis](https://www.malware-traffic-analysis.net/) – Source of real phishing email samples

- **GitHub**  – Investigation documentation and case management


## 📁 Repository Structure

1- raw_email/ – Original .eml file and rendered email screenshots

2- header_analysis/ – Header inspection, IP reputation checks, and blacklist results

3- link_analysis/ – Embedded link inspection and HTML analysis

4- findings/ – Extracted IOCs and investigation summary

5- extras/ – Supplemental notes and supporting evidence

## 🔎 SOC Relevance

This lab demonstrates how a SOC analyst conducts structured email triage, validates malicious indicators, and documents findings for escalation or response. The project highlights practical experience with phishing detection, threat intelligence validation, and clear security reporting aligned with Tier 1 SOC responsibilities.

## 🧩 MITRE ATT&CK Mapping

TA0001 – Initial Access

T1566.002 – Phishing: Link
