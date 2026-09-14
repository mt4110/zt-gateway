# Enterprise Usage Guide: Secure-Scan

[Japanese Version (Original)](../ENTERPRISE_GUIDE.md)

**Target Audience**: Security Operations, Field Engineering Teams, Compliance Officers.
**Version**: 1.0.0
**License**: [Apache-2.0](../../../../LICENSE).

---

## 1. Executive Summary

`secure-scan` is a local-first security tool designed to inspect confidential organizational data and deliverables **while maintaining zero data exfiltration risk**.
Unlike cloud-based antivirus software, it performs virus detection, secret discovery, and metadata sanitization entirely within the local environment (PC) without ever uploading files to internet servers.

## 2. Security Architecture & Trust

### 2.1 Principle of Local Execution
The core feature of this tool is that **"All processing is completed within local memory."**
*   **No Egress**: No scan target file data is ever sent to external networks (SaaS APIs, etc.).
*   **Memory Safety**: Implemented in Go, minimizing memory vulnerability risks such as buffer overflows.
*   **Isolated Environment**: Using Nix technology, required libraries (ClamAV, etc.) run in a sandboxed environment isolated from the system, preventing host OS pollution.

### 2.2 Module Provenance
This tool utilizes globally recognized engines with long-standing track records.

| Module       | Role                  | Provenance / Track Record                                                                                                                              |
| :----------- | :-------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ClamAV**   | Malware Detection     | An open-source antivirus standard maintained by Cisco Talos. Has a track record of blocking billions of threats in mail gateways since 2002.           |
| **YARA**     | Pattern Matching      | Developed by VirusTotal (Google). Known as the "Swiss Army Knife" for malware analysts, used by security vendors worldwide for threat detection rules. |
| **ExifTool** | Metadata Sanitization | The gold standard for metadata manipulation since 2003. Trusted by law enforcement and archival institutions.                                          |

## 3. Scope & Limitations

Understanding "what it can and cannot do" is key to trust in field operations.

### ✅ Covered
*   **Known Malware Detection**: Virus detection based on a database of millions of signatures.
*   **Static Analysis**: Scans contents without executing files, eliminating infection risk from the scan itself.
*   **Deep Scanning**: Recursive unwrapping and scanning of nested archives (e.g., Zip in Tar in Zip).
*   **Metadata Sanitization**: Removes only privacy information (GPS, Author) without damaging the file itself.

### ⚠️ Limitations
*   **Zero-Day Blocking**: Cannot detect unknown viruses (unregistered signatures). It is not behavioral detection (EDR).
*   **Dynamic Analysis (Sandbox)**: Does not verify "what happens when executed".
*   **Cloud-Speed Updates**: Definitions are used from the time of download, so there may be a lag of minutes to hours compared to real-time cloud detection.

## 4. Operational Guidelines

### 4.1 Explicit Working Directory Approval
When the working directory has a Git `origin` remote, set `ZT_SCAN_ALLOWED_REMOTES` to the approved remote URLs. Matching is exact against a comma-separated list. An unset list or unmatched URL blocks startup.

```bash
git remote get-url origin
# Set the URL after reviewing it. This example uses an SSH clone.
export ZT_SCAN_ALLOWED_REMOTES="git@github.com:mt4110/zt-gateway.git"
```

Local directories outside Git and repositories without an `origin` remote remain allowed. The existing `--force-public` option provides an explicit one-off override. Neither option skips file inspection.

This guard confirms the working directory. It does not infer repository visibility or file safety from a remote URL.

### 4.2 Update Policy
Threat information changes daily. Ensure "freshness" before use:

```bash
# 1. Update Tool Definitions (Recommended Daily)
secure-scan update

# 2. Run Scan
secure-scan check ./project-dir
```

### 4.3 Vulnerability & Incident Response
In the event a vulnerability is found in a dependent library (like ClamAV):
1.  **Nix Flake Update**: The admin team immediately updates `flake.lock` and issues a PR.
2.  **Immediate Application**: Users simply run `nix develop` to switch to the patched, safe binary.

---
### 4.4 Definition Freshness and Detection Coverage
Update frequency alone does not guarantee detection rates or protection from unknown threats. This project has not measured detection coverage. Check definition update results before use and evaluate coverage for the scanners, rules, and input formats in your environment.

---
**Disclaimer**: This tool significantly reduces security risk but does not guarantee 100% safety. Please use in conjunction with other defense layers (EDR, Firewall).
