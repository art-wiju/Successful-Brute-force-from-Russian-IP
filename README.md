**Threat Hunting: Successful Brute-force from Russian IP via RDP.**

🕵️ **Overview**

During routine logon monitoring, I identified a series of suspicious brute-force attempts targeting multiple hosts in the environment. The investigation revealed that several malicious external IPs were attempting to log in to devices using invalid credentials. One of these IPs eventually succeeded in accessing a system through a guest account, exposing a misconfigured RDP rule that allowed remote access.

📊 **Initial Detection: Failed Logon Attempts from External IPs**

To begin, I queried the DeviceLogonEvents table to identify hosts that had at least 10 failed logon attempts from the same remote IP address within a 24-hour window.

DeviceLogonEvents 
| where TimeGenerated > ago(24h) and isnotempty(RemoteIP)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by DeviceName, RemoteIP
| where FailedAttempts >= 10
| sort by FailedAttempts desc 

This revealed a pattern of brute-force activity from known malicious IP addresses targeting several endpoints.

a

🔍** Correlation: Failed Attempts Followed by Successful Logon**

To determine if any of these IPs eventually succeeded in gaining access, I ran the following correlation query:

let FailedIPs = 
    DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where isnotempty(RemoteIP)
    | where ActionType == "LogonFailed"
    | summarize FailedAttempts = count(),
        FirstAttempt = min(Timestamp),
        LastAttempt = max(Timestamp)
        by RemoteIP
    | where FailedAttempts >= 10;

DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| join kind=inner (FailedIPs) on RemoteIP
| summarize 
    Devices = make_set(DeviceName),
    Accounts = make_set(AccountName),
    TotalFailedAttempts = max(FailedAttempts),
    FirstFailed = min(FirstAttempt),
    LastFailed = max(LastAttempt),
    FirstSuccess = min(Timestamp)
    by RemoteIP
| sort by TotalFailedAttempts desc

✅ **Result**:

One of the malicious IPs (5.182.5.119) successfully logged into a device using a guest account. This strongly indicated a brute-force login that ultimately succeeded.

**🧪 Root Cause Analysis**

I investigated the affected host (vm-final-lab-je) to determine the attack vector and discovered that Remote Desktop Protocol (RDP) had been temporarily enabled. This was an unauthorized change that bypassed our default workstation policies.

The user later admitted they requested IT to allow RDP access temporarily for remote work, but the firewall rule was never removed — leaving the system exposed.

let targetDevice = "vm-final-lab-je";
let attackerIP = "5.182.5.119";
let compromiseTime = datetime(2025-04-12T13:57:36Z);
DeviceLogonEvents
| where DeviceName == targetDevice
| where RemoteIP == attackerIP
| where AccountName =~ "guest"
| where ActionType == "LogonSuccess"

To look for potential lateral movement, malicious command execution, or post-compromise behavior, I expanded my investigation using the following queries:

📁 **Process Execution**

let targetDevice = "vm-final-lab-je";
let compromiseTime = datetime(2025-04-12T13:57:36Z);
DeviceProcessEvents
| where DeviceName == targetDevice
| where Timestamp > compromiseTime
| where AccountName == "guest"
| where ProcessCommandLine !contains "7z" and ProcessCommandLine !contains "https://raw.githubusercontent.com/joshmadakor1"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc

**🚀 Network Events**

let targetDevice = "vm-final-lab-je";
let compromiseTime = datetime(2025-04-12T13:57:36Z);
DeviceNetworkEvents
| where DeviceName == targetDevice
| where Timestamp > compromiseTime and RemoteIP == "5.182.5.119"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol, ReportId
| order by Timestamp asc

📂 **File Events**

let targetDevice = "vm-final-lab-je";
let compromiseTime = datetime(2025-04-12T13:57:36Z);
DeviceFileEvents
| where DeviceName == targetDevice
| where Timestamp > compromiseTime
| where isnull(FileOriginUrl) or FileOriginUrl !has "github.com"
| where InitiatingProcessCommandLine !has_cs "Microsoft Defender for Endpoint"
    and InitiatingProcessCommandLine !has_cs "Advanced Threat Protection"
    and InitiatingProcessCommandLine !has_cs "joshmadakor1"
    and InitiatingProcessCommandLine !has_cs "\"7z2408-x64.exe\" /S"
    and InitiatingProcessCommandLine !has_cs "pwncrypt"
    and InitiatingProcessCommandLine !has_cs "exfiltratedata"
| project Timestamp, FileName, FolderPath, FileOriginUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc

**Containment and Remediation**

Immediate actions taken:

🚫 Blocked RDP traffic on the affected host via firewall rule.

🦮 Collected forensic image of the machine.

🔍 Investigated for persistence mechanisms (e.g., scheduled tasks, registry changes).

🔁 Scheduled the workstation for re-imaging by system administrators.

🧼 Reviewed and updated internal procedures to ensure temporary firewall changes are properly logged and automatically expired.


📚 **Lessons Learned**

Temporary access configurations must have expiration policies or mandatory cleanup protocols.

Guest accounts should be disabled and monitored — even on test systems.

Continuous logon monitoring paired with automated correlation can catch attacks before lateral movement begins.


💡 **Tools Used**

Microsoft Defender for Endpoint (EDR)

Azure Log Analytics / Kusto Query Language (KQL)

Windows Firewall

Internal asset management and forensic tools


🔐 **Outcome**

The incident was contained before privilege escalation or lateral movement occurred. No sensitive data was exfiltrated, and the vulnerability has been addressed at both the technical and procedural levels.
