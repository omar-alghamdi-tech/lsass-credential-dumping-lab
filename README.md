# Threat Hunting Lab: LSASS Credential Dumping via Task Manager

![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-0078D6?style=flat-square&logo=windows&logoColor=white)
![Sigma](https://img.shields.io/badge/Detection-Sigma_Rule-6A5ACD?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-T1003.001-red?style=flat-square)

---

## 📋 Scenario Overview

Adversaries often extract credentials from the memory of the **Local Security Authority Subsystem Service (LSASS)** to move laterally across a network. In this lab, I simulated an attacker who uses the built-in Windows **Task Manager** (`taskmgr.exe`) to dump `lsass.exe` memory to disk — a "living off the land" technique that needs no extra tools — and then hunted for it using Sysmon telemetry.

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |

## 🧪 Lab Environment & Setup

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Operating System | Windows 10 Enterprise |
| Telemetry | Sysmon (Sysinternals) with the SwiftOnSecurity configuration |

**Environment preparation:**

<img width="952" height="927" alt="Sysmon installation" src="https://github.com/user-attachments/assets/341a5915-a0e3-4db6-b8e1-a81e5ed93b00" />

<img width="940" height="395" alt="Sysmon configuration" src="https://github.com/user-attachments/assets/03bab908-0bce-4bd1-a16a-be9d6f8baaa2" />

<img width="1007" height="722" alt="Sysmon service running" src="https://github.com/user-attachments/assets/3c970a0a-fa83-437c-93ed-a2ba8d48cc02" />

<img width="721" height="365" alt="Environment ready" src="https://github.com/user-attachments/assets/5aa5cd1b-86f0-47a5-8673-7c5e3bd74228" />

---

## 🔴 Attack Simulation

With telemetry in place and Windows Defender Real-time Protection temporarily disabled (to observe the technique without being blocked), the attack was executed:

1. Opened Task Manager (`taskmgr.exe`) and went to the **Details** tab.
2. Located the highly privileged `lsass.exe` process.
3. Right-clicked it and selected **Create dump file**.

**Execution evidence:**

<img width="987" height="300" alt="Creating LSASS dump from Task Manager" src="https://github.com/user-attachments/assets/e26b3eda-7492-49fe-b2d4-6247a5cd1fcf" />

<img width="465" height="271" alt="Dump file created successfully" src="https://github.com/user-attachments/assets/6d8f3577-0acb-4d38-b625-8de5ec95d611" />

> ⚠️ Disabling Defender was a lab choice. In a real environment, Defender and **Credential Guard / LSA Protection (RunAsPPL)** would block or limit this technique — which is exactly why defenders must also be able to detect it when protections are missing or misconfigured.

---

## 🔵 Investigation & Threat Hunting

The obvious place to look is **Sysmon Event ID 10 (ProcessAccess)** — a process opening a handle to `lsass.exe`. However, many production configurations (including SwiftOnSecurity's) exclude `taskmgr.exe` from Event ID 10 to reduce noise.

**Recognizing this visibility gap, I pivoted the hunt to the artifact left on disk:** filtering Sysmon for **Event ID 11 (FileCreate)** revealed the exact moment the dump file was written.

**Hunting process:**

<img width="802" height="447" alt="Filtering Sysmon logs" src="https://github.com/user-attachments/assets/b174a65f-d9d5-4e5c-a2b2-729af9e8f78d" />

<img width="937" height="441" alt="Sysmon Event ID 11 results" src="https://github.com/user-attachments/assets/c42658ee-88ef-48ba-a53d-de0e2bc5b7a4" />

<img width="796" height="472" alt="Narrowing down to the dump file" src="https://github.com/user-attachments/assets/f6ebaf57-cac3-4fff-a747-81566e6254cc" />

**The golden artifact (IoC):**

<img width="625" height="597" alt="Sysmon Event ID 11 showing taskmgr.exe creating lsass.DMP" src="https://github.com/user-attachments/assets/13ba6a7c-a372-4990-b987-b2c34375d799" />

**Key findings:**

| Field | Value |
|---|---|
| `Image` (source process) | `C:\Windows\System32\taskmgr.exe` |
| `TargetFilename` (output) | `C:\Users\<user>\AppData\Local\Temp\lsass.DMP` |

> 💡 **Lesson:** when one data source is tuned out, look for a different stage of the same attack. Here, the *process access* was invisible, but the *file it produced* was not.

---

## 🛡️ Detection Engineering

The same logic is provided in three formats so it can be used in different SOC environments.

### 1. Sigma Rule (vendor-neutral)
Full rule: [`detections/lsass_dump_taskmgr.yml`](detections/lsass_dump_taskmgr.yml)

```yaml
logsource:
  product: windows
  category: file_event   # Sysmon Event ID 11
detection:
  selection:
    Image|endswith: '\taskmgr.exe'
    TargetFilename|contains: 'lsass'
    TargetFilename|endswith: '.dmp'
  condition: selection
level: high
```

Sigma rules can be converted to almost any SIEM query language with [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli).

### 2. IBM QRadar (AQL)
Hunting query for Sysmon events collected through WinCollect:

```sql
SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       LOGSOURCENAME(logsourceid) AS host,
       username,
       UTF8(payload) AS raw_event
FROM events
WHERE UTF8(payload) ILIKE '%Microsoft-Windows-Sysmon%'
  AND UTF8(payload) ILIKE '%taskmgr.exe%'
  AND UTF8(payload) ILIKE '%lsass%.dmp%'
ORDER BY starttime DESC
LAST 7 DAYS
```

> Searching the raw payload works everywhere but is slow on large datasets. For a production rule, create **Custom Event Properties** for `Image` and `TargetFilename` and filter on those instead.

### 3. Microsoft Defender for Endpoint / Sentinel (KQL)

```kusto
DeviceFileEvents
| where InitiatingProcessFileName =~ "taskmgr.exe"
| where FileName contains "lsass" and FileName endswith ".dmp"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName
```

---

## ✅ Defensive Recommendations

1. **Enable LSA Protection (RunAsPPL)** so non-protected processes cannot read LSASS memory.
2. **Enable Credential Guard** on supported systems to isolate credential secrets.
3. **Keep Defender / EDR active** — Attack Surface Reduction rule *"Block credential stealing from LSASS"* blocks this behavior.
4. **Limit local admin rights** — dumping LSASS requires administrative privileges.
5. **Alert on any `*.dmp` file containing `lsass` in its name**, regardless of the process that created it.

## 🔭 Next Steps

- Simulate other LSASS dumping methods (`rundll32 comsvcs.dll MiniDump`, `procdump`) and compare the artifacts each one leaves.
- Build a broader detection based on Sysmon **Event ID 10** with suspicious `GrantedAccess` values.

---

👤 **Omar Alghamdi** — SOC Analyst | Threat Hunting · [LinkedIn](https://www.linkedin.com/in/omar-al-ghamdi-) · [X](https://x.com/Omar_Cyber7)
