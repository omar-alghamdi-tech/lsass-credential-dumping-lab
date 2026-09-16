# 🎯 Threat Hunting: LSASS Credential Dumping via Task Manager

## 📖 Scenario Overview
Adversaries often attempt to extract credentials from the Local Security Authority Subsystem Service (LSASS) memory to conduct lateral movement. In this lab, I simulated a local execution attack where an adversary uses the native Windows Task Manager (`taskmgr.exe`) to dump the `lsass.exe` process memory to disk, intentionally bypassing basic security controls to test detection capabilities.

* **MITRE ATT&CK Tactic:** Credential Access (TA0006)
* **MITRE ATT&CK Technique:** OS Credential Dumping: LSASS Memory (T1003.001)

---

## 🛠️ Lab Environment & Setup
To properly detect this malicious activity, I configured a dedicated virtual environment with enhanced telemetry.

* **Hypervisor:** Oracle VirtualBox
* **Operating System:** Windows 10 Enterprise
* **Telemetry/Visibility:** Sysmon (Sysinternals) with SwiftOnSecurity configuration.

**Environment Preparation:**

<img width="952" height="927" alt="1" src="https://github.com/user-attachments/assets/341a5915-a0e3-4db6-b8e1-a81e5ed93b00" />

<img width="940" height="395" alt="2" src="https://github.com/user-attachments/assets/03bab908-0bce-4bd1-a16a-be9d6f8baaa2" />


<img width="1007" height="722" alt="3" src="https://github.com/user-attachments/assets/3c970a0a-fa83-437c-93ed-a2ba8d48cc02" />


<img width="721" height="365" alt="4" src="https://github.com/user-attachments/assets/5aa5cd1b-86f0-47a5-8673-7c5e3bd74228" />

---

## ⚔️ Attack Simulation
With the telemetry in place and Windows Defender Real-time Protection temporarily disabled, the simulation was executed:
1. Launched Task Manager (`taskmgr.exe`) and navigated to the **Details** tab.
2. Located the highly privileged `lsass.exe` process.
3. Executed a manual memory dump by selecting **Create dump file**.

**Execution Evidences:**

<img width="987" height="300" alt="5" src="https://github.com/user-attachments/assets/e26b3eda-7492-49fe-b2d4-6247a5cd1fcf" />

<img width="465" height="271" alt="6" src="https://github.com/user-attachments/assets/6d8f3577-0acb-4d38-b625-8de5ec95d611" />



---

## 🔍 Investigation & Threat Hunting
Initially, one might look for Event ID 10 (Process Access). However, robust configurations often tune out `taskmgr.exe` accessing processes to reduce SIEM noise. Recognizing this visibility gap, I pivoted my hunt to focus on artifact creation on the disk.

By filtering Sysmon logs for **Event ID 11 (File Create)**, I successfully identified the exact moment the payload was dropped.

**Hunting Process:**

<img width="802" height="447" alt="7" src="https://github.com/user-attachments/assets/b174a65f-d9d5-4e5c-a2b2-729af9e8f78d" />

<img width="937" height="441" alt="8" src="https://github.com/user-attachments/assets/c42658ee-88ef-48ba-a53d-de0e2bc5b7a4" />


<img width="796" height="472" alt="9" src="https://github.com/user-attachments/assets/f6ebaf57-cac3-4fff-a747-81566e6254cc" />


**🎯 The Golden Artifact (IoC):**

<img width="625" height="597" alt="10" src="https://github.com/user-attachments/assets/13ba6a7c-a372-4990-b987-b2c34375d799" />



**Key Findings:**
* **Image (Source Process):** `C:\Windows\System32\taskmgr.exe`
* **TargetFilename (Malicious Output):** `C:\Users\*\AppData\Local\Temp\lsass.DMP`

---

## 🛡️ Detection Rule (Kusto Query Language - KQL)
To automate the detection of this specific evasion technique in a SOC environment, I developed the following detection logic. This query alerts when Task Manager creates a dump file associated with LSASS.

```kusto
Sysmon_Event_11
| where EventID == 11
| where Image endswith "taskmgr.exe"
| where TargetFilename contains "lsass" and TargetFilename endswith ".DMP"
| project TimeGenerated, Computer, User, Image, TargetFilename
