# Attack Simulation: Atomic Red Team Tests

## Overview

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (ART) is an open-source library of small, portable tests mapped to the MITRE ATT&CK framework. Each test simulates a specific adversary technique, allowing defenders to validate their detection capabilities.

All tests are executed on **Target-PC (192.168.10.100)** via an Administrator PowerShell session.

---

## Setup

```powershell
# Import the module (required each new PowerShell session)
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
```

---

## Tests Executed

### T1136.001 — Create Account: Local Account

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **What It Does** | Creates a local user account via `net user /add` |
| **Detection** | Security EventCode=4720, Sysmon EID 1 (net.exe) |

```powershell
# Run the test
Invoke-AtomicTest T1136.001

# Clean up after validation
Invoke-AtomicTest T1136.001 -Cleanup
```

**Splunk Query:**
```spl
index=endpoint EventCode=4720 host="target-PC"
```

**Detection Doc:** [detections/T1136.001_local-account-creation.md](../detections/T1136.001_local-account-creation.md)

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **What It Does** | Executes PowerShell commands simulating adversary behavior |
| **Detection** | Sysmon EID 1 (Process Create), Sysmon EID 7 (Image Load) |

```powershell
Invoke-AtomicTest T1059.001
```

**Splunk Query:**
```spl
index=endpoint host="target-PC" "T1059.001"
```

---

### T1053.005 — Scheduled Task/Job: Scheduled Task

| Field | Value |
|-------|-------|
| **Tactic** | Execution, Persistence, Privilege Escalation |
| **What It Does** | Creates scheduled tasks via `schtasks.exe` for persistence |
| **Detection** | Security EventCode=4698, Sysmon EID 1 (schtasks.exe) |

```powershell
Invoke-AtomicTest T1053.005

# Clean up
Invoke-AtomicTest T1053.005 -Cleanup
```

**Splunk Query:**
```spl
index=endpoint host="target-PC" "T1053" earliest=-15m
```

---

## Running Custom Tests

To discover available tests for any technique:

```powershell
# List all tests for a technique
Invoke-AtomicTest T1059.001 -ShowDetailsBrief

# Run a specific test number
Invoke-AtomicTest T1059.001-1

# Run with verbose output
Invoke-AtomicTest T1136.001 -Verbose
```

---

## Adding New Tests

To expand detection coverage, follow this workflow:

1. **Choose a MITRE technique** from the [ATT&CK Matrix](https://attack.mitre.org/)
2. **Run the Atomic test:** `Invoke-AtomicTest T<ID>`
3. **Wait 2 minutes** for logs to reach Splunk
4. **Search Splunk** for the technique ID or related Event Codes
5. **Write a detection query** that identifies the malicious activity
6. **Document the detection** using the template in [detections/](../detections/)
7. **Clean up:** `Invoke-AtomicTest T<ID> -Cleanup`

---

## Future Tests to Add

| Technique | Name | Tactic | Priority |
|-----------|------|--------|----------|
| T1003.001 | LSASS Memory Dump | Credential Access | High |
| T1547.001 | Registry Run Keys | Persistence | High |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Medium |
| T1218.011 | Rundll32 Execution | Defense Evasion | Medium |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | Medium |
