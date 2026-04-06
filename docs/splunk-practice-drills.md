# Splunk Practice Drills

Hands-on exercises to build muscle memory with Splunk searches. Each drill has three parts:
1. **DO** — Perform an action on a VM
2. **FIND** — Write the Splunk query to find evidence of what you did
3. **UNDERSTAND** — Answer questions about what you found

Work through these in order. Difficulty increases as you go.

> **Important:** All searches use `index=endpoint` since that's where your forwarder sends data.
> Set your time range to **Last 15 minutes** unless stated otherwise.

---

## Level 1: Basic Searches (Getting Comfortable)

### Drill 1.1 — Find Your Own Login

**DO:** Log in to the Target-PC as Jenny Smith (jsmith).

**FIND:** Search Splunk for your login event.
```
Hint: Successful logons are EventCode=4624
```

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4624 host="target-PC"
```

**Bonus — filter to just Jenny:**
```spl
index=endpoint EventCode=4624 host="target-PC" jsmith
```
</details>

**UNDERSTAND:**
- What is the `Logon Type` field value? (Hint: Type 2 = interactive, Type 10 = RDP)
- What time did the login occur?
- What account domain is shown?

---

### Drill 1.2 — Find a Failed Login

**DO:** On the Target-PC login screen, try to log in as `jsmith` with the wrong password `wrongpassword123`.

**FIND:** Search Splunk for the failed login.

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4625 host="target-PC"
```
</details>

**UNDERSTAND:**
- What does the `Failure Reason` field say?
- What is the `Status` code? (Google "Windows logon status codes" to decode it)
- Can you see what IP address the attempt came from?

---

### Drill 1.3 — Count Events by Type

**DO:** Nothing — just query existing data.

**FIND:** How many events of each EventCode exist on target-PC in the last 24 hours?

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" earliest=-24h | stats count by EventCode | sort -count
```
</details>

**UNDERSTAND:**
- What are the top 5 most common Event Codes?
- Google the top 3 — what do they mean?
- Which source (Security, Sysmon, System) generates the most events?

---

### Drill 1.4 — Explore Your Data Sources

**DO:** Nothing — just explore.

**FIND:** What hosts, sources, and sourcetypes are in your endpoint index?

<details>
<summary>Answer</summary>

```spl
index=endpoint | stats count by host, source, sourcetype | sort -count
```
</details>

**UNDERSTAND:**
- How many different data sources are feeding into Splunk?
- Which host generates more events — ADDC01 or target-PC?
- What's the difference between `source` and `sourcetype`?

---

## Level 2: Attack Detection (Finding Bad Stuff)

### Drill 2.1 — RDP Brute Force Detection

**DO:** From Kali, run the brute force attack:
```bash
while IFS= read -r pass; do
  echo "Trying: $pass"
  timeout 10 xfreerdp /v:192.168.10.100 /u:tsmith /p:"$pass" /cert:ignore +auth-only 2>&1 | tail -1
done < ~/Desktop/ad-project/passwords.txt
```

**FIND (Step 1):** Find all the failed login attempts.

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4625 host="target-PC" earliest=-15m
```
</details>

**FIND (Step 2):** Count failed logins by user — who was targeted?

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4625 host="target-PC" earliest=-15m
| stats count by Account_Name
| sort -count
```
</details>

**FIND (Step 3):** Create a timeline — when did the burst happen?

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4625 host="target-PC" earliest=-15m
| timechart span=1m count
```
Click the **Visualization** tab to see a chart of the brute force spike.
</details>

**UNDERSTAND:**
- How many failed attempts occurred?
- Over what time window did they happen?
- Was there a successful login (4624) right after the failures? Check:
  ```spl
  index=endpoint EventCode=4624 host="target-PC" tsmith earliest=-15m
  ```

---

### Drill 2.2 — Atomic Red Team: Local Account Creation (T1136.001)

**DO:** On Target-PC (Admin PowerShell):
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
Invoke-AtomicTest T1136.001
```

**FIND (Step 1):** Find the account creation event.

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4720 host="target-PC" earliest=-5m
```
EventCode 4720 = "A user account was created"
</details>

**FIND (Step 2):** What account was created, and who created it?

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4720 host="target-PC" earliest=-5m
| table _time, Account_Name, SAM_Account_Name, user
```
</details>

**FIND (Step 3):** Find the Sysmon process that ran the command.

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "net user" earliest=-5m
```
</details>

**CLEANUP:** After you're done investigating:
```powershell
Invoke-AtomicTest T1136.001 -Cleanup
```

**UNDERSTAND:**
- What username was created?
- What process (Image) created the account?
- Why is this dangerous in a real environment?

---

### Drill 2.3 — Atomic Red Team: Scheduled Task (T1053.005)

**DO:** On Target-PC (Admin PowerShell):
```powershell
Invoke-AtomicTest T1053.005
```

**FIND (Step 1):** Find scheduled task creation in Sysmon.

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" "T1053" earliest=-5m
```
</details>

**FIND (Step 2):** Find the specific scheduled task event in Security logs.

<details>
<summary>Answer</summary>

```spl
index=endpoint EventCode=4698 host="target-PC" earliest=-5m
```
EventCode 4698 = "A scheduled task was created"
</details>

**FIND (Step 3):** How many total events did this single attack generate?

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" "T1053" earliest=-5m | stats count
```
</details>

**CLEANUP:**
```powershell
Invoke-AtomicTest T1053.005 -Cleanup
```

**UNDERSTAND:**
- What scheduled task names were created?
- What programs did the scheduled tasks run?
- Why do attackers use scheduled tasks? (Hint: persistence)

---

### Drill 2.4 — Atomic Red Team: PowerShell Download Cradle (T1059.001)

**DO:** On Target-PC (Admin PowerShell):
```powershell
Invoke-AtomicTest T1059.001
```

**FIND (Step 1):** Find PowerShell execution in Sysmon.

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" powershell earliest=-5m
```
</details>

**FIND (Step 2):** Look for the MITRE tag in the events.

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" "T1059.001" earliest=-5m
```
</details>

**UNDERSTAND:**
- What PowerShell command was executed?
- Was anything downloaded?
- What parent process launched PowerShell?

---

## Level 3: Analyst Thinking (Connecting the Dots)

### Drill 3.1 — Full Attack Timeline

**DO:** Run ALL of these in sequence from Kali and Target-PC:
1. Brute force tsmith from Kali
2. Run `Invoke-AtomicTest T1136.001` on Target-PC
3. Run `Invoke-AtomicTest T1053.005` on Target-PC

**FIND:** Build a complete timeline of the attack:

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" earliest=-15m
  (EventCode=4625 OR EventCode=4624 OR EventCode=4720 OR EventCode=4698)
| table _time, EventCode, Account_Name, user, ComputerName
| sort _time
```
</details>

**UNDERSTAND:**
- Can you tell the story of the attack from just the Splunk data?
- What was the first indicator of compromise?
- What would you escalate to a senior analyst?

---

### Drill 3.2 — Hunt for Anomalies

**DO:** Nothing — hunt through existing data.

**FIND:** What are the rarest events on target-PC? (Rare events often indicate attacks.)

<details>
<summary>Answer</summary>

```spl
index=endpoint host="target-PC" earliest=-24h
| stats count by EventCode
| sort count
| head 10
```
</details>

**UNDERSTAND:**
- What are those rare Event Codes?
- Are any of them suspicious?
- Google each one — could any be malicious?

---

### Drill 3.3 — Splunk Dashboard (Visual)

**DO:** Build a simple dashboard in Splunk.

1. Run this search:
   ```spl
   index=endpoint EventCode=4625 host="target-PC" earliest=-24h
   | timechart span=1h count
   ```
2. Click **Visualization** → choose **Column Chart**
3. Click **Save As → Dashboard Panel**
4. Name your dashboard: **SOC Overview**
5. Add a second panel with:
   ```spl
   index=endpoint host="target-PC" earliest=-24h
   | stats count by EventCode
   | sort -count
   | head 10
   ```

**UNDERSTAND:**
- What does the failed logon chart look like during a brute force vs normal activity?
- What are the dominant event types?

---

## Level 4: Advanced Queries (SPL Skills)

### Drill 4.1 — Stats and Timechart

Practice these SPL commands:

**Count by field:**
```spl
index=endpoint earliest=-24h | stats count by host
```

**Top values:**
```spl
index=endpoint earliest=-24h | top EventCode
```

**Rare values:**
```spl
index=endpoint earliest=-24h | rare EventCode
```

**Time series:**
```spl
index=endpoint earliest=-24h | timechart span=1h count by host
```

**Unique values:**
```spl
index=endpoint earliest=-24h | stats dc(EventCode) as unique_events by host
```

Run each one and switch to the **Visualization** tab to see charts.

---

### Drill 4.2 — Where and Eval

**Filter results:**
```spl
index=endpoint EventCode=4625 earliest=-24h
| stats count by Account_Name
| where count > 5
```

**Create calculated fields:**
```spl
index=endpoint earliest=-24h
| stats count by host
| eval status=if(count>1000, "High Volume", "Normal")
| table host, count, status
```

---

### Drill 4.3 — Transaction (Correlating Events)

Find brute force patterns — multiple failed logins followed by a success:

```spl
index=endpoint (EventCode=4625 OR EventCode=4624) host="target-PC" earliest=-24h
| transaction Account_Name maxspan=10m
| where eventcount > 5
| table _time, Account_Name, eventcount, duration
```

This groups events by user within a 10-minute window. If someone has 5+ events (mix of failures and success), that's a brute force pattern.

---

## SPL Quick Reference

| What You Want | SPL Command |
|---------------|-------------|
| Search for text | `index=endpoint "search term"` |
| Filter by field | `index=endpoint EventCode=4625` |
| Count by field | `\| stats count by fieldname` |
| Sort results | `\| sort -count` (descending) or `\| sort count` (ascending) |
| Show specific fields | `\| table _time, host, EventCode, user` |
| Time chart | `\| timechart span=1h count` |
| Top values | `\| top fieldname` |
| Rare values | `\| rare fieldname` |
| Filter after stats | `\| where count > 10` |
| Unique count | `\| stats dc(fieldname)` |
| First/last value | `\| stats first(_time) last(_time) by user` |
| Rename a field | `\| rename fieldname as "Display Name"` |
| Remove duplicates | `\| dedup fieldname` |

---

## Key Event Codes to Memorize

| EventCode | Meaning | Why It Matters |
|-----------|---------|----------------|
| 4624 | Successful logon | Who logged in? Was it expected? |
| 4625 | Failed logon | Brute force? Wrong password? |
| 4720 | User account created | Did an attacker create a backdoor account? |
| 4722 | User account enabled | Was a disabled account re-enabled? |
| 4732 | User added to security group | Privilege escalation? |
| 4740 | Account locked out | Brute force triggered lockout? |
| 4698 | Scheduled task created | Persistence mechanism? |
| 7045 | Service installed | Malware installed as a service? |
| 1 (Sysmon) | Process created | What ran on the system? |
| 3 (Sysmon) | Network connection | What connected to the internet? |
| 7 (Sysmon) | Image loaded (DLL) | DLL sideloading? |
| 11 (Sysmon) | File created | Malware dropped a file? |

---

## Recommended External Practice

After completing these drills, level up with:

1. **Boss of the SOC (BOTS)** — Splunk's official CTF with real attack data
   - Dataset: https://github.com/splunk/botsv3
   - Walkthrough: https://github.com/chan2git/splunk-bots
2. **CyberDefenders** — Blue team CTF challenges (many use Splunk)
   - https://cyberdefenders.org/
3. **Splunk Security Content** — Production detection rules to study
   - https://github.com/splunk/security_content
   - Browse at: https://research.splunk.com/
4. **TryHackMe** — Splunk rooms for guided practice
   - Search for "Splunk" on TryHackMe
