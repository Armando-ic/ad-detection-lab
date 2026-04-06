# SOC Analyst Reference Guide

Two essential resources every SOC analyst should know how to use fluently. This guide explains what they are, when to use them, and includes practice exercises to build familiarity.

---

## 1. MITRE ATT&CK Framework

**URL:** https://attack.mitre.org/

### What It Is

MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations. It's the universal language SOC teams use to categorize and communicate about threats.

### Key Concepts

| Term | Definition | Example |
|------|-----------|---------|
| **Tactic** | The adversary's goal (the "why") | Persistence — maintaining access |
| **Technique** | How the adversary achieves the goal (the "how") | T1053 — Scheduled Task/Job |
| **Sub-technique** | A more specific variation | T1053.005 — Scheduled Task |
| **Procedure** | The exact implementation by a specific group | APT29 uses schtasks.exe to create persistence |

### How to Navigate

1. **The Matrix:** https://attack.mitre.org/matrices/enterprise/ — a grid view of all tactics (columns) and techniques (rows). This is the big picture.

2. **Technique Pages:** Click any technique (e.g., T1110.001) to see:
   - Description of how the attack works
   - Real-world procedure examples from threat groups
   - Which data sources can detect it
   - Mitigation recommendations

3. **Groups:** https://attack.mitre.org/groups/ — real-world threat actors and which techniques they use. Useful for understanding threat profiles.

4. **Software:** https://attack.mitre.org/software/ — tools and malware mapped to techniques. Shows what tools attackers use for each technique.

### When to Use It

| Scenario | How ATT&CK Helps |
|----------|-------------------|
| Writing a detection rule | Look up the technique to understand all variations of the attack |
| Triaging an alert | Map the alert to a technique to understand the adversary's likely next steps |
| Writing an incident report | Use technique IDs for precise, standardized communication |
| Gap analysis | Compare your detection coverage against the matrix to find blind spots |
| Threat intelligence | Map threat group TTPs to understand what you should be detecting |

---

## 2. Ultimate Windows Security — Event Log Encyclopedia

**URL:** https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx?i=j

### What It Is

A comprehensive encyclopedia of every Windows Security Event ID. For each event, it shows:
- What triggered the event
- Every field in the event and what it means
- Examples of what the event looks like
- Security relevance and what to watch for

### How to Use It

1. **Search by Event ID:** When you see an EventCode in Splunk (e.g., 4625), look it up to understand every field.

2. **Field Decoder:** Each event page breaks down every field. For example, Event 4625 has:
   - `Status` and `Sub Status` — specific failure reason codes
   - `Logon Type` — how the logon was attempted (2=interactive, 3=network, 10=RDP)
   - `Failure Reason` — human-readable explanation

3. **Cross-reference with Splunk:** When a Splunk event has a field you don't understand, look up the Event ID on this site to decode it.

### When to Use It

| Scenario | How the Encyclopedia Helps |
|----------|---------------------------|
| You see an unfamiliar Event ID in Splunk | Look it up to understand what happened |
| A field value doesn't make sense | The encyclopedia explains every field and its possible values |
| Writing a detection query | Understand which fields to filter on and what values indicate malicious activity |
| Explaining an event to someone | Get the plain-English description of what the event means |
| Studying for certifications | Build deep knowledge of Windows event logging |

---

## Practice Exercises: Using These References

### Exercise 1: Decode a Failed Logon

1. Run a failed RDP attempt from Kali
2. Find the 4625 event in Splunk
3. Open https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4625
4. Match every field in your Splunk event to the encyclopedia entry
5. Answer:
   - What does `Logon Type 3` mean vs `Logon Type 10`?
   - What does `Status 0xC000006D` mean?
   - What does `Sub Status 0xC000006A` mean?

### Exercise 2: Map an Attack to ATT&CK

1. Run `Invoke-AtomicTest T1053.005` on Target-PC
2. Open https://attack.mitre.org/techniques/T1053/005/
3. Read the full technique page and answer:
   - What tactic(s) does this technique fall under?
   - What data sources can detect it?
   - What real-world threat groups use this technique?
   - What mitigations does MITRE recommend?

### Exercise 3: Build a Detection from ATT&CK

1. Pick a technique you haven't tested yet from the ATT&CK matrix
2. Read the technique page — note the recommended data sources
3. Check if your lab collects those data sources (Sysmon, Security log, etc.)
4. Run the Atomic Red Team test for that technique
5. Write a Splunk query to detect it
6. Document it using the detection template in [detections/](../detections/)

### Exercise 4: Event ID Deep Dive

Look up each of these Event IDs on the Ultimate Windows Security encyclopedia and fill in the table:

| EventCode | Name | What Triggers It | Key Fields to Monitor |
|-----------|------|-------------------|----------------------|
| 4624 | | | |
| 4625 | | | |
| 4648 | | | |
| 4672 | | | |
| 4720 | | | |
| 4732 | | | |
| 4740 | | | |
| 4698 | | | |
| 7045 | | | |

Complete this table by researching each event. This builds the foundational knowledge that separates a strong SOC analyst from someone who just runs queries.

### Exercise 5: Threat Group Research

1. Go to https://attack.mitre.org/groups/
2. Pick a threat group relevant to your industry interest (e.g., APT29 for government, FIN7 for finance)
3. List the top 10 techniques they use
4. For each technique, check: does your lab detect it?
5. If not, what would you need to add?

This is a real-world exercise that SOC teams perform to prioritize detection development against likely threats.

---

## Bookmark These

| Resource | URL | When to Use |
|----------|-----|-------------|
| ATT&CK Matrix | https://attack.mitre.org/matrices/enterprise/ | Mapping attacks to framework |
| ATT&CK Techniques | https://attack.mitre.org/techniques/ | Understanding specific attack methods |
| ATT&CK Groups | https://attack.mitre.org/groups/ | Threat intelligence research |
| Windows Event Encyclopedia | https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ | Decoding Windows Event IDs |
| Atomic Red Team Tests | https://github.com/redcanaryco/atomic-red-team | Finding test commands for techniques |
| Splunk Security Research | https://research.splunk.com/ | Production-grade detection rules |
