# Wireshark Practice Drills

Hands-on exercises to build packet analysis skills. Each drill follows:
1. **DO** — Capture traffic or open a sample pcap
2. **FIND** — Use display filters to isolate what matters
3. **UNDERSTAND** — Answer questions about what you found

---

## Setup

### Install Wireshark
- **Host PC:** Download from [wireshark.org](https://www.wireshark.org/download.html) — install with default options
- **Kali Linux:** Already installed (`sudo wireshark` or from the app menu)

### Install the SOC Security Profile
Import a pre-built profile that highlights security-relevant fields:
1. Download the Security profile from [amwalding/wireshark_profiles](https://github.com/amwalding/wireshark_profiles)
2. In Wireshark: right-click the profile bar (bottom right) → Import → select the zip
3. Switch to the "Security" profile when doing these drills

### Download Practice PCAPs
Create a folder for your practice files:
```
mkdir ~/Desktop/ad-project/pcaps
```

Download sample pcaps from:
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — clean protocol examples
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html) — real malware pcaps (password for zips: `infected`)
- [Unit 42 Wireshark Quizzes](https://unit42.paloaltonetworks.com/) — guided challenges with answers

---

## Level 1: Wireshark Basics (Host PC — No VMs Needed)

### Drill 1.1 — Capture Your Own Traffic

**DO:** Open Wireshark on your host PC. Select your active network adapter and start capturing. Then:
1. Open a web browser
2. Go to `http://example.com` (plain HTTP, not HTTPS)
3. Stop the capture after the page loads

**FIND:** Use this display filter to find the HTTP request:
```
http.request
```

**UNDERSTAND:**
- What is the destination IP of example.com?
- What HTTP method was used? (GET, POST, etc.)
- Can you see the full URL in the packet details?
- Expand the packet layers — what are the 4 layers? (Ethernet → IP → TCP → HTTP)

---

### Drill 1.2 — Learn the Display Filter Syntax

**DO:** Using the same capture from 1.1, practice these filters one at a time:

| Filter | What It Shows |
|--------|--------------|
| `ip.addr == 93.184.216.34` | All traffic to/from example.com |
| `tcp.port == 80` | All HTTP traffic |
| `tcp.port == 443` | All HTTPS traffic |
| `dns` | All DNS queries/responses |
| `dns.qry.name contains "example"` | DNS queries for example.com |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | TCP SYN packets (new connections) |
| `frame.len > 1000` | Large packets |
| `!(arp or dns or icmp)` | Filter out noise |

**UNDERSTAND:**
- What's the difference between `==` and `contains`?
- What does `&&` mean? What about `||`?
- What does `!` (exclamation mark) do?
- Why would you filter out ARP, DNS, and ICMP?

---

### Drill 1.3 — Follow a TCP Stream

**DO:** In your capture, find an HTTP request. Right-click the packet → **Follow → TCP Stream**.

**UNDERSTAND:**
- What do the red and blue colors mean? (Red = client, Blue = server)
- Can you read the HTTP headers?
- Can you see the HTML content of the page?
- Close the stream window. Notice the display filter changed — what did it add?

---

### Drill 1.4 — DNS Deep Dive

**DO:** Start a new capture. Then in your browser, visit 5 different websites. Stop the capture.

**FIND:**
```
dns
```

Then narrow it:
```
dns.qry.type == 1
```
(Type 1 = A record queries — hostname to IP)

**UNDERSTAND:**
- What DNS server is your PC using? (Check the destination IP of DNS queries)
- How many DNS queries were generated per website visit?
- Can you find the DNS response that contains the IP address? Look in the packet details under "Answers"
- What is a DNS query vs a DNS response? (Check `dns.flags.response`)

---

### Drill 1.5 — Analyze a Ping

**DO:** Open a terminal and ping a website:
```
ping -n 4 8.8.8.8
```
(Capture this in Wireshark)

**FIND:**
```
icmp
```

**UNDERSTAND:**
- What are the two ICMP message types you see? (Type 8 = Echo Request, Type 0 = Echo Reply)
- What is the time between request and reply? (This is the round-trip time)
- What data is inside the ICMP payload?
- How is this different from TCP traffic?

---

## Level 2: Security Analysis (Sample PCAPs)

### Drill 2.1 — Detect a Port Scan

**DO:** Download a pcap containing a port scan. From [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures), get any Nmap scan pcap. Or generate one yourself from Kali:
```bash
sudo nmap -sS 192.168.10.100 -oP /tmp/scan.pcap
```
(Capture on Kali with Wireshark while running the scan)

**FIND:** Look for SYN packets without a full handshake:
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Then check how many different ports were targeted:
Go to **Statistics → Endpoints → TCP tab**. Sort by port.

Or use **Statistics → Conversations → TCP tab** to see all connections.

**UNDERSTAND:**
- How many ports were scanned?
- How can you tell this is a scan vs normal traffic? (Hint: many different ports, many RST responses)
- What does a SYN scan look like vs a full connect scan?
- What filter would find RST (reset) packets? (`tcp.flags.reset == 1`)

---

### Drill 2.2 — Detect a Brute Force Attack

**DO:** On Kali, start Wireshark capturing on eth0. Then run your RDP brute force:
```bash
while IFS= read -r pass; do
  timeout 10 xfreerdp /v:192.168.10.100 /u:tsmith /p:"$pass" /cert:ignore +auth-only 2>&1 | tail -1
done < ~/Desktop/ad-project/passwords.txt
```
Stop the capture after it finishes.

**FIND:** Filter for RDP traffic:
```
tcp.port == 3389
```

Then look at the connection pattern:
```
tcp.port == 3389 && tcp.flags.syn == 1
```

**UNDERSTAND:**
- How many connection attempts do you see?
- How quickly did they happen? (Check timestamps)
- Is there a pattern? (Same source, same destination, same port, rapid succession)
- How is this different from a normal user connecting via RDP?
- Can you see the TLS handshake? (RDP uses TLS encryption)

**BONUS:** Go to **Statistics → I/O Graphs**. Set the display filter to `tcp.port == 3389`. You should see a spike during the brute force.

---

### Drill 2.3 — Examine DNS Queries from Your Lab

**DO:** Capture traffic on Kali while running various commands:
```bash
nslookup mydfir.local 192.168.10.7
nslookup ADDC01.mydfir.local 192.168.10.7
ping 192.168.10.100
```

**FIND:**
```
dns
```

**UNDERSTAND:**
- What DNS server answered the queries? (Should be 192.168.10.7 — your DC)
- Can you see the A record response with the IP address?
- What is the difference between a forward lookup and a reverse lookup?

---

### Drill 2.4 — Analyze Kerberos Authentication

**DO:** Capture on Kali or Target-PC while logging into the domain. On Target-PC, log out and log back in as jsmith.

**FIND:** Filter for Kerberos traffic:
```
kerberos
```

Narrow to ticket requests:
```
kerberos.msg.type == 10 || kerberos.msg.type == 12
```
(Type 10 = AS-REQ, Type 12 = TGS-REQ)

**UNDERSTAND:**
- What is an AS-REQ? (Authentication Service Request — asking for a TGT)
- What is a TGS-REQ? (Ticket Granting Service Request — asking for a service ticket)
- What encryption type is being used? (`kerberos.etype`)
- Where are the tickets going? (Which server is the KDC?)
- Why is this important for detecting Kerberoasting? (Hint: excessive TGS-REQ with RC4 encryption)

---

### Drill 2.5 — Analyze Malware Traffic (Sample PCAP)

**DO:** Go to [malware-traffic-analysis.net/training-exercises.html](https://www.malware-traffic-analysis.net/training-exercises.html). Download the most recent exercise pcap (password: `infected`). Open it in Wireshark.

**FIND (Step 1):** Get an overview. Go to **Statistics → Protocol Hierarchy**. What protocols are present?

**FIND (Step 2):** Look at DNS queries:
```
dns.qry.name
```
Are any domain names suspicious? (Random-looking strings, recently registered domains)

**FIND (Step 3):** Look for HTTP POST requests (often used for data exfiltration):
```
http.request.method == "POST"
```

**FIND (Step 4):** Check for beaconing — regular intervals of communication:
Go to **Statistics → I/O Graphs**. Look for periodic spikes.

**UNDERSTAND:**
- What was the infected machine's IP?
- What external IPs did it communicate with?
- Can you identify the C2 (command and control) server?
- What data was being sent out?

---

## Level 3: SOC Analyst Investigations (Real Scenarios)

### Drill 3.1 — Full Attack Capture

**DO:** This is a combined exercise. Capture on Kali for the entire duration:

1. Start Wireshark on Kali (capture eth0)
2. Run an nmap scan: `nmap -sV 192.168.10.100`
3. Run the RDP brute force
4. Connect via RDP with the correct password: `xfreerdp /v:192.168.10.100 /u:tsmith /p:'GTh146pe!' /cert:ignore`
5. Disconnect after 30 seconds
6. Stop the capture. Save it as `full-attack.pcapng`

**FIND:** Now analyze it as if you're a SOC analyst who received this pcap:

**Phase 1 — Reconnaissance:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 192.168.10.100
```
How many ports were probed?

**Phase 2 — Brute Force:**
```
tcp.port == 3389 && tcp.flags.syn == 1
```
When did the RDP attempts start? How many?

**Phase 3 — Successful Access:**
```
tcp.port == 3389 && tcp.len > 0
```
Can you identify when the connection became a sustained session (longer data transfers)?

**UNDERSTAND:**
- Write a 3-sentence summary of what happened, as if briefing your SOC lead
- What MITRE ATT&CK techniques were used? (Reconnaissance, Brute Force, Remote Services)
- At what point should a SOC analyst have raised an alert?

---

### Drill 3.2 — CyberDefenders Challenge

**DO:** Go to [CyberDefenders PacketMaze](https://cyberdefenders.org/blueteam-ctf-challenges/packetmaze/). Create a free account and attempt the challenge.

This is a real blue team CTF — you'll be given a pcap and questions to answer using Wireshark. No hints here — this is your test.

**UNDERSTAND:**
- What techniques did you use to find the answers?
- What display filters were most helpful?
- What would you do differently next time?

---

### Drill 3.3 — Unit 42 Wireshark Quiz

**DO:** Go to [Unit 42 Wireshark Quizzes](https://unit42.paloaltonetworks.com/) and search for "Wireshark quiz". Download the pcap and work through the questions.

The February 2023 quiz features **Qakbot in an Active Directory environment** — directly relevant to your home lab.

**UNDERSTAND:**
- How does malware C2 traffic look different from normal browsing?
- What indicators of compromise (IOCs) can you extract from the pcap?
- How would you use these IOCs to write a Splunk detection rule?

---

## Display Filter Quick Reference

### By Protocol
| Filter | What It Shows |
|--------|---------------|
| `dns` | All DNS traffic |
| `http` | All HTTP traffic |
| `tls` | All TLS/SSL traffic |
| `kerberos` | Kerberos authentication |
| `smb2` | SMB file sharing |
| `ldap` | LDAP directory queries |
| `icmp` | Ping and ICMP messages |
| `arp` | ARP address resolution |
| `tcp` | All TCP traffic |
| `udp` | All UDP traffic |

### By Condition
| Filter | What It Shows |
|--------|---------------|
| `ip.addr == 192.168.10.100` | All traffic to/from an IP |
| `ip.src == 192.168.10.250` | Traffic FROM Kali |
| `ip.dst == 192.168.10.100` | Traffic TO Target-PC |
| `tcp.port == 3389` | RDP traffic |
| `tcp.port == 445` | SMB traffic |
| `tcp.port == 88` | Kerberos traffic |
| `tcp.port == 389` | LDAP traffic |
| `tcp.port == 9997` | Splunk forwarder traffic |
| `udp.port == 53` | DNS traffic |
| `frame.len > 1000` | Large packets |
| `tcp.analysis.retransmission` | Retransmitted packets (network issues) |

### SOC Hunting Filters
| Filter | What It Finds |
|--------|--------------|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | New connection attempts (port scan indicator) |
| `tcp.flags.reset == 1` | Rejected connections |
| `dns.qry.type == 1` | DNS A record lookups |
| `dns.resp.len > 200` | Large DNS responses (tunneling indicator) |
| `http.request.method == "POST"` | HTTP POST requests (data exfiltration) |
| `http.request.uri contains "exe"` | Executable downloads |
| `tls.handshake.type == 1` | TLS Client Hello (new encrypted connections) |
| `kerberos.msg.type == 12` | Kerberos TGS requests (Kerberoasting indicator) |
| `smb2.cmd == 5` | SMB2 Create requests (file access) |
| `http.user_agent` | HTTP User-Agent strings (malware often has unique UAs) |
| `!(arp or dns or stp or cdp or lldp)` | Filter out common noise |

### Operators
| Operator | Meaning | Example |
|----------|---------|---------|
| `==` | Equals | `ip.addr == 10.0.0.1` |
| `!=` | Not equals | `ip.addr != 10.0.0.1` |
| `>` `<` `>=` `<=` | Comparison | `frame.len > 500` |
| `contains` | String contains | `http.host contains "evil"` |
| `matches` | Regex match | `dns.qry.name matches "^[a-z]{20,}"` |
| `&&` or `and` | AND | `ip.src == 10.0.0.1 && tcp.port == 80` |
| `\|\|` or `or` | OR | `tcp.port == 80 \|\| tcp.port == 443` |
| `!` or `not` | NOT | `!arp` |
| `in` | Value in set | `tcp.port in {80, 443, 8080}` |

---

## Key Protocols for SOC Analysts

| Protocol | Port | Why SOC Cares |
|----------|------|---------------|
| **DNS** | 53 | Domain lookups reveal C2 servers, tunneling, DGA domains |
| **HTTP** | 80 | Unencrypted web — see full request/response, malware downloads |
| **HTTPS/TLS** | 443 | Encrypted — can still analyze TLS handshakes, certificate info, SNI |
| **RDP** | 3389 | Remote access — brute force, lateral movement |
| **SMB** | 445 | File sharing — lateral movement, ransomware propagation |
| **Kerberos** | 88 | AD auth — Kerberoasting, Golden Ticket, overpass-the-hash |
| **LDAP** | 389/636 | AD queries — enumeration, credential harvesting |
| **NTLM** | Various | Legacy auth — Pass-the-Hash attacks |

---

## Recommended External Practice

After completing these drills, level up with:

1. **Malware Traffic Analysis Exercises** — Work through 1 exercise per week from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)
2. **CyberDefenders** — PacketMaze, WebStrike, Malware Traffic Analysis 3
3. **Unit 42 Quizzes** — Real malware families in real pcaps
4. **Chris Brenton's Antisyphon Training** — "Getting Started in Packet Decoding" (pay-what-you-can, next session April 23-26, 2026)
5. **TryHackMe** — Wireshark: The Basics → Packet Operations → Traffic Analysis
6. **Generate your own pcaps** — Capture every attack you run in your AD lab
