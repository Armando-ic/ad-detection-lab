# Lab Setup Guide

Step-by-step guide to building the Active Directory Detection Lab from scratch.

---

## Prerequisites

- **Host machine:** Windows 10/11 with at least 16 GB RAM (32 GB recommended for running all 4 VMs simultaneously)
- **Disk space:** ~120 GB free (NVMe SSD strongly recommended for VM performance)
- **Software:** Oracle VirtualBox 7.x
- **Accounts:** Splunk account (free license), Microsoft Evaluation ISOs

---

## Step 1: VirtualBox Network Configuration

Create a NAT Network so all VMs can communicate with each other and share internet access.

1. Open VirtualBox → **File → Preferences → Network**
2. Click **Add** to create a new NAT Network
3. Configure:
   - **Name:** AD Project
   - **Network CIDR:** 192.168.10.0/24
   - **Enable DHCP:** Yes

All VMs will be attached to this "AD Project" NAT Network.

---

## Step 2: Domain Controller (ADDC01)

### VM Settings
| Setting | Value |
|---------|-------|
| OS | Windows Server 2022 (Evaluation) |
| RAM | 2048 MB (2 GB) |
| CPUs | 2 |
| Disk | 50 GB (dynamically allocated) |
| Network | NAT Network: AD Project |

### Installation
1. Download Windows Server 2022 Evaluation ISO from Microsoft
2. Create the VM with settings above
3. Install Windows Server 2022 (Desktop Experience)
4. Set a strong Administrator password

### Active Directory Configuration
1. Open **Server Manager → Add Roles and Features**
2. Select **Active Directory Domain Services**
3. After installation, click **Promote this server to a domain controller**
4. Select **Add a new forest**
5. Root domain name: `mydfir.local`
6. Set DSRM password
7. Complete the wizard and restart

### Static IP Configuration
1. Open **Network and Sharing Center → Change adapter settings**
2. Right-click the adapter → **Properties → IPv4**
3. Configure:
   - IP: `192.168.10.7`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.10.1`
   - DNS: `127.0.0.1` (itself — it's the DNS server)

### Create Organizational Units and Users
1. Open **Active Directory Users and Computers**
2. Create OUs: `IT`, `HR`
3. Create users:
   - `jsmith` (Jenny Smith) → IT OU
   - `tsmith` (Terry Smith) → HR OU
4. Set passwords and add users to **Remote Desktop Users** group

---

## Step 3: Splunk Server

### VM Settings
| Setting | Value |
|---------|-------|
| OS | Ubuntu Server 24.04 LTS |
| RAM | 4096 MB (4 GB) |
| CPUs | 2 |
| Disk | 100 GB (dynamically allocated) |
| Network | NAT Network: AD Project |

### Installation
1. Install Ubuntu Server 24.04 from ISO
2. Set static IP during installation or after:
   - IP: `192.168.10.10`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.10.1`
   - DNS: `8.8.8.8`

### Splunk Enterprise Setup
1. Download Splunk Enterprise `.deb` from splunk.com
2. Install: `sudo dpkg -i splunk-*.deb`
3. Start Splunk: `sudo /opt/splunk/bin/splunk start --accept-license`
4. Set admin credentials
5. Enable receiving on port 9997:
   - Splunk Web → **Settings → Forwarding and Receiving → Receive Data → New**
   - Listen on port: `9997`
6. Create the `endpoint` index:
   - **Settings → Indexes → New Index**
   - Index name: `endpoint`

### Set Timezone
```bash
sudo timedatectl set-timezone America/New_York
```

---

## Step 4: Target Workstation (demo / Target-PC)

### VM Settings
| Setting | Value |
|---------|-------|
| OS | Windows 11 |
| RAM | 6144 MB (6 GB) |
| CPUs | 4 |
| Disk | 80 GB (dynamically allocated) |
| Network | NAT Network: AD Project |

### Installation
1. Install Windows 11 from ISO
2. Set static IP:
   - IP: `192.168.10.100`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.10.1`
   - DNS: `192.168.10.7` (points to ADDC01)

### Join the Domain
1. **Settings → System → About → Rename this PC (advanced)**
2. Click **Change → Domain** → enter `mydfir.local`
3. Authenticate with domain admin credentials
4. Restart

### Enable Remote Desktop
1. **Settings → System → Remote Desktop → On**
2. Add domain users (jsmith, tsmith) to Remote Desktop Users
3. Enable firewall rule:
   ```
   netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
   ```

### Install Sysmon
1. Download Sysmon from Microsoft Sysinternals
2. Download a Sysmon configuration (e.g., Olaf Hartong's sysmon-modular)
3. Install: `sysmon64.exe -accepteula -i sysmonconfig.xml`
4. Verify: `sc query Sysmon64` — should show RUNNING

### Install Splunk Universal Forwarder
1. Download from splunk.com
2. Install with receiving indexer set to `192.168.10.10:9997`
3. Configure `inputs.conf` at `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:

```ini
[WinEventLog://Application]
index = endpoint
disabled = false

[WinEventLog://Security]
index = endpoint
disabled = false

[WinEventLog://System]
index = endpoint
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

4. Restart the forwarder: `splunk restart` (from the bin directory)

### Install Atomic Red Team
1. Open PowerShell as Administrator
2. Set execution policy:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
   ```
3. Install:
   ```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
   Install-AtomicRedTeam -getAtomics
   ```
4. Import before use (each session):
   ```powershell
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
   ```

---

## Step 5: Kali Linux (Attacker)

### VM Settings
| Setting | Value |
|---------|-------|
| OS | Kali Linux 2025.x |
| RAM | 4096 MB (4 GB) |
| CPUs | 2 |
| Disk | 20 GB (dynamically allocated) |
| Network | NAT Network: AD Project |

### Static IP Configuration
Configure via NetworkManager GUI or CLI:
- IP: `192.168.10.250`
- Subnet: `255.255.255.0`
- Gateway: `192.168.10.1`
- DNS: `8.8.8.8`

If NetworkManager drops the connection, assign manually:
```bash
sudo ip addr add 192.168.10.250/24 dev eth0
sudo ip route add default via 192.168.10.1 dev eth0
```

### Install Required Tools
```bash
sudo apt update
sudo apt install -y crowbar
```

> **Note:** Kali 2025+ ships with FreeRDP 3.x. Crowbar was built for FreeRDP 2.x and will silently fail. See [docs/lessons-learned.md](lessons-learned.md) for the workaround.

---

## Step 6: Verify the Lab

Run through the [Health Check](../AD_Lab_Health_Check.md) to confirm all VMs are connected, logging, and detecting attacks properly.

### Quick Verification
1. **Network:** Ping all VMs from Kali — 0% packet loss
2. **Domain:** On Target-PC, run `nltest /dsgetdc:mydfir.local` — returns ADDC01
3. **Splunk:** Search `index=endpoint | stats count by host` — both ADDC01 and target-PC appear
4. **Sysmon:** Open Notepad on Target-PC, search Splunk for `index=endpoint host="target-PC" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" notepad`
5. **Detection:** Run an Atomic Red Team test, verify it appears in Splunk within 2 minutes
