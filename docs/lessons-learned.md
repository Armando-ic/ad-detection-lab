# Lessons Learned & Troubleshooting

Honest documentation of issues encountered while building this lab and how they were resolved. These are common pitfalls that anyone following the MyDFIR series (or building a similar AD lab) may encounter in 2026.

---

## 1. Crowbar Fails Silently with FreeRDP 3

**Symptom:** Crowbar runs through all passwords and reports "No results found" — even though the correct password is in the wordlist.

**Root Cause:** Kali Linux 2025+ ships with FreeRDP 3.x. Crowbar 0.4.2 was built for FreeRDP 2.x. The exit codes are reversed:
- FreeRDP 2: `exit 0` = success, `exit 1` = failure
- FreeRDP 3: `exit 0` = failure, `exit 1` = success

Crowbar checks for exit code 0 as a successful login, so it never finds a match.

**Fix:** Use an xfreerdp loop that accounts for the FreeRDP 3 exit codes:

```bash
while IFS= read -r pass; do
  echo "Trying: $pass"
  timeout 10 xfreerdp /v:192.168.10.100 /u:tsmith /p:"$pass" /cert:ignore +auth-only 2>&1 |
  grep -q "exit status 1" && echo ">>> SUCCESS: $pass <<<" && break
done < passwords.txt
```

**Lesson:** Always verify tool compatibility when using a different OS version than a tutorial. Check exit codes and output formats — they change between major versions.

---

## 2. RDP Connection Refused Despite Being Enabled

**Symptom:** `xfreerdp` returns `ERRCONNECT_CONNECT_FAILED`. Port 3389 is not listening on the Target PC.

**Root Cause:** Enabling Remote Desktop in Windows Settings does not automatically create Windows Firewall rules to allow inbound RDP connections.

**Fix:**
```cmd
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
```

If TermService still isn't listening after enabling, reboot the Target PC and verify:
```cmd
netstat -an | findstr 3389
```

**Lesson:** "Enabled" in the UI doesn't always mean "accessible from the network." Always verify with `netstat` that the port is actually listening, and check firewall rules separately.

---

## 3. Kali Linux Loses Network Connectivity

**Symptom:** Kali's `eth0` interface has no IPv4 address. `ip addr show eth0` shows only an IPv6 link-local address. All pings fail.

**Root Cause:** NetworkManager on Kali intermittently drops the static IP configuration on the VirtualBox NAT Network adapter.

**Quick Fix:**
```bash
sudo ip addr add 192.168.10.250/24 dev eth0
sudo ip route add default via 192.168.10.1 dev eth0
```

**Permanent Fix:** Bypass NetworkManager entirely:
```bash
sudo nmcli device set eth0 managed no
sudo tee /etc/network/interfaces.d/eth0 << 'EOF'
auto eth0
iface eth0 inet static
    address 192.168.10.250
    netmask 255.255.255.0
    gateway 192.168.10.1
    dns-nameservers 8.8.8.8
EOF
```

**Lesson:** NetworkManager is designed for dynamic environments (laptops switching between WiFi and Ethernet). For a lab with static IPs, configuring the interface directly in `/etc/network/interfaces` is more reliable.

---

## 4. Splunk Searches Return Zero Results

**Symptom:** `index=* EventCode=4625` returns nothing, but events exist locally on the Target PC (verified with `Get-WinEvent`).

**Root Cause (1 — Wrong Index):** The `inputs.conf` on the Target PC sends all data to `index=endpoint`, not the default index. Searching `index=*` may not include custom indexes depending on Splunk's role-based access.

**Fix:** Always use the specific index:
```spl
index=endpoint EventCode=4625 host="target-PC"
```

**Root Cause (2 — Time Sync):** VM clocks drifted significantly from real time. Events were indexed under incorrect timestamps, so time-bounded searches missed them.

**Fix:** Sync all VM clocks:
- **ADDC01:** `tzutil /s "Eastern Standard Time"`
- **Target-PC:** `w32tm /config /manualpeerlist:"192.168.10.7" /syncfromflags:manual /update` then `w32tm /resync /force`
- **Splunk:** `sudo timedatectl set-timezone America/New_York`
- **Splunk Web:** User Preferences → Timezone → GMT-04:00 Eastern Time

**Lesson:** Time sync is foundational for any SIEM deployment. If your clocks are wrong, your searches will miss events. In production, NTP is one of the first things configured and monitored. Always verify with `earliest=-24h` or "All time" if you suspect time issues.

---

## 5. VirtualBox Configuration Corruption (VERR_DISK_FULL)

**Symptom:** VirtualBox fails to launch with `E_FAIL (0x80004005)`. Individual VMs show as "Inaccessible" with "Document is empty."

**Root Cause:** The host C: drive ran completely out of disk space while VirtualBox was writing configuration files, truncating them to 0 bytes.

**Fix:** VirtualBox maintains a `-prev` backup of every configuration file:
1. Restore `VirtualBox.xml` from `VirtualBox.xml-prev`
2. Restore individual `<VM>.vbox` files from `<VM>.vbox-prev`
3. Update file paths if VMs were moved to a different drive

**Lesson:** Monitor host disk space. VMs with dynamically allocated disks can consume space gradually until the host drive fills up. Consider placing VMs on a dedicated drive with ample space. If corruption occurs, always check for `-prev` backup files before recreating anything.

---

## 6. Atomic Red Team — Module Not Recognized

**Symptom:** `Invoke-AtomicTest` is not recognized as a command in PowerShell.

**Root Cause:** The Atomic Red Team PowerShell module must be imported in each new PowerShell session. It does not auto-load.

**Fix:**
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
```

**Lesson:** PowerShell modules from third-party tools typically need explicit importing unless added to your PowerShell profile. For lab use, importing manually each session is fine.

---

## 7. VM Performance — USB Drive Bottleneck

**Symptom:** All VMs run extremely slowly. Task Manager shows the USB drive (F:) at 100% active time constantly.

**Root Cause:** VMs were stored on a USB-attached external drive. VM disk I/O requires fast random read/write performance that USB cannot provide.

**Fix:** Moved all VMs to the host's internal NVMe SSD (WD Black SN770). Performance improved dramatically.

**Lesson:** Always store VMs on the fastest available storage. NVMe SSD is ideal, SATA SSD is acceptable, USB/HDD will cause significant performance issues. Monitor with Task Manager → Performance → Disk to identify I/O bottlenecks.

---

## General Takeaways

1. **Verify, don't assume.** When a tool says "enabled" or "configured," check with `netstat`, `sc query`, `Get-WinEvent`, or equivalent commands to confirm it's actually working.

2. **Check tool versions.** Tutorials age quickly. A command that works in a 2024 video may fail silently in 2026 due to dependency updates. Always check `--version` and read changelogs.

3. **Time sync is non-negotiable for SIEM.** If events aren't appearing in your searches, check the clocks first. This applies to production environments just as much as home labs.

4. **Read the error messages.** `exit status 1`, `ERRCONNECT_CONNECT_FAILED`, and `No such device` all point to specific, diagnosable problems. The error message is your first clue.

5. **Use AI tools for troubleshooting.** Claude Code was used extensively to diagnose these issues in real time — reading error output, suggesting diagnostic commands, and identifying root causes. This is a legitimate and efficient approach to technical problem-solving.
