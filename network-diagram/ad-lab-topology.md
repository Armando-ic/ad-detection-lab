# AD Detection Lab — Network Topology

```mermaid
graph TB
    subgraph NAT_Network["NAT Network: AD Project (192.168.10.0/24)"]
        direction TB

        subgraph DC["Domain Controller"]
            ADDC01["ADDC01<br/>Windows Server 2022<br/>192.168.10.7<br/>Active Directory / DNS"]
        end

        subgraph SIEM["SIEM Server"]
            SPLUNK["Splunk<br/>Ubuntu Server 24.04<br/>192.168.10.10<br/>Splunk Enterprise"]
        end

        subgraph TARGET["Target Workstation"]
            DEMO["Target-PC (demo)<br/>Windows 11<br/>192.168.10.100<br/>Sysmon + Splunk Forwarder"]
        end

        subgraph ATTACKER["Attacker Machine"]
            KALI["Kali Linux<br/>192.168.10.250<br/>Crowbar / Atomic Red Team"]
        end
    end

    DEMO -- "Sysmon & WinEvent Logs<br/>(port 9997)" --> SPLUNK
    ADDC01 -- "Sysmon & WinEvent Logs<br/>(port 9997)" --> SPLUNK
    DEMO -- "Domain Auth / DNS<br/>(LDAP, Kerberos)" --> ADDC01
    KALI -- "RDP Brute Force<br/>(port 3389)" --> DEMO
    KALI -- "Attack Simulations" --> DEMO

    style ADDC01 fill:#4a90d9,stroke:#2c5aa0,color:#fff
    style SPLUNK fill:#4db848,stroke:#2d8028,color:#fff
    style DEMO fill:#f5a623,stroke:#c47d0e,color:#fff
    style KALI fill:#d0021b,stroke:#a00218,color:#fff
```

## Data Flow Summary

| Source | Destination | Protocol/Port | Purpose |
|--------|------------|---------------|---------|
| Target-PC | Splunk | TCP 9997 | Splunk Universal Forwarder (Sysmon, Security, System, Application logs) |
| ADDC01 | Splunk | TCP 9997 | Splunk Universal Forwarder (Sysmon, Security, System, Application logs) |
| Target-PC | ADDC01 | TCP 389/636, 88 | LDAP, Kerberos (Domain authentication, DNS) |
| Kali | Target-PC | TCP 3389 | RDP brute force attacks |
| Kali | Target-PC | Various | Attack simulations (Atomic Red Team) |
