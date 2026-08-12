# wazuh-windows-beaconing-activity-investigation-dfir-lab
## Overview

In cybersecurity, beaconing is a repeated communication pattern where a compromised endpoint periodically contacts a remote system.

A simplified example:

10:00:00  Endpoint → Remote IP
10:01:00  Endpoint → Remote IP
10:02:00  Endpoint → Remote IP
10:03:00  Endpoint → Remote IP
10:04:00  Endpoint → Remote IP

The important characteristic is regularity.

The endpoint may be checking for:

Commands
Configuration
New instructions
Additional payloads
Status updates

This behavior is commonly associated with Command and Control (C2).

A single connection might look completely normal:

Windows → HTTPS → Internet

The same destination being contacted once is not necessarily suspicious.

But when you observe:

Same process
+
Same destination
+
Same port
+
Similar interval
+
Repeated connections

the pattern becomes much more interesting.

So the investigation is about behavior over time, not a single network event.

Periodic communication alone does not prove C2.

Many legitimate applications communicate regularly.

Examples:

Antivirus
Windows Update
Cloud synchronization
Email clients
Monitoring software
Collaboration applications

Therefore we need to determine:

Who?
 ↓
What process?
 ↓
Which destination?
 ↓
How often?
 ↓
Which protocol/port?
 ↓
Is the destination expected?


In this lab, a safe local periodic TCP connection pattern was generated and investigated using PowerShell, process identification, Windows network information, Sysmon Event ID 3, and Wazuh Discover. The investigation focused on correlating the communicating process, destination, port, timing, and user context.

---

# Lab Objectives

- Determine whether endpoint network traffic exhibits a periodic communication pattern.
- Identify the process responsible for the observed connections.
- Associate network activity with the correct Process ID and user context.
- Examine destination IP, destination port, protocol, and connection timing.
- Analyze Sysmon Event ID 3 for network connection evidence.
- Correlate process and network telemetry within Wazuh Discover.
- Distinguish legitimate periodic communication from potentially suspicious beaconing.
- Construct a time-based communication profile from observed events.
- Assess the evidence without treating periodic traffic alone as proof of C2.

---

# Lab Environment

| Component          | Value                                  |
| ------------------ | -------------------------------------- |
| Host OS            | Windows 11 Pro                         |
| SIEM               | Wazuh 4.12                             |
| Endpoint Agent     | Wazuh Agent                            |
| Endpoint Name      | DESKTOP-9MMM37V                        |
| Agent ID           | 001                                    |
| Investigation Type | Beaconing Activity Investigation       |
| Destination        | 127.0.0.1                              |
| Destination Port   | 8088                                   |
| Protocol            | TCP                                    |
| Tools Used         | PowerShell, Sysmon, Wazuh Discover    |

---

# Tools Used

- PowerShell
- Get-NetTCPConnection
- Get-Process
- Windows Event Viewer
- Sysmon Event ID 3
- Wazuh Discover
- Wazuh Agent

---

# Investigation Scenario

A Windows endpoint triggers a SOC investigation after showing repeated outbound-style connection events at regular intervals. The activity is unusual enough to raise concern about possible beaconing, but there is no immediate evidence of malware.

The analyst needs to determine:

Which process generated the connections?
Which user was associated with the activity?
What destination and port were contacted?
How regularly did the connections occur?
Was the activity visible in Sysmon and Wazuh?
Does the communication pattern represent legitimate periodic activity or potential C2 behavior?

The investigation focuses on correlating process identity, network activity, timing, and endpoint telemetry before reaching a conclusion.

---

# Investigation Workflow

```text
Periodic Network Connection
        ↓
Identify Destination
        ↓
Identify Port / Protocol
        ↓
Identify Process
        ↓
Identify Process ID
        ↓
Correlate Sysmon Event ID 3
        ↓
Measure Connection Intervals
        ↓
Correlate Wazuh Telemetry
        ↓
Review User / Process Context
        ↓
Determine Legitimate vs Suspicious
```

---

# Investigation Steps

### Step 1 – Verify Wazuh Agent

Verify that the Windows endpoint is communicating with Wazuh.

```bash
sudo /var/ossec/bin/agent_control -i 001
```

---

### Step 2 – Identify the Windows Endpoint

```powershell
hostname
```

Determine the Windows endpoint IP information:

```powershell
Get-NetIPAddress -AddressFamily IPv4 |
Where-Object {$_.IPAddress -notlike "127.*"} |
Select-Object IPAddress, InterfaceAlias
```

---

### Step 3 – Establish a Network Baseline

Review existing TCP connections:

```powershell
Get-NetTCPConnection -State Established |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

This provides an initial view of network activity before generating the controlled test traffic.

---

### Step 4 – Create a Safe Local Listener

A local TCP listener was created on port `8088`.

```powershell
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Any,
    8088
)

$listener.Start()
```

The listener remained on the local Windows system and did not communicate with an external server.

---

### Step 5 – Generate Periodic Connections

A PowerShell loop was used to create repeated connections every 30 seconds.

```powershell
for ($i = 1; $i -le 10; $i++) {

    $client = [System.Net.Sockets.TcpClient]::new()

    try {
        $client.Connect("127.0.0.1", 8088)
    }
    finally {
        $client.Close()
    }

    Start-Sleep -Seconds 30
}
```

This generated a controlled beacon-like pattern:

```text
Connection
    ↓
30 seconds
    ↓
Connection
    ↓
30 seconds
    ↓
Connection
```

---

### Step 6 – Identify the Process ID

The PID of the PowerShell process running the loop was obtained using:

```powershell
$PID
```

The process can also be identified using:

```powershell
Get-Process powershell | Format-Table Id, ProcessName, StartTime
```

---

### Step 7 – Correlate the PID With the Network Connection

```powershell
Get-NetTCPConnection |
Where-Object {$_.RemotePort -eq 8088} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

The `OwningProcess` field was correlated with:

```powershell
Get-Process -Id <PID>
```

This established the relationship:

```text
powershell.exe
      ↓
127.0.0.1:8088
```

---

### Step 8 – Investigate Sysmon Event ID 3

Open:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

Review:

```text
Event ID 3 – Network Connection Detected
```

Important fields include:

- Image
- User
- Source IP
- Source Port
- Destination IP
- Destination Port
- Protocol
- Process ID
- Timestamp

---

### Step 9 – Measure the Connection Pattern

The timestamps were reviewed to determine whether the connections occurred at regular intervals.

Expected pattern:

```text
T1
T2 = T1 + approximately 30 seconds
T3 = T2 + approximately 30 seconds
T4 = T3 + approximately 30 seconds
```

The objective was to identify periodic behavior rather than rely on a single network event.

---

### Step 10 – Investigate Wazuh Discover

Verify the endpoint:

```text
agent.name: DESKTOP-9MMM37V
```

Search for Sysmon network connection events where available:

```text
agent.name: DESKTOP-9MMM37V AND data.win.system.eventID:3
```

Additional searches can include:

```text
agent.name: DESKTOP-9MMM37V AND 127.0.0.1
```

and:

```text
agent.name: DESKTOP-9MMM37V AND 8088
```

Field names may vary depending on the Wazuh decoder and Sysmon integration.

---


# Evidence Correlation

| Evidence | Source | Observation |
|---|---|---|
| Endpoint Identity | `hostname` | Windows workstation identified |
| Process | `Get-Process` | PowerShell identified |
| Process ID | `$PID` | PID associated with the beaconing loop |
| Network Connection | `Get-NetTCPConnection` | Connection to `127.0.0.1:8088` observed |
| Network Event | Sysmon Event ID 3 | Network connection telemetry captured |
| Destination | Windows / Sysmon | Loopback address `127.0.0.1` |
| Destination Port | Windows / Sysmon | TCP `8088` |
| Periodicity | Event timestamps | Approximately 30-second intervals |
| Endpoint Telemetry | Wazuh Discover | Network activity correlated |
| Timeline | Analyst | Beacon-like pattern reconstructed |

---

# MITRE ATT&CK Context

Beaconing may be relevant to Command and Control investigations.

Potential ATT&CK context includes:

- **T1071 – Application Layer Protocol**
- **T1105 – Ingress Tool Transfer**
- **T1095 – Non-Application Layer Protocol**

The exact mapping depends on the actual communication protocol and observed behavior.

This controlled lab does not demonstrate malicious C2.

---
