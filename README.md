# Windows Beaconing Activity Investigation with Wazuh (DFIR Lab 48)

## Overview

Beaconing is a repeated network communication pattern in which an endpoint contacts the same destination at regular or semi-regular intervals. Although periodic communication can be associated with Command and Control (C2), legitimate applications can also generate regular network traffic.

In this lab, a safe local periodic TCP connection pattern was generated and investigated using PowerShell, process identification, Windows network information, Sysmon Event ID 3, and Wazuh Discover. The investigation focused on correlating the communicating process, destination, port, timing, and user context.

---

# Lab Objectives

- Understand beaconing behavior from a DFIR perspective
- Identify repeated network connection patterns
- Identify the process responsible for a network connection
- Correlate a network connection with a Process ID
- Analyze Sysmon Event ID 3
- Investigate periodic connection timestamps
- Correlate network activity with Wazuh Discover
- Distinguish beacon-like behavior from confirmed C2 activity
- Build a network activity timeline
- Document forensic observations

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

A Windows endpoint is suspected of generating periodic network traffic.

A SOC analyst must determine whether the repeated connections represent normal application behavior or a potential beaconing pattern associated with Command and Control activity.

For the controlled lab, the endpoint intentionally generated repeated TCP connections to the local loopback address `127.0.0.1` on port `8088`.

The investigation focuses on:

- Identifying the communicating process
- Determining the Process ID
- Identifying the destination
- Measuring connection intervals
- Reviewing Sysmon Event ID 3
- Correlating the activity in Wazuh
- Determining whether the pattern is actually malicious

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

# Key Findings

- A controlled periodic TCP connection pattern was successfully generated.
- The destination was `127.0.0.1`.
- The destination port was `8088`.
- PowerShell was identified as the process generating the connections.
- The Process ID was identified using `$PID`.
- `Get-NetTCPConnection` was used to correlate the network connection with the owning process.
- Sysmon Event ID 3 provided network connection telemetry.
- Wazuh Discover was used to correlate endpoint network activity.
- The connections occurred at approximately regular intervals.
- The activity was intentionally generated and therefore was not malicious C2.

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

# DFIR Analysis

The investigation demonstrated how repeated network connections can produce a beacon-like pattern that warrants investigation in a SOC environment.

Process-to-network correlation was particularly important. Identifying the destination alone would not provide enough context. The investigation linked the network connection to a specific PowerShell process using the Process ID and `OwningProcess` information.

Sysmon Event ID 3 and Wazuh Discover provided additional centralized telemetry for analyzing the connection pattern.

Because the destination was the local loopback address `127.0.0.1` and the activity was intentionally generated as part of the lab, the observed periodic traffic was benign.

This demonstrates an important SOC principle:

> Regular network communication is a detection lead, not automatic proof of Command and Control.

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

# Skills Practiced

- Windows DFIR
- Network Activity Analysis
- Beaconing Analysis
- Process-to-Network Correlation
- Process ID Analysis
- Get-NetTCPConnection
- Sysmon Event ID 3
- Wazuh Discover
- Timeline Reconstruction
- SOC Investigation
- Behavioral Analysis
- Evidence Correlation

---

# Outcome

Successfully generated and investigated a controlled periodic network connection pattern using PowerShell.

The investigation correlated the PowerShell process with its Process ID, destination IP, destination port, and repeated connection timestamps. Sysmon Event ID 3 and Wazuh Discover were used to provide endpoint and SIEM visibility.

The lab demonstrated how analysts can identify beacon-like behavior while avoiding the incorrect assumption that periodic traffic automatically represents malicious Command and Control.
