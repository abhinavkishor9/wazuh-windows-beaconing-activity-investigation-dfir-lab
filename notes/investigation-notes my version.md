# Investigation Notes

## Lab Summary

This investigation focused on analyzing a repeated network communication pattern on a Windows endpoint and determining whether the behavior resembled beaconing activity.

---

## Analyst Methodology

1. Verify Wazuh agent status.
2. Identify the Windows endpoint.
3. Establish the existing network connection baseline.
4. Create a controlled local TCP listener.
5. Generate periodic TCP connections.
6. Identify the PowerShell Process ID.
7. Correlate the PID with the network connection.
8. Identify the owning process.
9. Review Sysmon Event ID 3.
10. Collect connection timestamps.
11. Measure the approximate connection interval.
12. Investigate the endpoint in Wazuh Discover.
13. Correlate process, destination, port, and timing.

---

## Investigation Scenario

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

## Evidence Collected

### Evidence 1 – Wazuh Agent

Collected:

- Agent ID
- Agent status
- Endpoint identity

Finding:

Confirmed that the Windows endpoint was actively communicating with Wazuh.

---

### Evidence 2 – Network Baseline

Command Used

```powershell
Get-NetTCPConnection -State Established |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
```

Finding:

Established the endpoint's existing TCP connection state before generating the controlled test traffic.

---

### Evidence 3 – Local TCP Listener

Collected:

- Local listener
- TCP port `8088`
- Loopback communication

Finding:

Created a safe local destination for generating repeatable network telemetry.

---

### Evidence 4 – Periodic Network Activity

Command Used

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

Finding:

Generated repeated TCP connections to `127.0.0.1:8088` at approximately 30-second intervals.

---

### Evidence 5 – Process Identification

Command Used

```powershell
$PID
```

Finding:

Identified the Process ID of the PowerShell instance responsible for the test connection loop.

---

### Evidence 6 – Process-to-Network Correlation

Command Used

```powershell
Get-NetTCPConnection |
Where-Object {$_.RemotePort -eq 8088} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

Finding:

The `OwningProcess` value was used to associate the TCP connection with the responsible process.

---

### Evidence 7 – Process Verification

Command Used

```powershell
Get-Process -Id <PID>
```

Finding:

Confirmed that the process associated with the connection was PowerShell.

---

### Evidence 8 – Sysmon Network Connection

Event Investigated:

- Sysmon Event ID 3

Finding:

Provided network connection telemetry containing information such as process, destination, port, protocol, and timestamp.

---

### Evidence 9 – Wazuh Correlation

Wazuh Discover was searched using the endpoint identity and network telemetry.

Example:

```text
agent.name: DESKTOP-9MMM37V AND data.win.system.eventID:3
```

Additional searches:

```text
agent.name: DESKTOP-9MMM37V AND 127.0.0.1
```

```text
agent.name: DESKTOP-9MMM37V AND 8088
```

Finding:

Wazuh provided centralized visibility into the endpoint network activity and supporting Sysmon telemetry.

---

### Evidence 10 – Connection Timing

Collected:

- Sysmon Event ID 3 timestamps

Finding:

The repeated connections occurred at approximately 30-second intervals, producing a regular communication pattern.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Non-Application Layer Protocol | T1095 |

The mapping provides contextual relevance to beaconing investigations. The controlled laboratory activity itself was not malicious C2.

---

