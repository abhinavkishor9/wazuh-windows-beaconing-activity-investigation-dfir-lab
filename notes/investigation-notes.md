# Investigation Notes

## Lab Summary

This investigation focused on analyzing a repeated network communication pattern on a Windows endpoint and determining whether the behavior resembled beaconing activity.

A controlled PowerShell connection loop was used to generate periodic TCP connections to the local loopback address `127.0.0.1` over port `8088`. The process responsible for the connections was identified and correlated with Sysmon Event ID 3 and Wazuh Discover telemetry.

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
14. Reconstruct the communication timeline.
15. Determine whether the observed behavior was benign or suspicious.
16. Stop the test listener and clean up the lab.

---

## Investigation Scenario

A SOC analyst observes repeated network connections from a Windows endpoint at seemingly regular intervals.

The activity could represent:

- Legitimate application communication
- Monitoring traffic
- Software update activity
- Command and Control beaconing

The analyst must determine:

- Which process generated the connections?
- What destination was contacted?
- What port was used?
- How frequently did the connections occur?
- Which user owned the process?
- Was the activity visible in Wazuh?
- Does the pattern represent actual malicious C2 or only beacon-like behavior?

The investigation therefore focuses on **process-to-network correlation and temporal analysis**.

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

## DFIR Analysis

The investigation demonstrated that beaconing analysis requires correlation between network activity, the process responsible for the connection, the destination, and the timing of repeated connections.

The PowerShell Process ID was correlated with the `OwningProcess` field returned by `Get-NetTCPConnection`. Sysmon Event ID 3 then provided historical network connection evidence, while Wazuh Discover supplied centralized endpoint visibility.

Although the activity produced a regular 30-second communication pattern, the destination was the local loopback address `127.0.0.1` and the traffic was intentionally generated for the lab. Therefore, the observed behavior was benign.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Non-Application Layer Protocol | T1095 |

The mapping provides contextual relevance to beaconing investigations. The controlled laboratory activity itself was not malicious C2.

---

## Analyst Observations

- Beaconing is a behavioral pattern rather than a single IOC.
- Process-to-network correlation is essential.
- Process IDs can link network connections to the responsible process.
- `OwningProcess` can help associate network activity with a process.
- Sysmon Event ID 3 provides useful network connection telemetry.
- Wazuh can centralize and correlate Sysmon network events.
- Regular communication intervals can be a useful detection signal.
- Legitimate applications can also generate periodic network traffic.
- A beacon-like pattern does not automatically prove Command and Control.
- Destination, process, user, protocol, frequency, and surrounding activity must be analyzed together.

---

## Investigation Assessment

The endpoint generated repeated connections from PowerShell to `127.0.0.1:8088` at approximately 30-second intervals.

The activity resembled beaconing from a temporal perspective, but the local destination and controlled test conditions established that the behavior was benign.

---

## Conclusion

The investigation demonstrated how a SOC analyst can identify and investigate periodic network communication by correlating process information, Process IDs, network connections, Sysmon Event ID 3, timestamps, and Wazuh telemetry.

The lab reinforced that periodic communication should be treated as an investigative lead rather than automatically classified as malicious Command and Control activity.
