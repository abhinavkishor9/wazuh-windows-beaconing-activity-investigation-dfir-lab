# Investigation Timeline

## Lab 48 – Beaconing Activity Investigation

| Sequence | Activity | Evidence |
|---|---|---|
| T1 | Verified Wazuh agent | Wazuh Manager |
| T2 | Identified Windows endpoint | `hostname` |
| T3 | Collected local network baseline | `Get-NetTCPConnection` |
| T4 | Created local TCP listener | PowerShell |
| T5 | Started periodic connection loop | PowerShell |
| T6 | Identified current PowerShell PID | `$PID` |
| T7 | Correlated network connection with PID | `Get-NetTCPConnection` |
| T8 | Identified owning process | `Get-Process` |
| T9 | Reviewed Sysmon Event ID 3 | Event Viewer |
| T10 | Collected connection timestamps | Sysmon |
| T11 | Measured connection intervals | Analyst |
| T12 | Searched endpoint in Wazuh Discover | Wazuh |
| T13 | Correlated network activity with process | Wazuh / Sysmon |
| T14 | Reconstructed periodic communication pattern | Analyst |
| T15 | Stopped the test listener | PowerShell |
| T16 | Completed investigation assessment | Analyst |

---

# Investigation Flow

```text
Verify Wazuh Agent
        ↓
Identify Endpoint
        ↓
Collect Network Baseline
        ↓
Create Local Listener
        ↓
Generate Periodic Connections
        ↓
Identify PowerShell PID
        ↓
Correlate PID With Connection
        ↓
Identify Owning Process
        ↓
Review Sysmon Event ID 3
        ↓
Measure Connection Intervals
        ↓
Investigate Wazuh Discover
        ↓
Correlate Process + Network + Timing
        ↓
Build Timeline
        ↓
Assess Beaconing Behavior
        ↓
Clean Up Lab
```

---

# Connection Timeline

The controlled traffic followed an approximately periodic pattern:

| Event | Destination | Port | Expected Interval |
|---|---|---|---|
| Connection 1 | 127.0.0.1 | 8088 | Initial |
| Connection 2 | 127.0.0.1 | 8088 | ~30 seconds |
| Connection 3 | 127.0.0.1 | 8088 | ~30 seconds |
| Connection 4 | 127.0.0.1 | 8088 | ~30 seconds |
| Connection 5 | 127.0.0.1 | 8088 | ~30 seconds |

Use the actual timestamps captured from Sysmon Event ID 3 in the final investigation record.

---

# Process-to-Network Timeline

The core correlation was:

```text
PowerShell Process
       ↓
Process ID
       ↓
OwningProcess
       ↓
TCP Connection
       ↓
127.0.0.1:8088
       ↓
Repeated Every ~30 Seconds
```

---

# Timeline Analysis

The investigation began with endpoint and Wazuh validation, followed by a baseline review of existing network connections.

A local TCP listener was then created on port `8088`. PowerShell generated repeated connections to `127.0.0.1` at approximately 30-second intervals.

The PowerShell Process ID was obtained using `$PID` and correlated with the network connection using the `OwningProcess` field returned by `Get-NetTCPConnection`.

Sysmon Event ID 3 provided historical network connection telemetry. The resulting events were investigated in Wazuh Discover to correlate process, destination, port, and timestamp information.

---

# Analyst Assessment

The observed traffic demonstrated a **beacon-like periodic communication pattern**, but it did not represent malicious Command and Control activity.

The destination was `127.0.0.1`, the connection was intentionally generated, and the listener was created as part of the controlled lab.

The investigation therefore demonstrates the importance of distinguishing:

```text
Periodic Communication
        ≠
Confirmed C2
```

A real beaconing investigation would require additional analysis of the process, external destination, destination reputation, protocol, user context, duration, and surrounding endpoint activity.
```
