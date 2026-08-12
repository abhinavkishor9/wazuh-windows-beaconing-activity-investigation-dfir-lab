# Troubleshooting Notes

## Issue 1 – Unable to Identify the Correct PowerShell PID

### Problem

Multiple PowerShell processes were running, making it difficult to determine which process generated the periodic connections.

### Cause

More than one PowerShell session was active on the endpoint.

### Resolution

From the PowerShell window running the beaconing loop, execute:

```powershell
$PID
```

This returns the PID of the current PowerShell process.

Verify the PID with:

```powershell
Get-Process -Id <PID>
```

---

## Issue 2 – TCP Connection Not Visible in Get-NetTCPConnection

### Problem

The connection to port `8088` was not visible when checking active TCP connections.

### Cause

The lab connection was intentionally opened and closed quickly, so the connection may have terminated before the command was executed.

### Resolution

Run the query while the connection is active:

```powershell
Get-NetTCPConnection |
Where-Object {$_.RemotePort -eq 8088} |
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
```

Use Sysmon Event ID 3 for historical evidence when the live connection is no longer present.

---

## Issue 3 – Sysmon Event ID 3 Not Found

### Problem

No network connection events were visible in the Sysmon Operational log.

### Cause

Possible causes include:

- Sysmon is not running.
- Network connection monitoring is unavailable.
- The relevant event was not generated.
- The Sysmon configuration does not provide the expected telemetry.

### Resolution

Check the Sysmon service:

```powershell
Get-Service Sysmon64
```

Then review:

```text
Event Viewer
→ Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational
```

Search for:

```text
Event ID 3
```

---

## Issue 4 – Wazuh Does Not Show Event ID 3

### Problem

Sysmon Event ID 3 was visible locally but could not immediately be found in Wazuh Discover.

### Cause

The Sysmon Operational channel may not be collected, decoded, or indexed in the expected Wazuh fields.

### Resolution

First verify the endpoint:

```text
agent.name: DESKTOP-9MMM37V
```

Then search more broadly:

```text
data.win.system.eventID:3
```

If necessary, inspect a known Sysmon event in Wazuh and use the field names actually present in that event.

---


## Issue 5 – OwningProcess Did Not Match the Expected PID

### Problem

The PID returned by `Get-NetTCPConnection` did not immediately match the PowerShell PID.

### Cause

Possible causes include:

- Multiple PowerShell sessions.
- The connection closed before the PID was checked.
- The process changed between observations.
- The network query was performed after the connection ended.

### Resolution

Run the network query during an active connection and immediately check:

```powershell
Get-Process -Id <PID>
```

Also verify the current PowerShell PID using:

```powershell
$PID
```

---

## Issue 6 – Connection Intervals Were Not Exactly 30 Seconds

### Problem

The observed intervals varied slightly.

Example:

```text
29 seconds
31 seconds
30 seconds
```

### Cause

Process scheduling, system load, execution time, and event collection latency can introduce small variations.

### Resolution

Use approximate periodicity rather than requiring identical intervals.

Document the actual timestamps from Sysmon rather than assuming every interval is exactly 30 seconds.

---

## Issue 7 – Beacon-Like Pattern Could Be Misclassified

### Problem

The repeated connection pattern appeared suspicious because it was periodic.

### Cause

Regular network communication can resemble C2 beaconing even when the traffic is legitimate.

### Resolution

Investigate the complete context:

- Process
- User
- Destination
- Port
- Protocol
- Frequency
- Destination reputation
- Purpose of the application

For this lab:

```text
Process: powershell.exe
Destination: 127.0.0.1
Port: 8088
```

The activity was intentionally generated and was therefore benign.

---

## Issue 8 – Listener Remained Active After Testing

### Problem

Port `8088` remained open after the lab.

### Cause

The TCP listener was still running in the PowerShell session.

### Resolution

Stop the listener:

```powershell
$listener.Stop()
```

Verify:

```powershell
Get-NetTCPConnection -LocalPort 8088 -ErrorAction SilentlyContinue
```

---

