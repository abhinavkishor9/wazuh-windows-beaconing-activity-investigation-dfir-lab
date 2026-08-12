# Investigation Timeline

| Steps | Activity | Evidence |
|---|---|---|
| 1 | Verified Wazuh agent | Wazuh Manager |
| 2 | Identified Windows endpoint | `hostname` |
| 3 | Collected local network baseline | `Get-NetTCPConnection` |
| 4 | Created local TCP listener | PowerShell |
| 5 | Started periodic connection loop | PowerShell |
| 6 | Identified current PowerShell PID | `$PID` |
| 7 | Correlated network connection with PID | `Get-NetTCPConnection` |
| 8 | Identified owning process | `Get-Process` |
| 9 | Reviewed Sysmon Event ID 3 | Event Viewer |
| 10 | Collected connection timestamps | Sysmon |
| 11 | Measured connection intervals | Analyst |
| 12 | Searched endpoint in Wazuh Discover | Wazuh |
| 13 | Correlated network activity with process | Wazuh / Sysmon |
| 14 | Reconstructed periodic communication pattern | Analyst |
| 15 | Stopped the test listener | PowerShell |
