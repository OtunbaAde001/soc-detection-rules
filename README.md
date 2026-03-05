# soc-detection-rules
This includes Microsoft Sentinel KQL query, Sigma detection rule and MITRE ATT&CK mapping

```kql
SigninLogs
| where ResultType != "0" // Filter for failed sign-ins
| summarize Count = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| order by Count desc
```

```kql
DeviceNetworkEvents
| summarize count() by RemoteIP
| order by count_ desc
```
// Detect suspicious file renames, extensions, and high-volume modifications
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed", "FileModified")
| extend NewExt = tostring(split(FileName, ".")[-1])
| where NewExt in~ (
    "locked","encrypted","crypt","enc","cry","pay","pay2unlock",
    "aes","aes256","lockedfile","dark","locky","zepto","cerber"
)
    or FileName matches regex @"\.(locked|encrypted|crypt|enc|cry)$"
| summarize FileChangeCount = count(), Devices = dcount(DeviceId) by DeviceId, DeviceName, bin(Timestamp, 5m)
| where FileChangeCount > 50

// Detect processes commonly used by ransomware or performing destructive actions
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "vssadmin resize shadowstorage",
    "wbadmin delete catalog",
    "wbadmin delete systemstatebackup",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "cipher /w:",
    "powershell -enc",
    "icacls * /grant Everyone:F"
)
or ProcessName in~ (
    "vssadmin.exe","wbadmin.exe","bcdedit.exe","cipher.exe",
    "7z.exe","winrar.exe","powershell.exe","cmd.exe"
)
| project Timestamp, DeviceName, ProcessName, ProcessCommandLine, InitiatingProcessFileName, AccountName


// Combine file activity + process behaviour for stronger detection
let SuspiciousProcesses = DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete",
    "cipher /w:",
    "bcdedit /set",
    "shadowstorage"
);
let SuspiciousFiles = DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed","FileModified")
| extend NewExt = tostring(split(FileName, ".")[-1])
| where NewExt in~ ("locked","encrypted","crypt","enc","cry")
| summarize FileChangeCount = count() by DeviceId, DeviceName;
SuspiciousProcesses
| join kind=inner SuspiciousFiles on DeviceId
| project Timestamp, DeviceName, ProcessName, ProcessCommandLine, FileChangeCount







