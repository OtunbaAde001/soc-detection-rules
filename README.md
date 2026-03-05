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
```kql
let startTime = ago(30d);
let endTime = now();
let suspiciousExtensions = dynamic([".locked", ".encrypted", ".crypt"]);
let massFileModifications = DeviceNetworkEvents
    | where Timestamp between (startTime .. endTime)
    | where ActionType == "FileModified"
    | summarize Count = count() by FileName, DeviceId
    | where Count > 100; // Example threshold for mass modifications
let highVolumeRenames = DeviceNetworkEvents
    | where Timestamp between (startTime .. endTime)
    | where ActionType == "FileRenamed"
    | summarize Count = count() by FileName, DeviceId
    | where Count > 100; // Example threshold for high-volume renames
let knownRansomwareProcesses = DeviceNetworkEvents
    | where Timestamp between (startTime .. endTime)
    | where ProcessName in ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "cipher.exe")
    | summarize Count = count() by ProcessName, DeviceId;
let shadowCopyDeletions = DeviceNetworkEvents
    | where Timestamp between (startTime .. endTime)
    | where ActionType == "ShadowCopyDeleted"
    | summarize Count = count() by DeviceId;
union massFileModifications, highVolumeRenames, knownRansomwareProcesses, shadowCopyDeletions
| summarize TotalCount = sum(Count) by DeviceId
| order by TotalCount desc
```
