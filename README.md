# RfaPowerShell
A collection of common or misc functions.

## How to Check Windows Update history
```
[Net.ServicePointManager]::SecurityProtocol=[enum]::GetNames([Net.SecurityProtocolType])|Foreach-Object{[Net.SecurityProtocolType]::$_};( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex; Get-HotfixApiCombo
```
## Check reboot history of a computer
```
[Net.ServicePointManager]::SecurityProtocol=[enum]::GetNames([Net.SecurityProtocolType])|Foreach-Object{[Net.SecurityProtocolType]::$_};( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex;; Get-RebootReport
```

## Quickly download PSEXEC
```
[Net.ServicePointManager]::SecurityProtocol=[enum]::GetNames([Net.SecurityProtocolType])|Foreach-Object{[Net.SecurityProtocolType]::$_};( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex; Receive-PsExec
```

## Install-KB4571729
```
[Net.ServicePointManager]::SecurityProtocol=[enum]::GetNames([Net.SecurityProtocolType])|Foreach-Object{[Net.SecurityProtocolType]::$_};( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex; Install-KB4571729
```
