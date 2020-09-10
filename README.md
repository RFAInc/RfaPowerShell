# RfaPowerShell
A collection of common or misc functions.

## How to Check Windows Update history
```
( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex; Get-HotfixApiCombo
```

## Quickly download PSEXEC
```
( new-object Net.WebClient ).DownloadString( 'https://raw.githubusercontent.com/RFAInc/RfaPowerShell/master/RfaPowerShell.psm1' ) | iex; Receive-PsExec
```
