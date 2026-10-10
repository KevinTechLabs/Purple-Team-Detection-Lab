# Purple-Team Detection Lab - Windows runner (v2)
# Runs each atomic on the Windows target, logs its exact UTC window, cleans up.
# Run in an elevated PowerShell on the isolated Windows VM:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\run_tests.ps1
#
# NOTE: Defender is left ON. T1059.001 (Mimikatz) and T1003.001 (LSASS) payloads
# may be blocked by Defender; the PowerShell/process behavior is still recorded
# by Sysmon. To measure host detection of the payload itself, run those inside a
# temporary Defender exclusion.

$atomics = "C:\AtomicRedTeam\atomics"
$psd1    = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1"
$log     = "$HOME\results_win_$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')).csv"
"technique,test,start_utc,end_utc" | Out-File $log -Encoding ascii
Import-Module $psd1 -Force

function Run($t,$n){
  Write-Host "=== $t (test $n) ==="
  $start=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  Invoke-AtomicTest $t -TestNumbers $n -PathToAtomicsFolder $atomics -GetPrereqs | Out-Null
  Invoke-AtomicTest $t -TestNumbers $n -PathToAtomicsFolder $atomics
  $end=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  "$t,$n,$start,$end" | Add-Content $log
  Start-Sleep 20
  Invoke-AtomicTest $t -TestNumbers $n -PathToAtomicsFolder $atomics -Cleanup
  Write-Host ""
}

Run T1059.001 1   # PowerShell execution (Mimikatz cradle)
Run T1547.001 1   # Registry Run key persistence
Run T1053.005 1   # Scheduled task
Run T1136.001 1   # Create local account
Run T1003.001 1   # LSASS memory access (Defender may block)
Run T1082 1       # System information discovery
Run T1033 1       # System owner/user discovery
Run T1057 2       # Process discovery (test 2 = Windows; test 1 is non-Windows)
Run T1070.001 1   # Clear Windows event logs (re-pull atomic if missing)
Run T1112 1       # Modify registry

Write-Host "Done. Window log: $log"
