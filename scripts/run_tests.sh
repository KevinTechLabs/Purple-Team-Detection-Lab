#!/usr/bin/env bash
# Purple-Team Detection Lab - test runner
# Runs each atomic, logs its exact UTC window to a CSV, then cleans up so the
# target returns to baseline. Run on the isolated target as a user with sudo.
set -u
ATOMICS="$HOME/AtomicRedTeam/atomics"
PSD1="$HOME/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1"
LOG="results_$(date -u +%Y%m%dT%H%M%SZ).csv"
echo "technique,test,start_utc,end_utc" > "$LOG"

run() {  # $1=technique  $2=test number
  local t="$1" n="$2"
  echo "=== $t (test $n) ==="
  local start; start=$(date -u +%FT%TZ)
  sudo pwsh -c "Import-Module '$PSD1' -Force; Invoke-AtomicTest $t -TestNumbers $n -PathToAtomicsFolder '$ATOMICS'"
  local end; end=$(date -u +%FT%TZ)
  echo "$t,$n,$start,$end" >> "$LOG"
  sleep 20   # let the alert land in Wazuh before the next test
  sudo pwsh -c "Import-Module '$PSD1' -Force; Invoke-AtomicTest $t -TestNumbers $n -PathToAtomicsFolder '$ATOMICS' -Cleanup"
  echo
}

run T1136.001 1   # create local account
run T1098.004 1   # add SSH authorized key
run T1053.003 1   # cron persistence
run T1543.002 1   # systemd service
run T1070.003 1   # clear bash history
run T1222.002 1   # chmod sensitive file
run T1087.001 1   # enumerate local accounts
run T1057 1       # process discovery
run T1046 1       # network service scan
run T1552.001 1   # search files for credentials

echo "Done. Window log: $LOG"
