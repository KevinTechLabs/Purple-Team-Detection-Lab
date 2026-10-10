# Windows baseline (v2)

v2 extends the lab to a **Windows 11** target with **Sysmon** (SwiftOnSecurity
config) feeding the same Wazuh manager. The headline finding is the mirror image
of Linux: **Windows is well-covered out of the box.** Where a stock Linux agent
caught 2/10, Windows + Sysmon + Wazuh's built-in ruleset catches most common
persistence/execution techniques at actionable severity with no custom rules.

## Environment

- **Target:** Windows 11 (Enterprise eval, build 26300) as a KVM guest on the
  AI-LAB host, local account only, Defender left **on**.
- **Telemetry:** Sysmon (SwiftOnSecurity `sysmonconfig-export.xml`) + the Wazuh
  Windows agent forwarding the `Microsoft-Windows-Sysmon/Operational` channel.
- **Agent:** `win11-lab`, reporting Active to the Wazuh manager (example address
  `10.20.1.10`; real addresses are not published).
- **Network:** host-NAT (`192.0.2.0/24`, documentation range) with reach to the
  manager — the VLAN-tagged path wasn't passing DHCP, and for a
  host-local-technique box NAT is an acceptable, simpler placement (documented,
  not hidden).

## Method

Identical to Linux: `windows/run_tests.ps1` runs each atomic, logs its UTC window
and cleans up. Detections are correlated in the Wazuh dashboard, filtered to the
`win11-lab` agent and `rule.level >= 6` to cut Sysmon noise and surface
actionable alerts.

## Baseline results

Confirmed detections (rule IDs observed in the dashboard for the run window):

| ATT&CK | Technique | Baseline | Evidence |
|---|---|:---:|---|
| T1547.001 | Registry Run key | ✅ Detected | 92302 (lvl 6), 92041 "Base64-like registry value" (lvl 10) |
| T1059.001 | PowerShell (Mimikatz cradle) | ✅ Detected* | 92203 / 92205 "PowerShell created executable" (lvl 6–9) |
| T1112 | Modify registry | ✅ Detected | 92041 (lvl 10) |
| T1070.001 | Clear Windows event logs | ✅ Detected, **under-rated** | 63103 "The audit log was cleared" (lvl **5**) |
| T1053.005 | Scheduled task | ◻ Likely (Security 4698 / Sysmon) — not confirmed per-window |
| T1136.001 | Create local account | ◻ Likely (Security 4720) — not confirmed per-window |
| T1003.001 | LSASS memory access | ⚠ Defender-blocked payload; Sysmon EID 10 depends on config |
| T1082 | System info discovery | ❌ Below actionable level (Sysmon EID 1 only, low severity) |
| T1033 | System owner/user discovery | ❌ Below actionable level |
| T1057 | Process discovery | ❌ Below actionable level (confirmed with test 2, `tasklist`) |

**Notes on the two that initially didn't run:** T1057's atomic test #1 is a
non-Windows variant — test **2** (`tasklist`) is the Windows one and ran clean.
T1070.001's atomic wasn't in the pulled set, so the technique was run directly
(`wevtutil cl Security`), which is actually a higher-signal test: it generates
Windows Event **1102**, caught by Wazuh rule **63103** — but only at level 5.

\* The Mimikatz payload itself was **blocked by Defender** ("Access is denied"),
but Sysmon still recorded PowerShell writing executables to disk, so the behavior
was detected even though the tool never executed. That layering — Defender blocks
the payload, Sysmon records the attempt — is itself worth showing.

Also seen: **61638 / 61634** "Sysmon - Suspicious Process" (dllhost.exe,
taskhost.exe) at level 12.

## What this means

- **Telemetry is everything.** The same SIEM caught almost nothing on a stock
  Linux agent and a lot on Windows — the difference is Sysmon plus Wazuh's rich
  Windows/Sysmon ruleset. The lesson isn't "Windows is safer," it's "instrument
  the host and the detections follow."
- **Two kinds of gap surfaced:**
  1. **Visibility gap** — discovery commands (`systeminfo`, `whoami`, `tasklist`
     for T1082/T1033/T1057) generate only low-severity process-creation events
     and never cross the actionable threshold. Same story as the Linux discovery
     gap; the fix is a custom rule + frequency logic (a burst of discovery in one
     session).
  2. **Rating gap** — T1070.001 (clearing the Security log) *is* detected by rule
     63103, but at level 5. Clearing the audit log is a high-confidence indicator
     of an actor covering their tracks; it should alert at 10–12. This is a pure
     tuning win: one override rule that raises 63103's level.

## After: custom rules close both gaps

Two rules ([`windows/local_rules.xml`](../windows/local_rules.xml)) close the
gaps, re-run verified:

| Gap | Before | After | Rule |
|---|---|---|---|
| Discovery (T1082 / T1033 / T1057) | under threshold — no actionable alert | **burst detected, level 10** | 100222 |
| Clear Security log (T1070.001) | detected but under-rated (63103, level 5) | **elevated to level 12** | 100220 |

- **100220** overrides rule 63103 so clearing the Security log alerts at 12.
  Verified: "Windows Security event log was cleared (elevated)" fired at level 12.
- **100221** tags each discovery binary (Sysmon `originalFileName`, so renames are
  caught); **100222** is a frequency rule that fires on 3+ discovery commands in 5
  minutes. Verified: "Discovery burst" fired at level 10 after six recon commands.

**A real lab gotcha, documented:** the burst rule first used `same_source_ip` to
scope the count to one host — but Windows eventchannel/Sysmon events carry no
source-IP field, so that condition silently blocked the rule. Removing it (the
agent already scopes the events) made it fire. That kind of "the rule compiles but
never matches" bug is exactly what a purple-team re-run catches.

## Still open (optional, lower value)

1. Confirm the two "Likely" rows per-window (scheduled task, account creation).
2. LSASS (T1003.001): to measure host detection rather than Defender's block, run
   it inside a Defender-exclusion window and confirm Sysmon EID 10 fires.

The honest framing stands: Windows started strong, and the two real weaknesses
(a visibility gap and a rating gap) are now fixed and proven.
