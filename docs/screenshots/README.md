# Screenshots

Drop your dashboard evidence here and reference it from the main README. Suggested
set (all from the Wazuh/Sentinel runs):

| File | What it shows |
|---|---|
| `baseline-events.png` | Filtered Wazuh events during the baseline run — only 5902/2833 fire |
| `after-custom-rules.png` | Wazuh events filtered to `rule.id:(100201..100211)` — the new detections |
| `sentinel-t1552.png` | The level-12 T1552.001 alert in Sentinel with MITRE tactic mapping |
| `navigator-before-after.png` | ATT&CK Navigator baseline vs after layers side by side |

Scrub any real IPs/hostnames before committing. The Navigator images can be
exported from [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
after loading `navigator/baseline.json` and `navigator/after.json`.
