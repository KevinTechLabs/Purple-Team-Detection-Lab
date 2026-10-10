# Screenshots

## Windows — custom rules firing (the "after")

![Windows after detections](windows-after-detections.png)

*Filtered to the custom rules: each discovery command tagged (100221), the
**Discovery burst** firing at level 10 (100222), and the **Security log clear**
elevated to level 12 (100220) — the two gaps closed.*

## Windows — the log-clear rating gap, before and after

![Log clear before and after](windows-logclear-before-after.png)

*Same action, two ratings: stock Wazuh scores a cleared Security log at level 5
(rule 63103); the custom override (100220) raises it to level 12.*

## Windows — baseline detections (out of the box)

![Windows baseline detections](windows-baseline-detections.png)

*Before any custom rules: Wazuh + Sysmon already catch PowerShell dropping
executables, registry Run-key / Base64 writes, and suspicious processes.*

---

### Still worth adding (optional)

- **Linux credential-access alert** — the Sentinel / Wazuh **T1552.001
  "/etc/shadow"** alert at level 12, for the Linux side.
- **ATT&CK coverage** — before/after comparison graphics are generated from the
  Navigator layers in [`../../navigator/`](../../navigator/).

Capture more with a region screenshot (`grim -g "$(slurp)" ~/Pictures/shot.png`),
dragging the box **below the address bar** so no real IP is included.
