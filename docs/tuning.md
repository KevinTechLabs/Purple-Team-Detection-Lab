# Tuning: from loud detections to usable ones

Writing a rule that fires is step one. Writing one that fires *only* on the thing
you care about is the real work. The first pass of the custom rules produced
**~1,240 alerts in one hour** on a lab box doing almost nothing — unusable as-is.

## Where the noise comes from

| Rule | Why it's loud | Fix |
|---|---|---|
| 100202 (account enum) | `-w /etc/passwd -p r` fires on every login, `ls -l`, `id`, shell completion — anything that reads the file | Scope to explicit enumeration commands (`getent passwd`, `cat /etc/passwd`) via execve, not a blanket read-watch; or threshold on frequency |
| 100207 (chmod) | `chmod`/`fchmodat` fire on normal installs, builds, package managers | Restrict to permission changes on sensitive paths (`/etc`, SUID bits), or exclude known-good parents (`apt`, `dpkg`, build dirs) |
| 100204 (find/grep) | Admins run `find`/`grep` constantly | Match on credential-indicative arguments (`id_rsa`, `.aws/credentials`, `password`) rather than the binary alone |

## Approach

1. **Measure the baseline noise** per rule over 24h of normal activity.
2. **Add context** — technique keys in auditd should encode *intent* (the file
   being searched, the argument pattern), not just the binary.
3. **Frequency rules** — a single `ps` is noise; 20 discovery commands from one
   session in 60s is a signal. Use Wazuh `frequency`/`timeframe` composite rules.
4. **Allow-list the benign** — package managers, CI agents, the backup job.
5. **Re-measure** and record the before/after alert volume, same as the detection
   before/after.

This mirrors the evidence-based tuning in
[Homelab-SIEM-Detection-Lab](https://github.com/KevinTechLabs/Homelab-SIEM-Detection-Lab),
where ~8,300 false-alarm events were turned into quiet records while everything
else still alerted at full severity.

## Status

Detection coverage is proven (2/10 → 7/10). Noise reduction is the next pass and
is intentionally *not* folded into the headline numbers — the point of this repo
is to show both halves of the job honestly.
