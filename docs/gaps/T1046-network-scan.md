# Gap: T1046 — Network service scanning (host-side miss, by design)

## What was tested
Atomic Red Team T1046 test 1 performs a port sweep using bash's `/dev/tcp`
pseudo-device:
```
( echo 2> /dev/null > /dev/tcp/<target>/$port )
```

## Why host auditing can't see it
`/dev/tcp` is a **bash builtin**, not an external program. It opens sockets
directly from the shell process and spawns no child process, so there is no
`execve` for auditd to record. The host simply has no process-level artifact to
alert on. (The auditd/Wazuh rule 100206 only fires if the scan uses the real
`nmap` binary.)

## Why this is a layering decision, not a failure
Port scanning is a **network** behavior and is best detected where the packets
are: at the firewall/IDS. In this environment that's already covered:

- **Suricata** on pfSense (scan/recon signatures)
- **pfBlockerNG** / firewall logs showing a burst of connection attempts across
  many ports from one source

Trying to force host-based detection of a socket-level scan would be the wrong
tool for the job. The honest result is: **host = no detection, network = covered.**

## Optional host-side addition
If host visibility into scans is wanted, point the atomic at `nmap` (rule 100206
already matches it), or add auditd `connect` syscall logging — but expect that to
be extremely noisy and of limited value versus the network layer.
