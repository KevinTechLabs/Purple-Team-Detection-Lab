# Security Policy

## Scope and safety

This repository documents a **defensive detection-engineering** exercise run in an
isolated home lab. It contains Wazuh rules, auditd configuration, a test runner,
and write-ups — no exploits, malware, or offensive tooling.

- All testing was performed against a disposable host on an **isolated Lab VLAN**.
- No real IP addresses, hostnames, credentials, or keys are published. Addresses
  are replaced with documentation ranges (`10.20.x.x`, `192.0.2.x`).
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) performs the
  actions it simulates. Run it only on disposable, isolated hosts — never on a
  production or daily-use machine.

## Reporting

If you spot a sensitive value that slipped into this repo (an IP, key, or
credential), please open an issue or contact the maintainer directly so it can be
scrubbed and the history rewritten.
