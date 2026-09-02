# Third-party notices

The project source is MIT licensed. The following bundled artifacts retain their
upstream licenses and attribution.

## Splunk Attack Data

- Artifacts:
  - `app/backend/data/splunk_t1003_001_sysmon.log` — Atomic Red Team T1003.001
  - `app/backend/data/splunk_t1059_001_encoded_powershell_sysmon.log` — encoded PowerShell T1059.001
  - `app/backend/data/splunk_t1105_sysmon.log` — Atomic Red Team T1105
- Upstream: https://github.com/splunk/attack_data
- Copyright: Splunk Inc.
- License: Apache License 2.0
- License copy: `app/backend/data/LICENSE-SPLUNK-ATTACK-DATA`

The data is attack-lab telemetry. “Real logs” here means authentic raw Sysmon XML
captured from an instrumented attack-range execution, not telemetry from an unknown
production victim.

## SigmaHQ detection rules

The 30 unmodified YAML rules under `app/backend/rules/` are sourced from the official
https://github.com/SigmaHQ/sigma repository and licensed under the Detection Rule
License 1.1 (`DRL-1.1`). The curated pack covers Windows process creation and process
access detections relevant to LSASS access, PowerShell, credential tooling, Certutil,
BITS, WMI, Rundll32, and executable masquerading.

- Upstream snapshot: SigmaHQ commit `8375f87fc85224a96ec133266ea934a3338246ba`
- Snapshot date: 2026-09-01
- Artifact count: 30 YAML rules

Every bundled YAML artifact retains its upstream title, UUID, author list, references,
status, dates, ATT&CK tags, false-positive guidance, and regression-test reference where
provided. The application derives the exact upstream URL from the rule category and
filename, persists the complete YAML, and renders author/source/license provenance in
the detection library and investigation context.

The application preserves this attribution in the persisted rule artifact and displays
it with every Sigma match. A copy of the license is at
`app/backend/rules/LICENSE-SIGMA-DETECTION-RULES.md`.
