# TSA-001: more_eggs LNK Dropper Delivered as a Fake Resume

Static analysis of a Windows shortcut dropper distributed inside a ZIP archive named after a fictitious job applicant. The archive is the delivery stage of a recruiter-targeted phishing campaign that ends in the more_eggs JavaScript backdoor.

TLP:CLEAR

---

## Summary

The shortcut runs an obfuscated batch command that writes a configuration file to the user's temporary directory, copies the Microsoft-signed system binary `ie4uinit.exe` beside it, and runs that binary with the `-basesettings` switch. The signed binary reads the attacker's configuration file and uses it to fetch and execute a remote COM scriptlet.

No attacker-written executable is placed on disk at any point. Execution is proxied entirely through a signed Windows binary reading a text configuration file, which defeats controls keyed on unsigned or unknown binaries.

The obfuscation is rebuilt per victim by the delivery server. Signatures keyed on the obfuscation vocabulary will not survive to the next sample, so the detection content here is structural rather than string-based.

---

## Repository contents

```
report/       Malware analysis report and threat assessment
rules/        Two YARA rules, two Sigma rules
iocs/         Indicator set, MISP import block
evidence/     Raw tool output supporting every claim in the report
notes/        Chain of custody, file manifest
screenshots/  MISP event and IRIS case
```

### Reports

- `report/TSA-001-malware-analysis-report.md` — full analysis, Zeltser template
- `report/TSA-001-threat-assessment.md` — actor and campaign context, ICD 203 estimative language

### Detection content

| File | Target | Status |
|---|---|---|
| `rules/fin6_moreeggs_lnk.yar` | LNK stage, structural | Validated against sample |
| `rules/moreeggs_dropped_inf.yar` | Dropped INF, fragmented directives | Validated against sample |

Process-level detection for this technique is already covered by the public
SigmaHQ rule `Ie4uinit Lolbin Use From Invalid Path`
(d3bf399f-b0cf-4250-8bb4-dfc192ab81dc), which fires on ie4uinit.exe executing
from a directory outside System32. That rule is referenced rather than
duplicated here. The YARA rules above cover the LNK and INF stages, for which
no public rule exists.

### Reproduction

Deobfuscation is reproducible from the two CyberChef recipes in `evidence/`. Load the recipe, paste the corresponding input, and compare the output byte count against the value stated in the report.

---

## Analysis environment

REMnux on an isolated VLAN with egress blocked at the network boundary and at the host firewall. Inbound SSH from a single jump host. The sample was never executed and no connection to campaign infrastructure was attempted at any point.

Every finding is reproducible from the sample bytes without network access.

Tooling: 7-Zip, file, TrID, Detect It Easy, ExifTool, LnkParse3, ClamAV, YARA with the YARA Forge core package, CyberChef.

---

## Enrichment and case management

Indicators were enriched through an IntelOwl playbook combining VirusTotal, AbuseIPDB, MISP, MalwareBazaar, URLhaus and ThreatFox. Results were curated by hand into a single MISP event carrying file, URL and domain-ip objects with explicit relationships, plus threat actor, malware and attack pattern galaxy clusters. A corresponding case was opened in IRIS with the indicator set, a timeline and open tasks for detection rule validation.

Automatic push connectors were deliberately disabled. A connector emits flat attributes with no relationships, and the relationship graph is the point of the event.

These steps followed the analysis rather than driving it. The IRIS timeline records that sequence honestly rather than backdating it.

---

## Scope

In scope: the ZIP archive, the LNK dropper, the decoy image, and the INF file the dropper writes.

Out of scope: the more_eggs JavaScript backdoor and the DLL component that follows it. The next stage was already offline when this sample was analysed and was not recovered.

Analysis was static only. Behavioral claims are derived by reassembling and reading the obfuscated command chain, not by observation. The report states this limitation in each section where it applies.
