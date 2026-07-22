# Threat Sample Analysis

Static analysis of real malware samples, from acquisition through detection content. Each entry takes one sample, works it end to end in an isolated lab, and publishes the analysis, the indicators, the detection rules, and the handling record.

The work is first-party. Findings come from examining the sample, not from restating vendor write-ups. Where an entry builds on published reporting, it says so and cites it.

## Method

Each sample is acquired to an isolated, egress-blocked analysis network and hashed at every transfer hop. Analysis follows the four-stage model: automated triage, static properties, then deeper static or dynamic work as the sample warrants. Every claim traces to raw tool output published alongside the report.

Reports follow the structure of Lenny Zeltser's malware analysis template. Threat judgments use ICD 203 estimative language. Handling records capture the chain-of-custody elements from NIST SP 800-86.

## Structure

Every entry has the same five directories:

```
report/     Analysis report and, where written, a threat assessment
iocs/       Machine-readable indicator set
rules/      Detection content authored for the sample
evidence/   Raw tool output behind every claim
notes/      Chain of custody and file manifest
```

Optional directories appear when the work produced them: a detonated sample adds behavioral output, a packed binary adds an unpacked payload, and so on. Nothing empty is added for symmetry.

## Entries

| ID | Sample | Focus |
|---|---|---|
| TSA-001 | more_eggs LNK dropper (FIN6) | Static analysis of a two-layer obfuscated LNK dropper; signed-binary proxy execution; LNK forensic metadata; authored YARA |
