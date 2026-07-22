# TSA-001: Threat Assessment

Companion to the TSA-001 malware analysis report. This document covers actor and campaign context and expresses judgment in ICD 203 estimative language. It assumes the technical findings in the analysis report and does not restate them.

## Actor Naming

Vendor naming for this activity operates at two layers. Venom Spider, also called Golden Chickens, is the malware-as-a-service provider whose builder produces this dropper. FIN6, also called Skeleton Spider, and TA4557 are names for operators who buy from that provider. More than one operator uses the same builder, which is why similar droppers appear in campaigns attributed to different groups.

## Key Judgments

FIN6 almost certainly remains an active, financially motivated threat to corporate recruitment and HR functions. Confidence: high. This rests on 2025 campaign reporting from multiple independent vendors and a multi-year pattern of tactic evolution.

The more_eggs delivery chain is very likely intended as an initial-access foothold for follow-on objectives such as credential theft or ransomware staging, rather than as an end in itself. Confidence: moderate. This rests on the malware's modular, download-capable design and the operator's monetization history rather than on directly observed post-exploitation activity in this sample.

Network indicators for this campaign are low durability. Confidence: moderate. The sample's drop host is an attacker subdomain on a commercial domain registered since 2015, so the parent cannot be blocked without collateral impact. Host and behavioral indicators are more durable and should be prioritized for detection: the relocation of a signed binary outside System32, the creation of `ieuinit.inf` in a user temp directory, and the anomalous process ancestry those produce.

## Confidence and Gaps

Confidence is highest on the malware family identification, which matches the documented more_eggs execution chain. Confidence on the specific operator is lower, because vendor naming across FIN6, Skeleton Spider, and TA4557 is not reconciled and this sample's repository tagging is a single submitter-supplied value rather than a vendor assessment.

The main limitation is the absence of runtime and telemetry data. Analysis was static only and no detonation was performed, so behavioral claims are derived by reading the reassembled command chain rather than by observation.

## Estimative Language

Likelihood terms follow ICD 203, Section D.6.e.(2)(a). Confidence is expressed as high, moderate, or low following common threat-intelligence convention; ICD 203 permits confidence levels but does not define a three-point scale. Likelihood and confidence are stated in separate sentences.

## References

- MITRE ATT&CK, FIN6 (G0037): [Link](https://attack.mitre.org/groups/G0037/)
- Malpedia, js.more_eggs: [Link](https://malpedia.caad.fkie.fraunhofer.de/details/js.more_eggs)
- ICD 203, Analytic Standards: [Link](https://www.dni.gov/files/documents/ICD/ICD-203.pdf)
