# Review of Supplied Student Diagrams

The ten supplied diagrams are retained under `docs/legacy_diagrams/` as design-history inputs, not authoritative protocol evidence.

Useful ideas preserved in the implementation include staged PCAP ingestion, IKE/ESP separation, statistical traffic features, model comparison, security assessment, dashboards, and reports.

Corrections made by VPNGUARD-X:

| Legacy concept at risk of overclaim | Implemented correction |
|---|---|
| Mapping an ESP SPI to cipher/security properties | SPI is only `OBSERVED`; algorithms/state remain unknown unless authorized SA mapping exists |
| Treating all IKE negotiation as visible | Only fixed headers and normally unencrypted IKE_SA_INIT contents are parsed as visible; protected exchanges stay unknown |
| Inferring tunnel/transport mode from topology as fact | Topology may support `AI_INFERRED`; mode is not hard evidence without visible negotiation or telemetry |
| Treating missing PFS/lifetime/replay evidence as disabled/weak | Report `UNKNOWN/UNOBSERVABLE`; use VICI/XFRM/ground truth in cooperative mode |
| Equating UDP/4500 with a translating NAT | Report validated UDP encapsulation; do not claim an active translator solely from framing |
| Converting classifier confidence into truth | Model output remains `AI_INFERRED` and cannot eliminate candidates |
| One weighted risk score | Return a candidate-wise policy-loss interval plus evidence completeness |
| One remediation for an uncertain configuration | Return robust common and candidate-contingent minimum-cost changes |
| IKEv1 as a normal peer mode | Keep it as an isolated deprecated/negative-control condition under RFC 9395 |

Where diagram text conflicts with the standards rulebook or executable observability matrix, the latter control.
