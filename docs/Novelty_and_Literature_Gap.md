# VPNGUARD-X Novelty and Literature Gap

**Version:** 0.1.0  
**Review scope:** Targeted design-stage review, not a claimed systematic literature review  
**Performance claims:** None; all comparative results are **TBD — requires experiment**

## 1. Problem with the initial integration concept

The student architecture combines common components: packet parsing, statistical features, XGBoost classification, rule checks, a weighted score, and reports. This is useful engineering but is not, by itself, a national-level research contribution. More importantly, several draft diagrams imply that passive PCAP analysis directly reveals CHILD-SA encryption, integrity, PFS, mode, lifetime, replay configuration, authentication method, and SAD contents. In IKEv2 this is generally false because exchanges after IKE_SA_INIT are protected.

The scientific problem is therefore not merely “classify encrypted VPN traffic.” It is:

> How can an analyzer make the strongest defensible IPsec configuration and security claims from incomplete encrypted evidence while proving which claims are visible, derived, probabilistic, or unknowable?

## 2. Relevant research strands

### 2.1 Encrypted-traffic classification

Deep Packet showed that learned representations can classify encrypted traffic and distinguish VPN/non-VPN traffic without conventional payload inspection. ET-BERT later used pre-trained datagram representations and explicitly discussed generalization limitations in encrypted traffic classification.

These methods motivate the feature/sequence baselines in VPNGUARD-X, but their typical output is an application/service label. They do not enforce IKE/IPsec protocol consistency, distinguish visible from hidden security configuration, or propagate configuration ambiguity into policy findings and risk intervals.

### 2.2 Logical constraints in machine learning

Semantic-loss and related neuro-symbolic work demonstrate that symbolic knowledge can guide learned outputs. CGII differs operationally: it applies hard protocol constraints as a transparent projection over a finite configuration space, records which evidence activated each constraint, detects an empty feasible set, and retains all surviving candidates. This design makes the constraint effect auditable for a protocol engineer.

### 2.3 Calibrated prediction sets

Adaptive prediction-set research demonstrates set-valued classification with finite-sample marginal coverage under exchangeability assumptions. VPNGUARD-X applies this idea to candidate VPN configurations after hard protocol projection. Coverage claims are made only when a held-out calibration set and its assumptions are recorded. Otherwise the system labels cumulative-mass sets as heuristic credible sets.

### 2.4 Standards and configuration assessment

RFC 8247, RFC 8221, RFC 9395, and NIST SP 800-77 Rev. 1 provide algorithm and deployment guidance. Conventional compliance tools assume the configuration is known from the endpoint or administrator. Passive analyzers instead face missing or encrypted fields. VPNGUARD-X evaluates rules over a supported configuration set and distinguishes certain violations from possible violations and unevaluable rules.

## 3. Gap statement

The targeted literature and current tool pattern leave five coupled gaps:

1. **Observability gap:** packet fields, endpoint state, and learned inference are frequently conflated.
2. **Protocol-validity gap:** independent ML labels may form impossible IKE/ESP combinations.
3. **Open-world gap:** closed-set traffic classifiers force a familiar class for unseen applications or stacks.
4. **Assurance gap:** point security scores hide uncertainty about encrypted configuration fields.
5. **Actionability gap:** generic recommendations are not optimized as minimum configuration changes and are not conditioned on the supported candidate set.

No claim is made here that no prior system has addressed any one of these issues. The defensible novelty hypothesis is their integrated, auditable treatment for passive IPsec assurance. A formal publication must extend this targeted review using documented databases, search strings, inclusion criteria, and a study-selection diagram.

## 4. Proposed contributions

### C1 — Executable IPsec observability model

A versioned matrix maps each property to passive visibility, derivation rule, cooperative source, failure conditions, and normative rationale. The runtime uses the same matrix to gate claims.

### C2 — Constraint-Guided IPsec Inference (CGII)

CGII eliminates candidates inconsistent with hard packet evidence and protocol semantics, then projects a learned prior onto the feasible set. It reports the candidate distribution, eliminated candidates, activated constraints, and conflict state.

### C3 — Evidence-aware calibrated configuration sets

The framework returns a calibrated prediction set when calibration data supports it, or a clearly labeled heuristic set otherwise. Point estimates are optional summaries, not mandatory outputs.

### C4 — Open-world encrypted application analysis

WEB, VIDEO, VOIP, BULK/FILE, INTERACTIVE/MESSAGING, and ICMP/CONTROL are accompanied by UNKNOWN detection, OOD metrics, leave-domain evaluation, and abstention.

### C5 — Set-valued assurance and risk intervals

Policy rules are evaluated over all supported candidates. Findings become certain, possible, or unevaluable; risk becomes an interval with evidence completeness and unresolved factors.

### C6 — Minimum-change counterfactual remediation

The engine searches a versioned configuration catalogue for compliant alternatives and separates robust changes from candidate-contingent changes.

### C7 — Dual-mode validation and reproducible cyber-range

Passive outputs are evaluated against authorized VICI/XFRM ground truth using controlled strongSwan scenarios. Every PCAP is paired with a machine-readable ground-truth record and environment manifest.

## 5. Why the combination is technically non-trivial

The components cannot be safely joined by a simple pipeline:

- Hard constraints must use only evidence eligible for elimination; an ML guess must not eliminate a standards-valid candidate.
- Calibration performed before constraint projection may not retain its nominal coverage after domain or candidate-space changes; both unconstrained and constrained calibration must be evaluated.
- Packet loss can remove IKE_SA_INIT while leaving ESP traffic; the system must widen—not sharpen—the candidate set.
- A possible policy violation must not be phrased as a detected weakness.
- Risk aggregation must preserve candidate uncertainty and rules that are genuinely unevaluable.
- Cooperative telemetry must establish labels without leaking into passive feature vectors.

## 6. Falsifiable research hypotheses

| ID | Hypothesis | Falsification test |
|---|---|---|
| H1 | CGII reduces protocol-violation rate relative to unconstrained ML without unacceptable exact-match loss | Compare both systems on identical held-out scenarios; report violation rate and paired bootstrap interval |
| H2 | Set-valued CGII maintains target marginal coverage with smaller sets than an uninformative candidate set | Split-conformal evaluation on held-out configuration groups |
| H3 | Evidence-aware abstention improves selective risk under OOD applications/stacks | Risk-coverage curves and OOD AUROC/FPR95 |
| H4 | Risk intervals achieve stated containment of ground-truth candidate risk under incomplete PCAPs | Inject 10/30/50% packet loss and test interval containment |
| H5 | Counterfactual search produces lower change cost than a fixed generic hardening checklist | Compare weighted edit cost and resulting compliance |
| H6 | Constraint projection improves label efficiency | Active-learning curves versus XGBoost/TCN without constraints |

All outcomes are **TBD — requires experiment**.

## 7. Ablations required to support novelty

1. ML prior only.
2. Deterministic parser/rules only.
3. ML + constraints without calibration.
4. ML + calibration without constraints.
5. Full CGII.
6. Full CGII without observability completeness features.
7. Full CGII without OOD abstention.
8. Point risk versus interval risk containment.
9. Generic remediation versus minimum-change remediation.

## 8. Claims the project must avoid

- “The first AI IPsec analyzer” unless a documented systematic search supports it.
- “Detects the ESP cipher from any PCAP.”
- “Determines whether PFS/anti-replay is enabled” in passive mode without qualifying evidence.
- “Security score equals breach probability.”
- “Conformal coverage” without a held-out calibration protocol and assumption statement.
- “PQC-secure” merely because an IKE_INTERMEDIATE exchange or ML-KEM-capable proposal is visible.
- Any accuracy, F1, AUROC, latency, robustness, or coverage number before experiment execution.

## 9. Positioning for SIH and publication

For SIH, the differentiator is a live demonstration in which the same PCAP yields:

- directly visible facts;
- hidden properties explicitly withheld;
- a candidate set narrowed by protocol evidence;
- a cooperative ground-truth reveal for validation;
- certain versus possible policy findings;
- an interval rather than false-precision score; and
- a minimum-change compliant configuration.

For publication, the contribution must be supported by cross-configuration/cipher/mode/encapsulation/stack generalization, OOD and incomplete-PCAP experiments, calibration evaluation, constraint-violation analysis, and reproducible artifacts.

## 10. Seed references

1. Kaufman, C. et al. RFC 7296, *Internet Key Exchange Protocol Version 2 (IKEv2)*, 2014. https://www.rfc-editor.org/rfc/rfc7296
2. Kent, S. RFC 4303, *IP Encapsulating Security Payload (ESP)*, 2005. https://www.rfc-editor.org/rfc/rfc4303
3. Wouters, P. RFC 9395, *Deprecation of IKEv1 and Obsoleted Algorithms*, 2023. https://www.rfc-editor.org/rfc/rfc9395
4. Barker, E. et al. NIST SP 800-77 Rev. 1, *Guide to IPsec VPNs*, 2020. https://doi.org/10.6028/NIST.SP.800-77r1
5. Lotfollahi, M. et al. “Deep Packet: A Novel Approach for Encrypted Traffic Classification Using Deep Learning.” *Soft Computing*, 24, 1999–2012, 2020. https://doi.org/10.1007/s00500-019-04030-2
6. Lin, X. et al. “ET-BERT: A Contextualized Datagram Representation with Pre-training Transformers for Encrypted Traffic Classification.” *The Web Conference*, 2022. https://doi.org/10.1145/3485447.3512217
7. Xu, J. et al. “A Semantic Loss Function for Deep Learning with Symbolic Knowledge.” *ICML/PMLR 80*, 2018. https://proceedings.mlr.press/v80/xu18h.html
8. Romano, Y., Sesia, M., and Candès, E. “Classification with Valid and Adaptive Coverage.” *NeurIPS*, 2020. https://proceedings.neurips.cc/paper/2020/hash/244edd7e85dc81602b7615cd705545f5-Abstract.html

