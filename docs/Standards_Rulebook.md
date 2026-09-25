# VPNGUARD-X Standards Rulebook

**Rulebook version:** 0.1.0  
**Semantic cutoff:** 2026-09-13  
**Machine-readable rules:** `configs/policy_rules.yaml`  
**Principle:** implementation requirements, deployment policy, and packet observability are separate concepts.

## 1. Interpretation rules

1. RFC 2119/8174 terms retain their normative force only in the source document’s stated scope.
2. `MUST implement` does not mean `MUST negotiate/use` in every deployment.
3. RFC 9395 updates RFC 8247 and RFC 8221. Explicit later deprecations take precedence.
4. NIST SP 800-77 Rev. 1 rules belong to the `nist_800_77r1` profile; they are not mislabeled as universal IETF requirements.
5. strongSwan documentation establishes implementation support/telemetry semantics, not general protocol mandates.
6. A passive-capture rule may conclude `UNKNOWN/UNOBSERVABLE`; absence of visible evidence is not a weakness.
7. Policy rules are evaluated over CGII’s supported candidate set. A violation is `certain` only when every candidate violates it.

## 2. Source register

| Source ID | Document | Version/status | URL |
|---|---|---|---|
| RFC7296 | Internet Key Exchange Protocol Version 2 | Internet Standard, Oct. 2014 | https://www.rfc-editor.org/rfc/rfc7296 |
| RFC4303 | IP Encapsulating Security Payload | Proposed Standard, Dec. 2005 | https://www.rfc-editor.org/rfc/rfc4303 |
| RFC3948 | UDP Encapsulation of IPsec ESP Packets | Standards Track, Jan. 2005 | https://www.rfc-editor.org/rfc/rfc3948 |
| RFC8247 | IKEv2 algorithm requirements/guidance | Proposed Standard, updated by RFC9395 | https://www.rfc-editor.org/rfc/rfc8247 |
| RFC8221 | ESP/AH algorithm requirements/guidance | Proposed Standard, updated by RFC9395 | https://www.rfc-editor.org/rfc/rfc8221 |
| RFC9395 | IKEv1 and obsolete-algorithm deprecation | Proposed Standard, Apr. 2023 | https://www.rfc-editor.org/rfc/rfc9395 |
| RFC9370 | Multiple Key Exchanges in IKEv2 | Proposed Standard, May 2023 | https://www.rfc-editor.org/rfc/rfc9370 |
| NIST80077R1 | Guide to IPsec VPNs | Final, June 2020 | https://doi.org/10.6028/NIST.SP.800-77r1 |
| SSWAN61 | strongSwan documentation | 6.1 documentation/current release at cutoff | https://docs.strongswan.org/docs/latest/ |

## 3. Observability rules

### OBS-IKE-001 — IKE version from header

- **Property:** `ike.version`
- **Source:** RFC 7296 §3.1, IKE Header; version field.
- **Predicate:** a structurally valid IKE header is parsed.
- **Output:** major/minor version is `OBSERVED`.
- **Caution:** UDP port 500/4500 alone is insufficient; validate header length/version/exchange structure.

### OBS-IKE-002 — Visible IKE_SA_INIT algorithms

- **Properties:** `ike.encryption`, `ike.integrity`, `ike.prf`, `ike.ke_group`.
- **Source:** RFC 7296 §1.2 and §3.3.
- **Predicate:** complete request and/or responder IKE_SA_INIT SA/KE payloads are visible and parsed.
- **Output:** offered transforms are `OBSERVED`; the responder’s selected transforms are `OBSERVED` when SAr1 is available.
- **Caution:** offered algorithms are not negotiated algorithms. If only the initiator proposal is captured, return a set of offers.

### OBS-IKE-003 — Protected-exchange boundary

- **Properties:** identity, authentication method, initial CHILD-SA transforms/traffic selectors/mode, later CHILD-SA details, protected notifications.
- **Source:** RFC 7296 §1.2–§1.3 and §3.14. IKE_AUTH, CREATE_CHILD_SA, and INFORMATIONAL payloads after the header are encrypted/integrity protected.
- **Predicate:** passive mode without authorized keys/telemetry.
- **Output:** protected contents are `UNKNOWN/UNOBSERVABLE` unless another valid evidence source exists.
- **Caution:** exchange type, header SPIs, message ID, flags, direction, size, and timing may remain visible; they do not reveal protected payload values.

### OBS-IKE-004 — CHILD-SA mode

- **Property:** `child.mode`.
- **Source:** RFC 7296 §1.3.1 and §2.23. `USE_TRANSPORT_MODE` is associated with the protected CHILD-SA negotiation; otherwise CHILD SAs use tunnel mode by protocol default when the option is not selected.
- **Passive output:** normally `UNKNOWN/UNOBSERVABLE`; outer-address topology may be `AI_INFERRED` only.
- **Cooperative output:** `OBSERVED` from VICI/XFRM/ground truth.
- **Caution:** do not assume tunnel mode merely because the notification cannot be seen through encryption.

### OBS-IKE-005 — CHILD-SA PFS

- **Property:** `child.pfs_group`.
- **Source:** RFC 7296 §1.3.1, §2.17, and §3.3.2. A fresh KE in CREATE_CHILD_SA can provide PFS for generated CHILD-SA keys.
- **Passive output:** `UNKNOWN/UNOBSERVABLE`; CREATE_CHILD_SA payload contents are protected.
- **Cooperative output:** `OBSERVED` from selected CHILD-SA/VICI configuration or scenario ground truth.

### OBS-IKE-006 — IKEv2 SA lifetime

- **Property:** `ike.lifetime_seconds` and `child.lifetime_seconds`.
- **Source:** RFC 7296 §2.8: unlike IKEv1, each IKEv2 endpoint enforces its own lifetime policy.
- **Passive output:** configured lifetime is `UNKNOWN/UNOBSERVABLE`. Observed rekey timing may be reported separately as `OBSERVED` timing or `AI_INFERRED` policy estimate.
- **Cooperative output:** `OBSERVED` from endpoint state/configuration.

### OBS-IKE-007 — Peer identity/authentication

- **Properties:** `peer.identity`, `authentication.family`, certificate attributes.
- **Source:** RFC 7296 §1.2, §1.3.1, §2.15–§2.16.
- **Passive output:** `UNKNOWN/UNOBSERVABLE` in normal IKEv2 after IKE_SA_INIT.
- **Caution:** outer IP address and IKE SPI are not authenticated identities.

### OBS-ESP-001 — ESP header facts

- **Properties:** `esp.spi`, `esp.sequence_low32`.
- **Source:** RFC 4303 §2.1–§2.2.
- **Output:** valid header values are `OBSERVED`.
- **Caution:** SPI is an index used in SAD lookup. It does not expose the SAD’s algorithms, keys, mode, lifetime, or replay window.

### OBS-ESP-002 — ESP algorithms

- **Properties:** `child.encryption`, `child.integrity`.
- **Source:** RFC 4303 §2 packet format; algorithms reside in SA state, while passive ESP exposes SPI/sequence and protected data.
- **Passive output:** `UNKNOWN/UNOBSERVABLE` unless a matching visible negotiation or authorized SA mapping exists. For normal IKEv2 the CHILD-SA negotiation is protected.
- **Cooperative output:** `OBSERVED` from VICI/XFRM.

### OBS-ESP-003 — ESN

- **Property:** `child.esn`.
- **Source:** RFC 4303 §2.2.1: only low-order 32 bits are transmitted even when ESN is used; ESN use is negotiated by SA management.
- **Passive output:** `UNKNOWN/UNOBSERVABLE` for ordinary captures shorter than a sequence wrap and without negotiation visibility.
- **Cooperative output:** `OBSERVED` from VICI/XFRM.

### OBS-ESP-004 — Anti-replay state

- **Properties:** `child.anti_replay_enabled`, window size, bitmap/current high sequence.
- **Source:** RFC 4303 §3.4.3. Implementations support anti-replay, but a receiver may enable/disable it per SA; receiver state is local.
- **Passive output:** `UNKNOWN/UNOBSERVABLE`. Packet sequence gaps/duplicates are observations, not proof of receiver enforcement.
- **Cooperative output:** `OBSERVED` from XFRM state/counters.

### OBS-NATT-001 — UDP 4500 demultiplexing

- **Property:** `encapsulation` and `packet.kind`.
- **Source:** RFC 3948 §2.1 and RFC 7296 §2.23.
- **Predicate:** UDP payload on port 4500 begins with four zero octets for an IKE non-ESP marker; a non-zero initial SPI identifies UDP-encapsulated ESP subject to structural validation; `0xff` single-byte payload is a NAT keepalive.
- **Output:** framing is `OBSERVED`; NAT-T session use is `DETERMINISTICALLY_DERIVED` from validated framing/session context.
- **Caution:** UDP 4500 alone does not determine IKE version and is not automatically ESP.

### OBS-NAT-002 — NAT detection

- **Property:** `nat_detected`.
- **Source:** RFC 7296 §2.23.
- **Output:** NAT detection notification payloads are `OBSERVED`; a verified hash mismatch is `DETERMINISTICALLY_DERIVED` NAT evidence when all required inputs are captured. NAT-T framing is evidence of encapsulation, not necessarily proof of a currently translating device.

## 4. Protocol-consistency rules

### CON-AEAD-001 — No separate integrity transform with AEAD

- **Scope:** IKE and ESP candidate consistency.
- **Source:** RFC 7296 §3.3 and RFC 8221 §4–§5.
- **Rule:** AEAD encryption candidates use `NONE` as the separate integrity field; non-AEAD encryption requires an allowed integrity mechanism under the selected policy.
- **Action:** eliminate impossible/inadmissible candidate combinations; this is not itself a vulnerability finding.

### CON-EVIDENCE-001 — Hard evidence only

- **Scope:** CGII.
- **Rule:** only validated `OBSERVED` or registered `DETERMINISTICALLY_DERIVED` evidence may hard-eliminate candidates. AI predictions cannot become premises for deterministic claims.
- **Source:** VPNGUARD-X assurance contract; research-system invariant.

### CON-CONFLICT-001 — Contradictory sources

- **Scope:** all properties.
- **Rule:** two authoritative observations with incompatible values produce `EVIDENCE_CONFLICT`; source priority must not silently discard either value.
- **Source:** VPNGUARD-X assurance contract.

## 5. IETF policy rules

### IETF-IKEV1-001 — IKEv1 is deprecated

- **Source:** RFC 9395 Abstract and §3.
- **Condition:** `ike_version == IKEV1`.
- **Finding:** certain/possible use of a deprecated Historic protocol.
- **Severity default:** high.
- **Remediation:** migrate to IKEv2; retain IKEv1 only as an isolated negative-control scenario.

### IETF-IKE-ENC-001 — DES/NULL prohibition

- **Source:** RFC 8247 §2.1.
- **Condition:** IKE encryption `ENCR_DES` or `ENCR_NULL`.
- **Normative status:** MUST NOT.
- **Severity:** critical.

### IETF-IKE-PRF-001 — MD5 PRF prohibition

- **Source:** RFC 8247 §2.2; RFC 9395 updates registry status.
- **Condition:** `PRF_HMAC_MD5`.
- **Normative status:** MUST NOT/deprecated.
- **Severity:** critical.

### IETF-IKE-INTEG-001 — Obsolete integrity algorithms

- **Source:** RFC 8247 §2.3 and RFC 9395 §5.
- **Condition:** MD5/DES-MAC/KPDK-MD5 integrity transforms or algorithms explicitly deprecated by RFC 9395.
- **Severity:** critical.

### IETF-KE-001 — Prohibited KE groups

- **Source:** RFC 8247 §2.4; RFC 9395 §5.
- **Condition:** group 1 or 22 (and registry-deprecated equivalents used by the catalogue).
- **Normative status:** MUST NOT/deprecated.
- **Severity:** critical.

### IETF-KE-002 — Discouraged KE groups

- **Source:** RFC 8247 §2.4.
- **Condition:** group 2, 5, 23, or 24.
- **Normative status at source:** SHOULD NOT.
- **Severity:** high.
- **Caution:** keep source status distinct from later organizational/NIST policy.

### IETF-ESP-AUTH-001 — Unauthenticated non-AEAD ESP

- **Source:** RFC 8221 §4 and §6.
- **Condition:** non-AEAD ESP encryption with `AUTH_NONE`.
- **Normative status:** MUST NOT except when authenticated encryption provides integrity.
- **Severity:** critical.

### IETF-ESP-3DES-001 — ESP 3DES discouraged

- **Source:** RFC 8221 §5.
- **Condition:** `ENCR_3DES` for ESP.
- **Normative status:** SHOULD NOT.
- **Severity:** high.

## 6. NIST SP 800-77 Rev. 1 profile rules

### NIST-IKEV2-001 — Prefer IKEv2

- **Source:** NIST SP 800-77 Rev. 1 §7.2.6, p. 76–77 in document pagination (PDF p. 92–93).
- **Condition:** IKEv1.
- **Guidance:** use IKEv2 instead of IKEv1 where possible; avoid IKEv1 aggressive mode.
- **Severity:** high.

### NIST-ALG-001 — Approved cryptography profile

- **Source:** NIST SP 800-77 Rev. 1 Executive Summary and §4.1.4.
- **Condition:** algorithm outside the configured NIST-approved allow-list.
- **Implementation:** allow-list is versioned; do not hard-code “current” status without a policy update.
- **Default 0.1 profile:** AES-GCM/AES-CTR/AES-CBC/AES-CCM with approved key sizes and SHA-2/GMAC integrity as applicable. 3DES, HMAC-MD5, and HMAC-SHA-1 fail this profile.

### NIST-KE-001 — Approved group profile

- **Source:** NIST SP 800-77 Rev. 1 §7.2.6.
- **Allowed groups in the cited guidance:** 14–21.
- **Condition:** selected group outside the profile allow-list.
- **Caution:** cryptographic-transition guidance may change; rule has a review date.

### NIST-PFS-001 — PFS recommendation

- **Source:** NIST SP 800-77 Rev. 1 §2.1 and §7.2.6.
- **Condition:** CHILD-SA PFS explicitly disabled.
- **Guidance:** use PFS when resources allow; PFS DH strength should be at least that of initial IKE DH in the profile.
- **Severity:** medium/high by organization.
- **Passive behavior:** normally possible/unevaluable, not certain.

### NIST-LIFE-001 — Bounded SA lifetime

- **Source:** NIST SP 800-77 Rev. 1 summary table and §7.2.6; the guide lists 8 hours and recommends limits by both time and traffic in most cases.
- **Condition:** endpoint-authorized lifetime missing or exceeds profile threshold.
- **Severity:** medium.
- **Passive behavior:** unevaluable; rekey timing alone does not reveal configured lifetime.

### NIST-AH-001 — Avoid AH

- **Source:** NIST SP 800-77 Rev. 1 §4.2.
- **Condition:** AH deployment.
- **Guidance:** NIST discourages AH and recommends ESP with appropriate authenticated protection when confidentiality is not needed.
- **Severity:** medium/high by environment.

## 7. Cooperative evidence rules

### COOP-VICI-001 — VICI SA state

- **Source:** strongSwan `swanctl --list-sas` documentation.
- **Fields:** IKE version/SPIs, identities, selected IKE transforms, CHILD-SA mode/protocol/SPIs/transforms, selectors, counters, rekey/lifetime timers.
- **Status:** `OBSERVED` with source `VICI`, not `OBSERVED_FROM_PCAP`.

### COOP-XFRM-001 — Linux XFRM state

- **Source:** authorized `ip -s xfrm state/policy`; NIST SP 800-77 Rev. 1 §5 examples.
- **Fields:** mode, protocol, SPI, algorithm/key metadata, replay window/context, counters, lifetime state, selectors/policy.
- **Handling:** redact keys before storage/publication; record command/tool/kernel version.

## 8. Crypto-agility rules

### AGILE-MKE-001 — Multiple key exchanges

- **Source:** RFC 9370 §§1–3.
- **Meaning:** IKEv2 may perform multiple successive key exchanges using IKE_INTERMEDIATE/IKE_FOLLOWUP_KE.
- **Passive behavior:** exchange type/timing may be observed, while protected KE contents remain unavailable after initial exchange. Do not infer the actual KEM solely from packet length.

### AGILE-SSWAN-001 — strongSwan support

- **Source:** strongSwan proposal documentation for 6.x.
- **Meaning:** additional exchanges are configured with `keX_`; strongSwan documents hybrid examples such as an initial classical method plus ML-KEM.
- **Policy:** experimental/future-ready module. Presence is not a generic security pass and absence is not a failure unless the selected organization profile requires it.

## 9. Rule lifecycle

Each machine-readable rule contains:

```text
rule_id, profile, enabled, property, operator, expected/value,
severity, weight, source_id, source_section, normative_level,
rationale, remediation, observability_requirement,
introduced, last_reviewed, supersedes
```

Changes require:

1. authoritative-source review;
2. unit-test update;
3. rulebook version increment;
4. policy hash update;
5. migration note for prior reports.

## 10. Non-rules

The following are explicitly forbidden shortcuts:

- “UDP 4500 means IKEv2.”
- “SPI identifies the cipher.”
- “Sequence numbers prove anti-replay is enabled.”
- “No visible PFS means PFS is disabled.”
- “No visible lifetime means infinite lifetime.”
- “High classifier confidence makes a hidden field observed.”
- “RFC mandatory-to-implement equals mandatory-to-negotiate.”
- “One weighted score is an objective probability of compromise.”
