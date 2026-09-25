# VPNGUARD-X Technical Assessment

**Run ID:** `vgx-890922898ff82e7a`  
**Mode:** `PASSIVE_BLACK_BOX`  
**Capture SHA-256:** `c2e9259e23dbc1109d340763214252063ae32576ce9c19e2232d0e2d8521baed`  
**Empirical benchmark metrics:** TBD — requires experiment

## Assurance summary

- CGII status: `OK`
- Inference status: `DETERMINISTICALLY_DERIVED`
- Feasible candidates: 3 of 28
- Returned set: 3; method `EVIDENCE_FEASIBLE_SET`; mass 1.0000
- Evidence completeness: 0.4633
- Policy/candidate basis status: `DETERMINISTICALLY_DERIVED`
- Risk interval: [0.0000, 0.0431] with basis `DETERMINISTICALLY_DERIVED` (policy loss, not compromise probability)

## Evidence ledger

| Property | Value | Status | Source | Rationale |
|---|---|---|---|---|
| `outer.ip_version` | 4 | `OBSERVED` | `PACKET_IP_HEADER` | IP version nibble was parsed from captured outer headers |
| `outer.source_address` | `["192.0.2.10", "192.0.2.20"]` | `OBSERVED` | `PACKET_IP_HEADER` | Outer source addresses are present in captured IP headers |
| `outer.destination_address` | `["192.0.2.10", "192.0.2.20"]` | `OBSERVED` | `PACKET_IP_HEADER` | Outer destination addresses are present in captured IP headers |
| `ike.version` | IKEV2 | `OBSERVED` | `IKE_HEADER` | The IKE major version is encoded in the fixed IKE header |
| `ike.exchange_type` | `[34]` | `OBSERVED` | `IKE_HEADER` | Exchange Type is a fixed-header field; protected payload contents are not implied |
| `ike.initiator_spi` | `["0x1122334455667788"]` | `OBSERVED` | `IKE_HEADER` | Initiator SPI is present in the IKE fixed header |
| `ike.responder_spi` | `["0x8877665544332211"]` | `OBSERVED` | `IKE_HEADER` | Non-zero responder SPI is present in the IKE fixed header |
| `ike.selected_encryption` | ENCR_AES_CBC_256 | `OBSERVED` | `IKE_SA_INIT_RESPONDER_SA_PAYLOAD` | Responder IKE_SA_INIT selection was parsed from the unencrypted SAr1 payload |
| `ike.selected_prf` | PRF_HMAC_SHA2_256 | `OBSERVED` | `IKE_SA_INIT_RESPONDER_SA_PAYLOAD` | Responder IKE_SA_INIT selection was parsed from the unencrypted SAr1 payload |
| `ike.selected_integrity` | AUTH_HMAC_SHA2_256_128 | `OBSERVED` | `IKE_SA_INIT_RESPONDER_SA_PAYLOAD` | Responder IKE_SA_INIT selection was parsed from the unencrypted SAr1 payload |
| `ike.selected_ke_group_transform` | MODP_2048 | `OBSERVED` | `IKE_SA_INIT_RESPONDER_SA_PAYLOAD` | Responder IKE_SA_INIT selection was parsed from the unencrypted SAr1 payload |
| `ike.initial_ke_group` | 14 | `OBSERVED` | `IKE_SA_INIT_KE_PAYLOAD` | Key Exchange method/group is encoded in the visible IKE_SA_INIT KE payload |
| `encapsulation` | NATIVE_ESP | `DETERMINISTICALLY_DERIVED` | `IP_PROTOCOL_50` | ESP records were carried directly as IP protocol 50 |
| `esp.spi` | `["0xaabbccdd"]` | `OBSERVED` | `ESP_HEADER` | SPI is the first 32-bit ESP header field |
| `esp.sequence_low32` | `{"0xaabbccdd": [1, 3]}` | `OBSERVED` | `ESP_HEADER` | The low-order 32-bit sequence field is visible in each ESP header |
| `esp.sequence_gap_count` | 1 | `DETERMINISTICALLY_DERIVED` | `ESP_SEQUENCE_ANALYSIS` | Positive sequence gaps were counted per direction and SPI; this is a capture-loss proxy, not proof of network loss |
| `capture.packet_truncation_rate` | 0.0000 | `DETERMINISTICALLY_DERIVED` | `PCAP_RECORD_METADATA` | Computed from captured length versus original length |
| `capture.packet_count` | 4 | `DETERMINISTICALLY_DERIVED` | `PCAP_RECORDS` | Counted successfully read packet records |
| `session.ike_session_count` | 1 | `DETERMINISTICALLY_DERIVED` | `IKE_SESSIONIZER` | Grouped IKE headers by initiator SPI and endpoint pair |
| `session.ike_sa_init_complete` | True | `DETERMINISTICALLY_DERIVED` | `IKE_STATE_MACHINE` | Matched IKE_SA_INIT request and response with Message ID zero |
| `ike.peer_identity` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Peer identity is carried in protected IKE_AUTH content |
| `ike.authentication_family` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Authentication payload/method is protected after IKE_SA_INIT |
| `child.encryption` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | CHILD-SA transforms are inside protected IKE_AUTH/CREATE_CHILD_SA payloads |
| `child.integrity` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | CHILD-SA transforms are inside protected IKE_AUTH/CREATE_CHILD_SA payloads |
| `child.mode` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | USE_TRANSPORT_MODE is inside protected CHILD-SA negotiation |
| `child.traffic_selectors` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Traffic selectors are inside protected CHILD-SA negotiation |
| `child.pfs_group` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Optional fresh KE for CHILD-SA is inside protected CREATE_CHILD_SA |
| `sa.configured_lifetime` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | IKEv2 lifetimes are locally enforced rather than negotiated |
| `child.esn` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Only low 32 sequence bits are transmitted under ESN |
| `child.anti_replay_enabled` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Anti-replay enablement is receiver-local per SA |
| `child.replay_window_size` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Replay-window state is maintained by the receiver |
| `inner.ip_version` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | The ESP inner payload is protected |
| `inner.application_class` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | No application model was supplied to passive evidence construction |
| `session.child_sa_to_spi_mapping` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `IPSEC_OBSERVABILITY_MATRIX` | Passive SPI does not expose the endpoint SAD mapping |
| `ike.additional_ke_algorithms` | UNKNOWN/UNOBSERVABLE | `UNKNOWN/UNOBSERVABLE` | `RFC9370_OBSERVABILITY` | Additional KE payload contents are protected; packet size or exchange presence does not identify ML-KEM or another method |

## CGII candidate set

| Candidate | Constrained probability |
|---|---:|
| `MODERN_V4_NATIVE_TRANSPORT_CBC14` | 0.333333 |
| `MODERN_V4_NATIVE_TUNNEL_CBC14` | 0.333333 |
| `MODERN_V4_NATIVE_TUNNEL_CBC14_NOPFS` | 0.333333 |

## Policy findings

| Rule | Status | Severity | Source |
|---|---|---|---|
| `IETF-IKEV1-001` | `NOT_SUPPORTED` | HIGH | RFC9395 Abstract and Section 3 |
| `IETF-IKE-ENC-001` | `NOT_SUPPORTED` | CRITICAL | RFC8247 Section 2.1 |
| `IETF-IKE-PRF-001` | `NOT_SUPPORTED` | CRITICAL | RFC8247 Section 2.2, as updated by RFC 9395 |
| `IETF-IKE-INTEG-001` | `NOT_SUPPORTED` | CRITICAL | RFC8247 Section 2.3, as updated by RFC 9395 Section 5 |
| `IETF-KE-001` | `NOT_SUPPORTED` | CRITICAL | RFC8247 Section 2.4, as updated by RFC 9395 Section 5 |
| `IETF-KE-002` | `NOT_SUPPORTED` | HIGH | RFC8247 Section 2.4 |
| `IETF-ESP-3DES-001` | `NOT_SUPPORTED` | HIGH | RFC8221 Section 5 |
| `NIST-ALG-CHILD-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Executive Summary and Section 4.1.4 |
| `NIST-ALG-IKE-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Executive Summary and Section 4.1.4 |
| `NIST-PRF-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Section 4.1.4 and Section 7.2.6 |
| `NIST-INTEG-IKE-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Section 4.1.4 |
| `NIST-INTEG-CHILD-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Section 4.1.4 |
| `NIST-KE-001` | `NOT_SUPPORTED` | HIGH | NIST80077R1 Section 7.2.6 |
| `NIST-PFS-001` | `POSSIBLE_VIOLATION` | MEDIUM | NIST80077R1 Sections 2.1 and 7.2.6 |
| `NIST-LIFE-001` | `NOT_SUPPORTED` | MEDIUM | NIST80077R1 Summary table and Section 7.2.6 |

## Counterfactual remediation

Status: `OK` with basis `DETERMINISTICALLY_DERIVED`. Cost interval: [0, 2.0000].

Robust common changes are those shared by every minimum-cost alternative:

- None established across all supported candidates; use the candidate-contingent JSON details.

## Limitations

Protected IKEv2/ESP contents were not decrypted. Hidden configuration fields remain inferred or unknown unless authorized cooperative telemetry supplied them. Possible violations are not detected vulnerabilities. Results are bounded by the versioned candidate catalogue and policy profile.
