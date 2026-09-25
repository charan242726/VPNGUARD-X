# CGII — Constraint-Guided IPsec Inference

**Algorithm version:** 0.1.0  
**Implementation:** `cgii/`  
**Unreported empirical quantities:** **TBD — requires experiment**

## 1. Objective

CGII estimates a security-relevant IPsec configuration without violating observed packet evidence or protocol semantics. It is deliberately set-valued: when several configurations explain the capture, all adequately supported candidates remain available to downstream policy, risk, and remediation modules.

CGII is not a decryption method and does not claim to recover secrets or protected IKE payloads.

## 2. Notation

- `C`: finite, versioned candidate configuration space.
- `c in C`: one complete candidate configuration.
- `O`: hard evidence ledger entries eligible for deterministic constraint construction.
- `x`: passive statistical/sequence feature vector.
- `K`: set of protocol and cross-field constraint predicates.
- `C_O`: candidates consistent with `O` and `K`.
- `q_theta(c|x)`: learned or supplied candidate prior.
- `P(c|O,x)`: constrained posterior-like normalized score.
- `alpha`: target error level for a prediction set.
- `Gamma_alpha(O,x)`: returned candidate set.

The term “posterior” describes normalized model mass after deterministic projection; it is not a fully generative Bayesian posterior unless `q_theta` and the evidence model are constructed as such.

## 3. Candidate representation

The reference schema is:

```text
CandidateConfiguration
  candidate_id
  ike_version                 {IKEV1, IKEV2}
  outer_ip_version            {4, 6}
  encapsulation               {NATIVE_ESP, NAT_T}
  ike_encryption
  ike_integrity
  ike_prf
  ike_ke_group
  child_mode                  {TUNNEL, TRANSPORT}
  child_encryption
  child_integrity
  child_pfs_group             {NONE, group-id}
  esn                         {true, false}
  anti_replay                 {true, false}
  child_lifetime_seconds
  authentication_family       {PSK, CERTIFICATE, EAP, OTHER}
```

Production configuration catalogues should be compiled from tested deployment templates. Blind Cartesian products are discouraged because they create combinations unsupported by a stack or organization.

## 4. Evidence eligibility

Only these entries may generate hard equality/exclusion constraints:

- `OBSERVED` packet or authorized telemetry values whose parser/source validation succeeded;
- `DETERMINISTICALLY_DERIVED` values with a registered derivation rule and complete premises.

`AI_INFERRED` values affect `q_theta` or auxiliary soft scores but do not eliminate candidates. `UNKNOWN/UNOBSERVABLE` values impose no constraint.

Cooperative telemetry may constrain evaluation-time candidates only when the requested mode is cooperative. It is withheld from passive feature extraction and passive-only benchmark inference.

## 5. Protocol constraints

A predicate `k(c,O)` returns true when candidate `c` is compatible with evidence `O`. The initial constraint registry includes:

1. IKE header major version equals candidate IKE version.
2. Outer IP version equals candidate outer IP version for the reconstructed session.
3. Native ESP versus RFC 3948 ESP-in-UDP framing equals candidate encapsulation.
4. A selected IKE transform observed in responder IKE_SA_INIT equals the corresponding candidate transform.
5. The visible IKE_SA_INIT KE group equals candidate initial IKE KE group.
6. An AEAD transform must not be paired with a separate integrity transform in the same proposal/configuration.
7. A non-AEAD encrypted transform with `NONE` integrity is invalid under profiles that require authenticated encryption/integrity.
8. Cooperative CHILD-SA mode, algorithms, PFS group, ESN, lifetime, and authentication family must match when explicitly supplied.
9. Endpoint/packet-source conflicts do not silently select one source; they produce an evidence conflict.

Constraints are individually logged with ID, premises, affected candidate IDs, and rationale.

## 6. Feasible candidate set

```math
C_O = {c in C : all k in K satisfy k(c,O)=1}.
```

If `C_O` is empty, CGII returns:

```text
status = EVIDENCE_CONFLICT
posterior = {}
prediction_set = []
```

It also reports a minimal conflicting evidence subset when available. It must not fall back to the unconstrained model output.

## 7. Candidate prior

The prior interface accepts non-negative scores for candidate IDs. A model may produce these directly or factorize over fields:

```math
q_theta(c|x) proportional to exp(sum_j log p_theta(c_j|x) + phi_theta(c,x)),
```

where `phi_theta` is an optional interaction score. Missing candidate scores receive zero unless a declared smoothing policy is enabled. The supplied prior is normalized over `C` before projection and is identified by model/hash/domain metadata.

For deterministic demonstrations without a trained model, a uniform prior is allowed and labeled `UNIFORM_BASELINE`, not AI inference.

## 8. Constrained posterior

```math
P(c|O,x) =
  q_theta(c|x) 1[c in C_O]
  / sum_{c' in C_O} q_theta(c'|x).
```

If every surviving candidate has zero prior mass, the reference implementation uses a uniform distribution over `C_O` and emits `ZERO_MASS_FALLBACK`. This avoids division by zero while preventing eliminated candidates from reappearing.

Required invariants:

- `P(c|O,x)=0` for every eliminated candidate.
- Sum over surviving candidates equals one within numerical tolerance.
- Adding hard evidence cannot add a candidate to `C_O`.
- Replacing evidence with UNKNOWN cannot shrink `C_O`.

## 9. Prediction sets

### 9.1 Heuristic cumulative-mass set

Without calibration data, sort candidates by decreasing constrained probability and include candidates until cumulative mass reaches `1-alpha`. The result is labeled `HEURISTIC_MASS_SET`; no coverage guarantee is claimed.

### 9.2 Split-conformal threshold set

For a held-out calibration sample `(O_i,x_i,y_i)`, define a simple nonconformity score:

```math
s_i = 1 - P_i(y_i|O_i,x_i).
```

For `n` calibration examples, use the finite-sample quantile:

```math
q_hat = Quantile_{ceil((n+1)(1-alpha))/n}({s_i}).
```

For a new example:

```math
Gamma_alpha(O,x) = {c in C_O : 1-P(c|O,x) <= q_hat}.
```

If the set is empty because of numerical/distribution shift effects, the highest-probability feasible candidate is included and a diagnostic flag is raised. Coverage is evaluated empirically; the usual marginal guarantee depends on exchangeability and a fixed calibration procedure.

An Adaptive Prediction Set implementation may replace the simple score after validation. The algorithm ID and calibration hash are stored with every set.

## 10. Evidence completeness

For requested property set `J`:

```math
E(O) = sum_j w_j s(status_j, confidence_j) / sum_j w_j.
```

Default status contributions are:

| Status | Contribution |
|---|---:|
| `OBSERVED` | 1.00 |
| `DETERMINISTICALLY_DERIVED` | 0.95 |
| `AI_INFERRED` | `0.50 * calibrated_confidence` |
| `UNKNOWN/UNOBSERVABLE` | 0.00 |

These coefficients are user-interface/reliability weights, not probabilities. Sensitivity analysis is required.

## 11. Conflict and uncertainty outputs

CGII returns:

- total and feasible candidate counts;
- activated constraints;
- elimination reason per candidate;
- constrained distribution;
- prediction set and method;
- entropy and maximum probability as diagnostics;
- posterior mass of the returned set;
- evidence completeness;
- unresolved fields across the set;
- OOD/abstention flags;
- model/calibration/catalogue/policy identifiers.

Low entropy does not override an OOD or insufficient-evidence gate.

## 12. Policy propagation

For rule `r`, define violation indicator `I_r(c)` for a complete candidate. For prediction set `G`:

```text
certain violation:  I_r(c)=1 for every c in G
possible violation: I_r(c)=1 for some but not every c in G
not supported:      I_r(c)=0 for every c in G
not evaluable:      G is empty or required catalogue field is unresolved/absent
```

The user-facing report must never shorten `possible violation` to `detected vulnerability`.

## 13. Risk interval

For severity weights `w_r` and optional graded loss `I_r(c) in [0,1]`:

```math
R(c) = sum_r w_r I_r(c) / sum_r w_r,
R_min = min_{c in G} R(c),
R_max = max_{c in G} R(c).
```

Optional probability-weighted expected risk may be reported as a secondary model-dependent statistic, never as the sole risk result.

## 14. Counterfactual remediation

Let `A_pi` be the candidates compliant with policy profile `pi`. A weighted edit distance is:

```math
d(c,c') = sum_j lambda_j 1[c_j != c'_j].
```

CGII finds `argmin_{c' in A_pi} d(c,c')` by exhaustive search over the tested catalogue. Ties are retained. For candidate set `G`, the solver derives:

- changes common to all minimum solutions for all `c in G`;
- candidate-contingent changes;
- `[minimum_cost, maximum_cost]`;
- remaining unevaluable rules.

## 15. Pseudocode

```text
CGII(C, evidence, prior, alpha, calibrator=None):
    O_hard <- validated OBSERVED + eligible DETERMINISTICALLY_DERIVED evidence
    constraints <- compile_constraints(O_hard)
    C_O <- []
    eliminated <- {}

    for c in C:
        failures <- [k.id for k in constraints if not k(c)]
        if failures is empty:
            append c to C_O
        else:
            eliminated[c.id] <- failures

    if C_O is empty:
        return EVIDENCE_CONFLICT(evidence, eliminated)

    p <- normalize(prior restricted to C_O)
    if sum(prior over C_O) == 0:
        p <- uniform(C_O)
        flag ZERO_MASS_FALLBACK

    if calibrator is fitted:
        G <- conformal_set(p, calibrator, alpha)
        method <- SPLIT_CONFORMAL
    else:
        G <- cumulative_mass_set(p, 1-alpha)
        method <- HEURISTIC_MASS_SET

    if OOD or evidence gate fails:
        retain p for diagnostics
        widen/abstain according to registered gate

    return distribution, G, constraints, eliminations,
           completeness, unresolved_fields, diagnostics
```

## 16. Complexity

For `|C|` candidates and `|K|` constraints, exact projection is `O(|C||K|)`. Policy evaluation is `O(|G||R|)` and brute-force remediation is `O(|G||C||F|)`. This is suitable for a tested catalogue containing hundreds or low thousands of configurations. Larger spaces require factor graphs, SAT/SMT, or integer programming; any approximation must preserve the no-unsupported-claim invariant.

## 17. Validation tests

1. Normalization and eliminated-mass tests.
2. Monotonic feasible-set tests under added/removed evidence.
3. AI evidence does not hard-eliminate candidates.
4. AEAD/integrity cross-field consistency.
5. Passive hidden fields remain unresolved.
6. Cooperative values correctly narrow the set.
7. Empty feasible set returns conflict.
8. Conformal quantile boundary tests.
9. Risk interval contains all candidate risks.
10. Remediation cost is minimal by exhaustive comparison.

## 18. Limitations

- Candidate-space omission can create false confidence; catalogue coverage must be audited.
- Probability calibration can fail under configuration, stack, capture-point, or application shift.
- Set coverage is marginal under stated assumptions, not a per-sample guarantee.
- Constraints encode the implemented semantic subset and require versioning/peer review.
- Passive traffic analysis may expose behavioral metadata but cannot validate protected cryptographic choices.
- The reference implementation is a research prototype; production deployment requires hardened parsing, resource limits, fuzzing, and independent security review.
