"""Bridge a probabilistic classifier into the typed CGII prior contract."""

from __future__ import annotations

from typing import Any, Sequence

from cgii.types import PriorDistribution


def candidate_prior_from_model(model: Any, feature_vector: Sequence[float], *, domain_id: str) -> PriorDistribution:
    distribution = model.predict_proba([list(feature_vector)])[0]
    return PriorDistribution(
        scores=distribution,
        model_id=str(model.model_id),
        model_hash=str(model.model_hash),
        domain_id=domain_id,
        is_learned=True,
    )
