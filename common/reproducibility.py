"""Seed control and runtime fingerprinting."""

from __future__ import annotations

import os
import platform
import random
import sys
from typing import Any


def seed_everything(seed: int) -> dict[str, Any]:
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    versions: dict[str, Any] = {"seed": seed, "python": sys.version, "platform": platform.platform()}
    try:
        import numpy as np  # type: ignore

        np.random.seed(seed)
        versions["numpy"] = np.__version__
    except ImportError:
        versions["numpy"] = None
    try:
        import torch  # type: ignore

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        if hasattr(torch, "use_deterministic_algorithms"):
            torch.use_deterministic_algorithms(True)
        versions["torch"] = torch.__version__
    except ImportError:
        versions["torch"] = None
    return versions
