"""Shared immutable deployment selection for CLI/API/dashboard."""
import os
from functools import lru_cache
from pathlib import Path
from deployment.bundle import load_deployment

@lru_cache(maxsize=4)
def _load(path, allow_demo):
    return load_deployment(path, allow_demo=allow_demo)

def selected_deployment(path=None, *, allow_demo=False):
    selected = path or os.environ.get("VPNGUARDX_DEPLOYMENT")
    return _load(str(Path(selected).resolve()), allow_demo or os.environ.get("VPNGUARDX_ALLOW_DEMO") == "1") if selected else None

def pipeline_for(profile_id="nist_800_77r1", *, path=None, allow_demo=False):
    from pipeline import VPNGuardXPipeline
    return VPNGuardXPipeline(profile_id=profile_id, deployment=selected_deployment(path, allow_demo=allow_demo))
