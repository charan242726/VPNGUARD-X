"""FastAPI service for bounded PCAP assessment."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Annotated

try:
    from fastapi import FastAPI, File, Form, HTTPException, UploadFile
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the locked 'service' dependencies to run the API") from exc

from deployment.runtime import pipeline_for


MAX_UPLOAD_BYTES = int(os.environ.get("VPNGUARDX_MAX_UPLOAD_BYTES", str(64 * 1024 * 1024)))
app = FastAPI(
    title="VPNGUARD-X",
    version="0.1.0",
    description="Evidence-bounded and constraint-guided IPsec security assurance",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "VPNGUARD-X", "version": "0.1.0"}


@app.post("/v1/analyze")
async def analyze(
    capture: Annotated[UploadFile, File(description="Authorized classic-PCAP capture")],
    profile_id: Annotated[str, Form()] = "nist_800_77r1",
    cooperative_properties_json: Annotated[str | None, Form()] = None,
    cooperative_source: Annotated[str, Form()] = "GATEWAY_TELEMETRY",
) -> dict:
    filename = Path(capture.filename or "capture.pcap").name
    if Path(filename).suffix.lower() not in {".pcap", ".cap"}:
        raise HTTPException(415, "This reference API accepts classic PCAP only")
    body = await capture.read(MAX_UPLOAD_BYTES + 1)
    if len(body) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "capture exceeds configured upload limit")
    cooperative = None
    if cooperative_properties_json:
        try:
            cooperative = json.loads(cooperative_properties_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, "invalid cooperative_properties_json") from exc
        if not isinstance(cooperative, dict):
            raise HTTPException(400, "cooperative properties must be a JSON object")
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="vpnguardx-", suffix=".pcap", delete=False) as handle:
            handle.write(body)
            temporary_path = Path(handle.name)
        pipeline = pipeline_for(profile_id)
        result = pipeline.analyze(temporary_path, cooperative_properties=cooperative, cooperative_source=cooperative_source).to_dict()
        result["capture"]["path"] = filename
        return result
    except (ValueError, OSError, RuntimeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
