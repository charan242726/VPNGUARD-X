"""Evidence-first Streamlit dashboard."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

try:
    import pandas as pd
    import streamlit as st
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the locked 'dashboard' dependencies to run Streamlit") from exc

from pipeline import VPNGuardXPipeline
from deployment.bundle import load_deployment
import pathlib


st.set_page_config(page_title="VPNGUARD-X", page_icon="🛡️", layout="wide")
st.title("VPNGUARD-X")
st.caption("Evidence-bounded and constraint-guided IPsec security assurance")

with st.sidebar:
    profile = st.selectbox("Policy profile", ["nist_800_77r1", "ietf_baseline"])
    st.info("Analyze only captures and endpoint telemetry you are authorized to use.")

uploaded = st.file_uploader("Classic PCAP", type=["pcap", "cap"])
telemetry = st.text_area("Optional authorized cooperative properties (JSON object)", value="")

if uploaded and st.button("Analyze", type="primary"):
    cooperative = None
    if telemetry.strip():
        try:
            cooperative = json.loads(telemetry)
            if not isinstance(cooperative, dict):
                raise ValueError("JSON root must be an object")
        except (json.JSONDecodeError, ValueError) as exc:
            st.error(f"Invalid telemetry: {exc}")
            st.stop()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix="vpnguardx-ui-", suffix=".pcap", delete=False) as handle:
            handle.write(uploaded.getvalue())
            temporary = Path(handle.name)
        result = VPNGuardXPipeline(profile_id=profile).analyze(temporary, cooperative_properties=cooperative).to_dict()
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    risk = result["risk"]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Mode", result["mode"])
    col2.metric("Evidence completeness", f"{result['cgii']['evidence_completeness']:.1%}")
    col3.metric("Candidate set", len(result["cgii"]["prediction_set"]))
    col4.metric("Risk interval", f"{risk['minimum']} – {risk['maximum']}")
    st.subheader("Evidence ledger")
    st.dataframe(pd.DataFrame(result["capture"]["evidence"]), use_container_width=True, hide_index=True)
    st.subheader("Policy findings")
    st.dataframe(pd.DataFrame(result["policy"]["findings"]), use_container_width=True, hide_index=True)
    st.subheader("Candidate distribution")
    st.bar_chart(pd.Series(result["cgii"]["posterior"]).sort_values(ascending=False))
    with st.expander("Counterfactual remediation"):
        st.json(result["remediation"])
    st.download_button("Download assessment JSON", json.dumps(result, indent=2), "assessment.json", "application/json")
