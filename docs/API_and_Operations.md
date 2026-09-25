# API and Operations

## Endpoints

`GET /health` returns service identity/version. `POST /v1/analyze` accepts multipart form fields:

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `capture` | file | yes | authorized classic PCAP (`.pcap`/`.cap`) |
| `profile_id` | string | no | `nist_800_77r1` or `ietf_baseline` |
| `cooperative_properties_json` | JSON string | no | authorized canonical properties; never secrets |

The response is the lossless assessment schema containing evidence, features metadata, application status, crypto-agility status, CGII trace, policy, risk, and remediation.

## Local development

```bash
python -m pip install -e '.[service]'
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Example request:

```bash
curl --fail http://127.0.0.1:8000/v1/analyze \
  -F capture=@authorized_capture.pcap \
  -F profile_id=nist_800_77r1
```

## Production controls not supplied by the prototype

Deploy behind authentication/authorization, TLS, request/rate limits, tenant-isolated object storage, antivirus/content controls, a job queue, audit logs, retention/deletion policy, and monitoring. Do not expose the development Uvicorn/Streamlit processes directly. Avoid returning server filesystem paths in a multi-tenant deployment.

The API deliberately does not perform live capture, scan endpoints, accept a target address, or initiate IKE.
