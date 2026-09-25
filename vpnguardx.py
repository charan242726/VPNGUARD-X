"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from common.logging import configure_logging
from deployment.runtime import pipeline_for
from deployment.bundle import load_deployment
from observability import collect_local_gateway_telemetry
from parser import capture_live
from reports import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpnguardx", description="Evidence-bounded IPsec PCAP assessment")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="analyze an authorized classic-PCAP capture")
    analyze.add_argument("pcap", type=Path)
    analyze.add_argument("--profile", choices=["nist_800_77r1", "ietf_baseline"], default="nist_800_77r1")
    analyze.add_argument("--cooperative-json", type=Path, help="authorized canonical endpoint properties")
    analyze.add_argument("--capture-metadata", type=Path, help="trusted local live-capture manifest; no secret fields are accepted")
    analyze.add_argument("--cooperative-source", default="SCENARIO_GROUND_TRUTH", help="provenance label for authorized cooperative properties")
    analyze.add_argument("--output", type=Path, default=Path("artifacts/latest"))
    analyze.add_argument("--include-packets", action="store_true")
    analyze.add_argument("--deployment", type=Path, help="verified deployment bundle directory")
    analyze.add_argument("--allow-demo-deployment", action="store_true", help="allow a bundle labelled SYNTHETIC_SOFTWARE_DEMO")
    capture = subparsers.add_parser("capture", help="passively capture local IKE/ESP traffic; performs no probe")
    capture.add_argument("interface")
    capture.add_argument("--duration", type=int, required=True)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--i-am-authorized", action="store_true", help="required acknowledgement")
    telemetry = subparsers.add_parser("telemetry", help="collect normalized read-only local IPsec gateway facts")
    telemetry.add_argument("--output", type=Path, required=True)
    telemetry.add_argument("--i-am-authorized", action="store_true", help="required acknowledgement")
    health = subparsers.add_parser("health", help="validate Python runtime and a verified deployment bundle")
    health.add_argument("--deployment", type=Path, required=True)
    health.add_argument("--allow-demo-deployment", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        cooperative = None
        capture_metadata = None
        if args.cooperative_json:
            cooperative = json.loads(args.cooperative_json.read_text(encoding="utf-8"))
            if not isinstance(cooperative, dict):
                raise ValueError("cooperative JSON root must be an object")
        if args.capture_metadata:
            capture_metadata = json.loads(args.capture_metadata.read_text(encoding="utf-8"))
            if not isinstance(capture_metadata, dict):
                raise ValueError("capture metadata JSON root must be an object")
        bundle = pipeline_for(
            args.profile,
            path=args.deployment,
            allow_demo=args.allow_demo_deployment,
        ).analyze(
            args.pcap,
            cooperative_properties=cooperative,
            cooperative_source=args.cooperative_source,
            capture_metadata=capture_metadata,
            include_packets=args.include_packets,
        )
        if capture_metadata and bundle.capture["packet_count"] == 0:
            raise ValueError("live capture contains no IPsec packets; no assessment report was generated")
        paths = write_reports(bundle, args.output)
        print(json.dumps({"run_id": bundle.run["run_id"], "reports": paths}, indent=2))
        return 0
    if args.command == "capture":
        manifest = capture_live(
            args.interface,
            args.output,
            duration_seconds=args.duration,
            authorized=args.i_am_authorized,
        )
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    if args.command == "telemetry":
        properties = collect_local_gateway_telemetry(authorized=args.i_am_authorized)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(properties, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"output": str(args.output.resolve()), "property_count": len(properties)}, indent=2))
        return 0
    if args.command == "health":
        deployment = load_deployment(args.deployment, allow_demo=args.allow_demo_deployment)
        print(json.dumps({
            "status": "ok",
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "deployment": deployment.to_dict(),
        }, indent=2, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
