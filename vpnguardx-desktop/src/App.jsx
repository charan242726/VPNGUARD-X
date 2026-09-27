import React, { useEffect, useMemo, useState } from "react";
import "./assurance.css";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Cpu,
  Download,
  FileText,
  Gauge,
  Layers3,
  Network,
  Play,
  Radar,
  ScanLine,
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  Upload,
  Wifi,
  XCircle,
} from "lucide-react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const states = {
  OBSERVED: ["Observed", "green"],
  DETERMINISTICALLY_DERIVED: ["Derived", "blue"],
  AI_INFERRED: ["AI inferred", "amber"],
  "UNKNOWN/UNOBSERVABLE": ["Unknown", "slate"],
};
const evidenceHelp = {
  OBSERVED:
    "Directly parsed from packet structure/capture metadata or authorized endpoint telemetry.",
  DETERMINISTICALLY_DERIVED:
    "Calculated uniquely from observed evidence and a registered rule.",
  AI_INFERRED:
    "Model estimate, not a packet-observed fact. Review its confidence and scope.",
  "UNKNOWN/UNOBSERVABLE":
    "Not visible in this capture, protected by encryption, endpoint-local, unsupported, or unavailable.",
};
const fieldLabels = {
  "ike.version": "IKE version",
  "ike.selected_encryption": "IKE encryption",
  "ike.selected_integrity": "IKE integrity",
  "ike.selected_prf": "IKE PRF",
  "ike.initial_ke_group": "IKE DH group",
  "ike.authentication_family": "Authentication family",
  "child.mode": "IPsec operating mode",
  "child.encryption": "ESP encryption",
  "child.integrity": "ESP integrity",
  "child.pfs_group": "Perfect forward secrecy",
  "child.esn": "Extended sequence numbers",
  "child.anti_replay_enabled": "Anti-replay protection",
  "child.replay_window_size": "Replay window",
  "sa.remaining_lifetime_seconds": "SA remaining lifetime",
  "sa.configured_lifetime": "SA configured lifetime",
  "child.traffic_selectors": "Traffic selectors",
  "child.protocol": "CHILD-SA protocol",
};
const n = (v, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d);
const pct = (v) => `${Math.round(n(v) * 100)}%`;
const pill = (s) => states[s] || states["UNKNOWN/UNOBSERVABLE"];
const tone = (s) =>
  s === "CERTAIN_VIOLATION"
    ? "red"
    : s === "POSSIBLE_VIOLATION"
      ? "amber"
      : "green";
function Pill({ tone = "slate", children }) {
  return <span className={`pill pill-${tone}`}>{children}</span>;
}
function EvidenceBadge({ status }) {
  const [label, t] = pill(status);
  return (
    <span
      className={`pill pill-${t}`}
      title={evidenceHelp[status] || evidenceHelp["UNKNOWN/UNOBSERVABLE"]}
    >
      {label}
    </span>
  );
}
function Empty({ title, detail, actionLabel, onAction }) {
  return (
    <div className="empty">
      <CircleDot size={20} />
      <strong>{title}</strong>
      <span>{detail}</span>
      {actionLabel && (
        <button className="button secondary empty-action" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}
function Metric({ icon: Icon, label, value, note, tone = "blue" }) {
  return (
    <motion.article
      className={`metric metric-${tone}`}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="metric-icon">
        <Icon size={18} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{note}</small>
      </div>
    </motion.article>
  );
}
function RiskGauge({ risk }) {
  if (
    !risk ||
    !Number.isFinite(Number(risk.minimum)) ||
    !Number.isFinite(Number(risk.maximum))
  )
    return (
      <div className="risk-gauge risk-gauge-pending">
        <div className="pending-orbit">
          <ShieldAlert size={26} />
        </div>
        <div>
          <b>Assessment pending</b>
          <span>
            Analyze an authorized IPsec PCAP or live capture to calculate the
            policy-risk interval.
          </span>
        </div>
      </div>
    );
  const min = Math.max(0, Math.min(1, n(risk.minimum))),
    max = Math.max(min, Math.min(1, n(risk.maximum)));
  const data = [
    { value: min, fill: "#3ddc97" },
    { value: Math.max(max - min, 0.012), fill: "#ffb84d" },
    { value: Math.max(1 - max, 0), fill: "#2b3851" },
  ];
  return (
    <div className="risk-gauge">
      <ResponsiveContainer width="100%" height={180}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius={62}
            outerRadius={85}
            paddingAngle={2}
            stroke="none"
          >
            {data.map((x, i) => (
              <Cell key={i} fill={x.fill} />
            ))}
          </Pie>
          <Tooltip formatter={pct} />
        </PieChart>
      </ResponsiveContainer>
      <div className="gauge-value">
        <b>{pct((min + max) / 2)}</b>
        <span>policy risk</span>
      </div>
      <div className="gauge-range">
        Bounded range {pct(min)} — {pct(max)}
      </div>
    </div>
  );
}
function FlowMap({ report }) {
  const s = report?.capture?.ike_sessions || [],
    f = report?.capture?.esp_flows || [];
  const nodes = [
    ...new Set(
      [
        ...s.flatMap((x) => [x.initiator_ip, x.responder_ip]),
        ...f.flatMap((x) => [x.src_ip, x.dst_ip]),
      ].filter(Boolean),
    ),
  ];
  if (!nodes.length)
    return (
      <Empty
        title="Awaiting endpoint telemetry"
        detail="Analyze a PCAP or authorized live capture to build the session map."
      />
    );
  return (
    <div className="flow-map">
      <div className="flow-node">
        <span className="node-orbit" />
        <Network size={24} />
        <b>{nodes[0]}</b>
        <small>Initiator / peer A</small>
      </div>
      <div className="flow-lane">
        <div className="protocol-lane ike-lane">
          <span>IKE negotiation</span>
          <i />
          <i />
          <i />
        </div>
        <div className="protocol-lane esp-lane">
          <span>ESP protected traffic</span>
          <i />
          <i />
          <i />
        </div>
      </div>
      <div className="flow-node">
        <span className="node-orbit" />
        <ShieldCheck size={24} />
        <b>{nodes[1] || "Protected endpoint"}</b>
        <small>Responder / peer B</small>
      </div>
      <div className="flow-caption">
        <Pill tone="blue">{s.length} IKE SAs</Pill>
        <Pill tone="green">{f.length} ESP flows</Pill>
        <span>Protected payload fields remain evidence-bounded.</span>
      </div>
    </div>
  );
}
const fieldState = (evidence, property) => {
  const item = evidence.find((x) => x.property_name === property);
  return item
    ? { value: item.value, status: item.status, source: item.source }
    : {
        value: null,
        status: "UNKNOWN/UNOBSERVABLE",
        source: "Requires gateway telemetry or observable PCAP evidence",
      };
};
const controlTone = (value) =>
  value?.status === "OBSERVED"
    ? "green"
    : value?.status === "DETERMINISTICALLY_DERIVED"
      ? "blue"
      : value?.status === "AI_INFERRED"
        ? "amber"
        : "slate";
function SessionTimeline({ report, evidence }) {
  const ike = fieldState(evidence, "ike.version"),
    mode = fieldState(evidence, "child.mode");
  const esp = (report?.capture?.esp_flows || []).length;
  const steps = [
    ["IKE discovery", ike.value || "Awaiting IKE evidence", !!ike.value],
    [
      "SA negotiation",
      mode.value
        ? `${mode.value} mode established`
        : "Protected negotiation details may require telemetry",
      !!mode.value,
    ],
    [
      "CHILD-SA / ESP",
      esp
        ? `${esp} ESP flow${esp === 1 ? "" : "s"} observed`
        : "Awaiting ESP traffic",
      !!esp,
    ],
    [
      "Endpoint assurance",
      evidence.some(
        (x) =>
          x.source === "GATEWAY_TELEMETRY" ||
          x.source === "STRONGSWAN_VICI" ||
          x.source === "LINUX_XFRM",
      )
        ? "Gateway state correlated"
        : "Connect gateway telemetry for replay, PFS and SA state",
      evidence.some(
        (x) =>
          x.source === "GATEWAY_TELEMETRY" ||
          x.source === "STRONGSWAN_VICI" ||
          x.source === "LINUX_XFRM",
      ),
    ],
  ];
  return (
    <div className="session-timeline">
      {steps.map(([title, detail, ready], index) => (
        <React.Fragment key={title}>
          <article className={ready ? "timeline-step ready" : "timeline-step"}>
            <span>
              {ready ? <CheckCircle2 size={15} /> : <CircleDot size={15} />}
            </span>
            <div>
              <b>{title}</b>
              <small>{detail}</small>
            </div>
          </article>
          {index < steps.length - 1 && (
            <i className={ready ? "timeline-link ready" : "timeline-link"} />
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

function ProtocolFacts({ report, evidence }) {
  const facts = [
    [
      "IPsec / ESP",
      (report?.capture?.esp_flows || []).length ? "ESP observed" : null,
      "OBSERVED",
    ],
    [
      "IKE version",
      fieldState(evidence, "ike.version").value,
      fieldState(evidence, "ike.version").status,
    ],
    [
      "IKE encryption",
      fieldState(evidence, "ike.selected_encryption").value,
      fieldState(evidence, "ike.selected_encryption").status,
    ],
    [
      "IKE integrity / PRF",
      fieldState(evidence, "ike.selected_integrity").value ||
        fieldState(evidence, "ike.selected_prf").value,
      fieldState(evidence, "ike.selected_integrity").value
        ? fieldState(evidence, "ike.selected_integrity").status
        : fieldState(evidence, "ike.selected_prf").status,
    ],
    [
      "DH key exchange",
      fieldState(evidence, "ike.initial_ke_group").value,
      fieldState(evidence, "ike.initial_ke_group").status,
    ],
    [
      "Tunnel / transport",
      fieldState(evidence, "child.mode").value,
      fieldState(evidence, "child.mode").status,
    ],
    [
      "ESP encryption",
      fieldState(evidence, "child.encryption").value,
      fieldState(evidence, "child.encryption").status,
    ],
    [
      "ESP integrity",
      fieldState(evidence, "child.integrity").value,
      fieldState(evidence, "child.integrity").status,
    ],
    [
      "PFS / DH group",
      fieldState(evidence, "child.pfs_group").value,
      fieldState(evidence, "child.pfs_group").status,
    ],
    [
      "Anti-replay",
      fieldState(evidence, "child.anti_replay_enabled").value,
      fieldState(evidence, "child.anti_replay_enabled").status,
    ],
    [
      "SA lifetime",
      fieldState(evidence, "sa.remaining_lifetime_seconds").value,
      fieldState(evidence, "sa.remaining_lifetime_seconds").status,
    ],
    [
      "Traffic class",
      report?.application?.label,
      report?.application?.label ? "AI_INFERRED" : "UNKNOWN/UNOBSERVABLE",
    ],
  ];
  return (
    <div className="protocol-facts">
      {facts.map(([label, value, status]) => {
        return (
          <article key={label}>
            <span>{label}</span>
            <b>
              {value === true
                ? "Enabled"
                : value === false
                  ? "Disabled"
                  : value == null
                    ? "Unknown / unavailable"
                    : Array.isArray(value)
                      ? value.join(", ")
                      : String(value)}
            </b>
            <EvidenceBadge status={status} />
          </article>
        );
      })}
    </div>
  );
}

function SIHCoverage({ report, evidence, onReviewEvidence }) {
  const telemetryReady = evidence.some((x) =>
    ["GATEWAY_TELEMETRY", "STRONGSWAN_VICI", "LINUX_XFRM"].includes(x.source),
  );
  const rows = [
    [
      "Traffic acquisition",
      "Classic PCAP upload and authorized fixed-filter live capture",
      "ready",
    ],
    [
      "IPsec / IKE identification",
      "IKEv1/v2, ESP, NAT-T, outer IPv4/IPv6, session reconstruction",
      "ready",
    ],
    [
      "Crypto and key exchange",
      "IKE proposals are packet-observed; CHILD-SA facts need endpoint telemetry",
      "bounded",
    ],
    [
      "Mode, PFS, replay and lifetime",
      "Authoritative when gateway telemetry is correlated; otherwise explicit unknown/inference",
      "bounded",
    ],
    [
      "Encrypted traffic classification",
      "WEB, VIDEO, VOIP, BULK_FILE, ICMP_CONTROL, INTERACTIVE_MESSAGING, UNKNOWN",
      "bounded",
    ],
    [
      "Assessment and reports",
      "Risk interval, policy findings, threat matrix, evidence JSON, executive and technical PDF",
      "ready",
    ],
    [
      "AES-128 / email / messaging extensions",
      "Available as demonstration-only OOD traces; excluded from frozen accuracy claims",
      "demo",
    ],
  ];
  return (
    <div className="coverage-layout">
      <section className="card coverage-hero">
        <div className="eyebrow">
          <CheckCircle2 size={14} /> SIH 26160 readiness
        </div>
        <h1>
          One interface.
          <br />
          <em>Every claim traceable.</em>
        </h1>
        <p>
          This view translates the problem statement into the system’s actual
          evidence boundary. It distinguishes packet-observed facts, authorized
          gateway facts, and model estimates.
        </p>
        <div className="coverage-status">
          <Pill tone="green">PCAP + live sensor</Pill>
          <Pill tone={telemetryReady ? "green" : "slate"}>
            {telemetryReady ? "gateway correlated" : "packet-only session"}
          </Pill>
          <Pill tone={report ? "blue" : "slate"}>
            {report ? "assessment loaded" : "awaiting assessment"}
          </Pill>
        </div>
      </section>
      <section className="card coverage-actions">
        <div className="section-title">
          <div>
            <span>Next best action</span>
            <h2>
              {telemetryReady
                ? "Run correlated assessment"
                : "Connect endpoint telemetry"}
            </h2>
          </div>
          <Pill tone={telemetryReady ? "green" : "amber"}>
            {telemetryReady ? "assurance ready" : "improves SA certainty"}
          </Pill>
        </div>
        <p>
          {telemetryReady
            ? "The current session can carry authoritative SA configuration into the assessment and reports."
            : "PCAP can prove IKE/ESP structure, but PFS, replay window, CHILD-SA crypto, mode, and lifetime may be encrypted or endpoint-local. Connect authorized read-only telemetry to verify them."}
        </p>
        <button className="button primary" onClick={onReviewEvidence}>
          Review evidence ledger
        </button>
      </section>
      <section className="card wide">
        <div className="section-title">
          <div>
            <span>Problem-statement coverage</span>
            <h2>What this deployment demonstrates</h2>
          </div>
          <Pill tone="blue">evidence-bounded</Pill>
        </div>
        <div className="coverage-rows">
          {rows.map(([area, detail, status]) => (
            <article key={area}>
              <span className={`coverage-dot ${status}`} />
              <div>
                <b>{area}</b>
                <small>{detail}</small>
              </div>
              <Pill
                tone={
                  status === "ready"
                    ? "green"
                    : status === "demo"
                      ? "blue"
                      : "amber"
                }
              >
                {status === "ready"
                  ? "implemented"
                  : status === "demo"
                    ? "demo / OOD"
                    : "telemetry-bounded"}
              </Pill>
            </article>
          ))}
        </div>
      </section>
      <section className="card wide">
        <div className="section-title">
          <div>
            <span>Current protocol identification</span>
            <h2>Evidence-statused results</h2>
          </div>
          <Pill tone={report ? "green" : "slate"}>
            {report ? "assessment evidence" : "no capture loaded"}
          </Pill>
        </div>
        <ProtocolFacts report={report} evidence={evidence} />
      </section>
    </div>
  );
}

function CaptureReceipt({ report }) {
  const collection = report?.capture?.collection;
  if (!collection)
    return (
      <div className="capture-receipt empty-receipt">
        <b>No live capture receipt</b>
        <span>
          Analyze a live capture to see which interface and trace produced its
          results.
        </span>
      </div>
    );
  return (
    <div className="capture-receipt">
      <div>
        <span>Capture interface</span>
        <b>{collection.interface || "Unknown"}</b>
      </div>
      <div>
        <span>Packets analyzed</span>
        <b>{report?.capture?.packet_count ?? "—"}</b>
      </div>
      <div>
        <span>IKE SAs / ESP flows</span>
        <b>
          {report?.capture?.ike_sessions?.length ?? 0} /{" "}
          {report?.capture?.esp_flows?.length ?? 0}
        </b>
      </div>
      <div>
        <span>Capture window</span>
        <b>{collection.duration_seconds ?? "—"} sec</b>
      </div>
      <div className="receipt-hash">
        <span>Trace SHA-256</span>
        <code>
          {report?.capture?.sha256 ||
            collection.capture_sha256 ||
            "Unavailable"}
        </code>
      </div>
      <small>
        Each report is tied to this exact trace. Interfaces that see the same
        gateway packets can produce matching assessments.
      </small>
    </div>
  );
}

export default function App() {
  const [interfaceError, setInterfaceError] = useState(""),
    [page, setPage] = useState("command"),
    [report, setReport] = useState(null),
    [interfaces, setInterfaces] = useState([]),
    [demos, setDemos] = useState([]),
    [iface, setIface] = useState(""),
    [seconds, setSeconds] = useState(20),
    [authorized, setAuthorized] = useState(false),
    [state, setState] = useState("ready"),
    [message, setMessage] = useState(
      "Checking local backend and verified model…",
    ),
    [filter, setFilter] = useState("ALL"),
    [telemetry, setTelemetry] = useState(null),
    [backend, setBackend] = useState("checking"),
    [watch, setWatch] = useState({ active: false, detected: false }),
    [caseHistory, setCaseHistory] = useState([]);
  const refreshCaseHistory = () =>
    window.vpnguardx?.getCaseHistory?.().then((entries) => setCaseHistory(entries || [])).catch(() => {});
  useEffect(() => {
    const bridge = window.vpnguardx;
    if (!bridge?.isDesktop) {
      setBackend("unavailable");
      setMessage(
        "Browser preview detected. Launch VPNGUARD-X through Electron; no mock analysis is available.",
      );
      return;
    }
    bridge
      .getBackendHealth()
      .then(() => {
        setBackend("ready");
        setMessage("Verified backend and model bundle ready.");
        return bridge.getInterfaces();
      })
      .then((result) => {
        const found = result?.interfaces || [];
        setInterfaces(found);
        setIface(found?.[0]?.name || "");
        setInterfaceError(
          result?.error ||
            (!found.length
              ? "No capture interfaces are available. Check dumpcap installation and capture permissions."
              : ""),
        );
        return bridge.getDemoPcaps();
      })
      .then((x) => setDemos(x || []))
      .then(() => refreshCaseHistory())
      .catch((error) => {
        setBackend("failed");
        setMessage(
          error.message ||
            "Backend/model health check failed. Re-run install.sh.",
        );
      });
  }, []);
  useEffect(() => {
    if (!watch.active) return;
    const timer = setInterval(
      () =>
        window.vpnguardx
          ?.getIpsecWatchStatus?.()
          .then((status) => {
            if (status) {
              setWatch(status);
              if (status.detected)
                setMessage(
                  `Candidate IKE/ESP traffic captured on ${status.interface}. Stop Watch Mode to verify and assess it.`,
                );
            }
          })
          .catch(() => {}),
      1000,
    );
    return () => clearInterval(timer);
  }, [watch.active]);
  const analyze = async (path, source = "PCAP") => {
    if (!path) return;
    if (backend !== "ready") {
      setMessage(
        "Backend/model unavailable; resolve startup status before analysis.",
      );
      return;
    }
    setState("analyzing");
    setMessage(
      `Running ${telemetry?.path ? "correlated " : ""}evidence-bounded ${source.toLowerCase()} analysis…`,
    );
    try {
      const data = await window.vpnguardx.runAnalysis(
        path,
        telemetry?.path || null,
      );
      setReport(data);
      refreshCaseHistory();
      setMessage(
        `Assessment complete · ${data.run?.run_id || "new investigation"}`,
      );
      setPage(source === "live capture" ? "live" : "command");
    } catch (e) {
      setMessage(e.message || "Analysis failed.");
      setPage("live");
    } finally {
      setState("ready");
    }
  };
  const capture = async () => {
    if (!authorized || !iface || backend !== "ready") return;
    setState("capturing");
    setMessage(`Capturing IKE/ESP on ${iface} for ${seconds} seconds…`);
    try {
      await analyze(
        await window.vpnguardx.startCapture(iface, seconds),
        "live capture",
      );
    } catch (e) {
      setState("ready");
      setMessage(
        e.message || "Live capture failed. Check capture permissions.",
      );
    }
  };
  const startWatch = async () => {
    if (!authorized || !iface || backend !== "ready") return;
    try {
      const started = await window.vpnguardx.startIpsecWatch(iface);
      setWatch(started);
      setMessage(
        `IPsec Watch Mode active on ${iface}. Only IKE/ESP/NAT-T candidate traffic is buffered.`,
      );
    } catch (e) {
      setMessage(e.message || "Could not start IPsec Watch Mode.");
    }
  };
  const stopWatch = async () => {
    try {
      const stopped = await window.vpnguardx.stopIpsecWatch();
      setWatch({ active: false, detected: false });
      if (stopped?.detected && stopped.pcapPath) {
        setMessage("IPsec evidence captured. Running assessment…");
        await analyze(stopped.pcapPath, "IPsec Watch capture");
      } else
        setMessage(
          "IPsec Watch stopped. No IPsec VPN traffic was detected on this interface.",
        );
    } catch (e) {
      setMessage(e.message || "Could not stop IPsec Watch Mode.");
    }
  };
  const evidence = report?.capture?.evidence || [],
    findings = report?.policy?.findings || [],
    risk = report?.risk,
    posture = risk
      ? Math.max(
          0,
          Math.round((1 - (n(risk.minimum) + n(risk.maximum)) / 2) * 100),
        )
      : null;
  const gatewayEvidence = evidence.filter((x) =>
      ["GATEWAY_TELEMETRY", "STRONGSWAN_VICI", "LINUX_XFRM"].includes(x.source),
    ).length,
    missingAssurance = [
      "child.pfs_group",
      "child.anti_replay_enabled",
      "child.replay_window_size",
      "sa.remaining_lifetime_seconds",
    ].filter(
      (property) =>
        !evidence.some((x) => x.property_name === property && x.value != null),
    );
  const candidates = useMemo(
    () =>
      Object.entries(report?.cgii?.posterior || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 7)
        .map(([name, value]) => ({
          name: name.replace("MODERN_", "").replaceAll("_", " "),
          value: Math.round(value * 100),
        })),
    [report],
  );
  const evidenceStats = useMemo(
    () =>
      Object.entries(states).map(([key, [name, tone]]) => ({
        name,
        value: evidence.filter((x) => x.status === key).length,
        fill: {
          green: "#3ddc97",
          blue: "#56a8ff",
          amber: "#ffb84d",
          slate: "#71809b",
        }[tone],
      })),
    [evidence],
  );
  const nav = [
    ["command", Gauge, "Command center"],
    ["live", Radar, "Live sensor"],
    ["gateway", Network, "Gateway connector"],
    ["coverage", CheckCircle2, "SIH coverage"],
    ["evidence", Layers3, "Evidence ledger"],
    ["assessment", ShieldAlert, "Security assessment"],
    ["reports", FileText, "Reports & export"],
  ];
  const command = (
    <div className="page-grid">
      <section className="hero card">
        <div className="eyebrow">
          <Sparkles size={14} /> AI-powered IPsec assurance
        </div>
        <h1>
          See the VPN.
          <br />
          <em>Respect the encryption.</em>
        </h1>
        <p>
          One analyst workspace for IKE/ESP discovery, calibrated inference,
          policy assurance, and evidence-ready reporting.
        </p>
        <div className="hero-actions">
          <button
            className="button primary"
            disabled={backend !== "ready"}
            onClick={() => setPage("live")}
          >
            <Radar size={17} />
            Start live analysis
          </button>
          <button
            className="button secondary"
            disabled={backend !== "ready"}
            onClick={() => window.vpnguardx?.selectPcap?.().then(analyze)}
          >
            <Upload size={17} />
            Open PCAP
          </button>
        </div>
        <div className="hero-grid">
          <span>
            <b>{report?.capture?.packet_count ?? "—"}</b>packets inspected
          </span>
          <span>
            <b>{report?.capture?.ike_sessions?.length ?? "—"}</b>IKE sessions
          </span>
          <span>
            <b>{report?.capture?.esp_flows?.length ?? "—"}</b>ESP flows
          </span>
        </div>
      </section>
      <section className="posture card">
        <div className="card-heading">
          <div>
            <span>Security posture</span>
            <h2>{posture === null ? "No assessment yet" : `${posture}/100`}</h2>
          </div>
          <Pill tone={posture !== null && posture < 60 ? "red" : "green"}>
            {risk ? "Evidence-bounded" : "Awaiting PCAP"}
          </Pill>
        </div>
        <RiskGauge risk={risk} />
        <p className="fine-print">
          Posture summarizes policy-risk bounds; it is not a compromise
          probability.
        </p>
      </section>
      <section className="flow-card card wide">
        <div className="section-title">
          <div>
            <span>Protocol observatory</span>
            <h2>VPN session topology</h2>
          </div>
          <Pill tone="green">
            <Wifi size={12} />
            passive
          </Pill>
        </div>
        <FlowMap report={report} />
      </section>
      <section className="metrics wide">
        <Metric
          icon={ScanLine}
          label="Protocol"
          value={report ? "IPsec / ESP" : "Ready"}
          note={report?.mode || "classic PCAP + authorized live capture"}
          tone="green"
        />
        <Metric
          icon={Cpu}
          label="AI confidence"
          value={
            report?.application?.max_probability != null
              ? pct(report.application.max_probability)
              : report?.application?.label || "Not loaded"
          }
          note={
            report?.application?.reason_code || "verified model bundle required"
          }
          tone="amber"
        />
        <Metric
          icon={ShieldCheck}
          label="Evidence completeness"
          value={
            report?.cgii?.evidence_completeness != null
              ? pct(report.cgii.evidence_completeness)
              : "—"
          }
          note={`${report?.cgii?.prediction_set?.length || 0} supported candidate(s)`}
        />
        <Metric
          icon={AlertTriangle}
          label="Policy findings"
          value={
            findings.filter((x) => x.status?.includes("VIOLATION")).length ||
            "0"
          }
          note="certain and possible exposures"
          tone="red"
        />
      </section>
      <section className="card chart-card">
        <div className="section-title">
          <div>
            <span>AI / CGII</span>
            <h2>Candidate confidence</h2>
          </div>
          <Pill
            tone={
              report?.run?.deployment?.state === "LOADED" ? "green" : "slate"
            }
          >
            {report?.run?.deployment?.purpose === "SYNTHETIC_SOFTWARE_DEMO"
              ? "verified demo model"
              : report?.run?.deployment?.state === "LOADED"
                ? "verified model"
                : "no model bundle"}
          </Pill>
        </div>
        {candidates.length ? (
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={candidates} layout="vertical">
              <XAxis type="number" domain={[0, 100]} hide />
              <YAxis
                type="category"
                width={145}
                dataKey="name"
                tick={{ fill: "#92a0ba", fontSize: 10 }}
              />
              <Tooltip formatter={(x) => `${x}%`} />
              <Bar dataKey="value" radius={[0, 7, 7, 0]} fill="#56a8ff" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <Empty
            title="No candidate prior loaded"
            detail="The model may abstain when the capture is outside its trained configuration support."
          />
        )}
      </section>
      <section className="card chart-card">
        <div className="section-title">
          <div>
            <span>Trust boundary</span>
            <h2>Evidence composition</h2>
          </div>
          <Pill tone="blue">provenance-first</Pill>
        </div>
        {evidence.length ? (
          <ResponsiveContainer width="100%" height={210}>
            <PieChart>
              <Pie
                data={evidenceStats.filter((x) => x.value)}
                dataKey="value"
                nameKey="name"
                innerRadius={54}
                outerRadius={82}
                paddingAngle={4}
              >
                {evidenceStats
                  .filter((x) => x.value)
                  .map((x) => (
                    <Cell key={x.name} fill={x.fill} />
                  ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <Empty
            title="No evidence ledger"
            detail="Packet facts, derivations, AI inferences, and unknowns appear here."
          />
        )}
      </section>
    </div>
  );
  const live = (
    <div className="live-layout">
      <section className="card sensor-card">
        <div className="section-title">
          <div>
            <span>Authorized collection</span>
            <h1>Live sensor</h1>
          </div>
          <Pill tone={state === "capturing" ? "green" : "slate"}>
            {state === "capturing" ? "Listening" : "Idle"}
          </Pill>
        </div>
        <p>
          Capture IPsec outer traffic only on an interface you are authorized to
          monitor. The report identifies the interface, capture window, and
          trace hash.
        </p>
        <div className="capture-controls">
          <label>
            Network interface
            <select
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              disabled={state !== "ready" || !interfaces.length}
            >
              {interfaces.length ? (
                interfaces.map((x) => (
                  <option key={x.name} value={x.name}>
                    {x.name} — {x.description}
                  </option>
                ))
              ) : (
                <option value="">No interfaces available</option>
              )}
            </select>
            <small>
              {interfaceError ||
                "Choose the interface carrying the encrypted IPsec outer traffic."}
            </small>
          </label>
          <label>
            Capture window
            <input
              type="number"
              min="5"
              max="3600"
              value={seconds}
              onChange={(e) => setSeconds(Number(e.target.value))}
            />
            <small>seconds · bounded capture</small>
          </label>
        </div>
        <label className="consent">
          <input
            type="checkbox"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
          />
          <span>
            I am authorized to collect and analyze traffic on this interface.
          </span>
        </label>
        <div className="capture-actions">
          {state === "capturing" ? (
            <button
              className="button danger"
              onClick={() => window.vpnguardx.stopCapture?.()}
            >
              <XCircle size={17} />
              Stop capture
            </button>
          ) : (
            <button
              className="button primary"
              disabled={
                backend !== "ready" ||
                !authorized ||
                !iface ||
                state !== "ready"
              }
              onClick={capture}
            >
              <Play size={17} />
              Capture & assess
            </button>
          )}
          <button
            className="button secondary"
            disabled={backend !== "ready"}
            onClick={() => window.vpnguardx?.selectPcap?.().then(analyze)}
          >
            <Upload size={17} />
            Analyze saved PCAP
          </button>
          {report && (
            <>
              <button
                className="button secondary"
                onClick={() => window.vpnguardx?.exportReport("executive")}
              >
                <Download size={17} />
                Executive PDF
              </button>
              <button
                className="button secondary"
                onClick={() => window.vpnguardx?.exportReport("technical")}
              >
                <Download size={17} />
                Technical PDF
              </button>
            </>
          )}
        </div>
        <section className={`watch-panel ${watch.active ? "active" : ""}`}>
          <div>
            <span className="watch-kicker">Optional IPsec Watch Mode</span>
            <b>
              {watch.active
                ? watch.detected
                  ? "Candidate traffic buffered"
                  : "Watching for IKE / ESP traffic"
                : "Off by default"}
            </b>
            <small>
              {watch.active
                ? watch.detected
                  ? "Candidate packets are buffered. Stop Watch Mode to verify IKE/ESP and assess the temporary capture."
                  : "No IPsec traffic has been detected yet. No report is created until evidence is found."
                : "Enable only on an interface you are authorized to monitor. It watches IKE, NAT-T, and ESP only; it never starts at login."}
            </small>
          </div>
          {watch.active ? (
            <button className="button danger" onClick={stopWatch}>
              <XCircle size={16} />
              Stop & assess
            </button>
          ) : (
            <button
              className="button secondary"
              disabled={
                backend !== "ready" ||
                !authorized ||
                !iface ||
                state !== "ready"
              }
              onClick={startWatch}
            >
              <Radar size={16} />
              Enable Watch
            </button>
          )}
        </section>
        <CaptureReceipt report={report} />
        <div className="sensor-note">
          <b>Capture model</b>
          <span>
            Each capture is analyzed independently. If interfaces observe the
            same gateway traffic, protocol results may match; compare the
            capture receipt and hash.
          </span>
        </div>
      </section>
      <section
        className={`radar-stage ${state === "capturing" ? "is-scanning" : ""}`}
      >
        <div className="radar-rings" />
        <div className="radar-sweep" />
        <div className="radar-center">
          <Radar size={34} />
          <b>{state === "capturing" ? "CAPTURING" : "SENSOR READY"}</b>
          <span>{iface || "Select interface"}</span>
        </div>
        <div className="radar-tag tag-one">IKE · UDP 500</div>
        <div className="radar-tag tag-two">NAT-T · UDP 4500</div>
        <div className="radar-tag tag-three">ESP · protocol 50</div>
      </section>
      <section className="card wide session-card">
        <div className="section-title">
          <div>
            <span>Session progression</span>
            <h2>Current evidence timeline</h2>
          </div>
          <Pill tone={gatewayEvidence ? "green" : "slate"}>
            {gatewayEvidence ? "gateway correlated" : "packet-only"}
          </Pill>
        </div>
        <SessionTimeline report={report} evidence={evidence} />
        <div className="assurance-gap">
          <ShieldAlert size={16} />
          <span>
            {missingAssurance.length
              ? `Needs telemetry: ${missingAssurance.join(", ")}.`
              : "Required SA assurance fields are present in the current evidence ledger."}
          </span>
        </div>
      </section>
      <section className="card demo-card">
        <div className="section-title">
          <div>
            <span>Safe replay</span>
            <h2>Demo captures</h2>
          </div>
          <Pill tone="blue">offline</Pill>
        </div>
        {demos?.length ? (
          demos.map((x) => (
            <button
              className="demo-row"
              key={x.path}
              onClick={() => analyze(x.path, "demo PCAP")}
            >
              <span>
                <FileText size={17} />
                <b>{x.name}</b>
                <Pill tone="slate">{x.kind || "PCAP"}</Pill>
              </span>
              <ChevronRight size={17} />
            </button>
          ))
        ) : (
          <Empty
            title="No local demo PCAP"
            detail="Add authorized PCAP or PCAPNG captures to the demo collection."
          />
        )}
      </section>
    </div>
  );
  const gateway = (
    <div className="gateway-layout">
      <section className="card gateway-hero">
        <div className="eyebrow">
          <Network size={14} />
          Managed endpoint evidence
        </div>
        <h1>
          Gateway
          <br />
          <em>connector.</em>
        </h1>
        <p>
          Use a normalized telemetry JSON from any managed gateway, or collect
          read-only facts from this Linux host when it is the IPsec endpoint.
          Raw configuration files, PSKs, and keys are never imported.
        </p>
        <div className="hero-actions">
          <button
            className="button primary"
            onClick={async () => {
              try {
                const selected =
                  await window.vpnguardx?.selectCooperativeTelemetry?.();
                if (selected) {
                  setTelemetry({
                    ...selected,
                    collectedAt: new Date().toISOString(),
                  });
                  setMessage(`Gateway telemetry connected · ${selected.name}`);
                }
              } catch (e) {
                setMessage(e.message || "Telemetry import failed.");
              }
            }}
          >
            <Upload size={17} />
            Connect telemetry JSON
          </button>
          <button
            className="button secondary"
            onClick={async () => {
              try {
                const collected =
                  await window.vpnguardx?.collectLocalGatewayTelemetry?.();
                if (collected) {
                  setTelemetry(collected);
                  setMessage(
                    `Local gateway telemetry collected · ${collected.propertyCount} facts`,
                  );
                }
              } catch (e) {
                setMessage(e.message || "Local gateway telemetry unavailable.");
              }
            }}
          >
            <Activity size={17} />
            Read local gateway (admin)
          </button>
          {telemetry && (
            <button
              className="button secondary"
              onClick={() => {
                setTelemetry(null);
                setMessage("Gateway telemetry disconnected.");
              }}
            >
              <XCircle size={17} />
              Disconnect
            </button>
          )}
        </div>
        <div className="connector-status">
          <div
            className={telemetry ? "connector-dot online" : "connector-dot"}
          />
          <div>
            <b>
              {telemetry
                ? "Gateway telemetry connected"
                : "No gateway telemetry connected"}
            </b>
            <span>
              {telemetry
                ? `${telemetry.name} · ${telemetry.propertyCount} authorized properties${telemetry.collectedAt ? ` · collected ${new Date(telemetry.collectedAt).toLocaleTimeString()}` : ""}`
                : "Passive capture remains available; hidden SA fields will remain unknown."}
            </span>
          </div>
        </div>
      </section>
      <section className="card connector-fields">
        <div className="section-title">
          <div>
            <span>What gateway evidence can prove</span>
            <h2>Authoritative SA facts</h2>
          </div>
          <Pill tone="green">read-only</Pill>
        </div>
        <div className="field-grid">
          {[
            "Tunnel / transport mode",
            "ESP encryption + integrity",
            "PFS / DH group",
            "SA lifetime + rekey state",
            "Replay protection + window",
            "ESN, selectors, counters",
          ].map((item) => (
            <div key={item}>
              <CheckCircle2 size={16} />
              <span>{item}</span>
            </div>
          ))}
        </div>
        <p className="fine-print">
          Local collection asks for administrator approval because strongSwan
          VICI and Linux XFRM SA state are protected. It runs fixed read-only
          commands only; future vendor connectors should emit the same
          normalized evidence JSON.
        </p>
      </section>
      <section className="card wide correlation-card">
        <div className="section-title">
          <div>
            <span>Hybrid live assessment</span>
            <h2>Correlation model</h2>
          </div>
          <Pill tone={telemetry ? "green" : "slate"}>
            {telemetry ? "ready to correlate" : "packet-only mode"}
          </Pill>
        </div>
        <div className="correlation-flow">
          <article>
            <Radar size={22} />
            <b>Network sensor</b>
            <span>IKE, ESP, outer metadata, timing</span>
          </article>
          <i />
          <article>
            <Network size={22} />
            <b>Gateway connector</b>
            <span>SA state, policy, replay, PFS</span>
          </article>
          <i />
          <article>
            <ShieldCheck size={22} />
            <b>Correlated assessment</b>
            <span>One evidence ledger + report</span>
          </article>
        </div>
        <button
          className="button primary"
          disabled={!telemetry}
          onClick={() => setPage("live")}
        >
          <ChevronRight size={17} />
          Continue to live capture
        </button>
      </section>
    </div>
  );
  const ledger = (
    <section className="card ledger">
      <div className="section-title">
        <div>
          <span>Evidence ledger</span>
          <h1>What the system knows</h1>
          <p>
            Every claim is separated into observed, derived, AI-inferred, or
            unknown evidence.
          </p>
        </div>
        <div className="filter-row">
          {["ALL", ...Object.keys(states)].map((x) => (
            <button
              className={filter === x ? "filter active" : "filter"}
              key={x}
              onClick={() => setFilter(x)}
            >
              {x === "ALL" ? "All" : states[x][0]}
            </button>
          ))}
        </div>
      </div>
      {evidence.filter((x) => filter === "ALL" || filter === x.status)
        .length ? (
        <div className="ledger-list">
          {evidence
            .filter((x) => filter === "ALL" || filter === x.status)
            .map((x, i) => {
              const [label, t] = pill(x.status);
              return (
                <motion.article
                  className="ledger-item"
                  key={`${x.property_name}-${i}`}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <div className={`ledger-status ${t}`} />
                  <div className="ledger-main">
                    <div>
                      <code>{x.property_name}</code>
                      <Pill tone={t}>{label}</Pill>
                    </div>
                    <strong>
                      {x.value == null
                        ? "Unknown / unobservable"
                        : typeof x.value === "object"
                          ? JSON.stringify(x.value)
                          : String(x.value)}
                    </strong>
                    <p>{x.rationale || "No rationale provided."}</p>
                  </div>
                  <div className="ledger-source">
                    <span>Source</span>
                    <b>{x.source || "—"}</b>
                    {x.confidence != null && (
                      <small>AI confidence {pct(x.confidence)}</small>
                    )}
                  </div>
                </motion.article>
              );
            })}
        </div>
      ) : (
        <Empty
          title="No evidence to display"
          detail="Run an analysis to inspect protocol, cryptographic, and metadata evidence."
        />
      )}
    </section>
  );
  const assessment = (
    <div className="assessment-grid">
      <section className="card findings-card">
        <div className="section-title">
          <div>
            <span>Policy engine</span>
            <h1>Security assessment</h1>
            <p>
              Rules are evaluated over supported configurations; possible
              findings are never presented as observed attacks.
            </p>
          </div>
          <RiskGauge risk={risk} />
        </div>
        <div className="finding-stack">
          {findings.length ? (
            findings.map((x, i) => (
              <article className="finding" key={i}>
                <div className={`finding-icon ${tone(x.status)}`}>
                  {x.status?.includes("VIOLATION") ? (
                    <AlertTriangle size={18} />
                  ) : (
                    <CheckCircle2 size={18} />
                  )}
                </div>
                <div>
                  <Pill tone={tone(x.status)}>
                    {x.status?.replaceAll("_", " ")}
                  </Pill>
                  <h3>{x.rule_id}</h3>
                  <p>
                    {x.rationale ||
                      `${x.field || "Policy field"} ${x.operator || ""} ${x.expected ?? ""}`}
                  </p>
                </div>
                <small>{x.severity || "INFO"}</small>
              </article>
            ))
          ) : (
            <Empty
              title="No policy findings yet"
              detail="Assess a capture to calculate policy exposure."
            />
          )}
        </div>
      </section>
      <section className="card matrix-card">
        <div className="section-title">
          <div>
            <span>Threat matrix</span>
            <h2>Exposure context</h2>
          </div>
          <Pill tone="red">no exploit claim</Pill>
        </div>
        {report?.threat_matrix?.length ? (
          <div className="threat-grid">
            {report.threat_matrix.slice(0, 8).map((x) => (
              <article key={x.threat_id} className="threat">
                <span className={`threat-level ${tone(x.finding)}`} />
                <code>{x.rule_id}</code>
                <b>{x.threat_context}</b>
                <p>{x.interpretation}</p>
                <Pill tone={pill(x.status)[1]}>{x.status}</Pill>
              </article>
            ))}
          </div>
        ) : (
          <Empty
            title="Threat matrix unavailable"
            detail="It is generated alongside policy evaluation."
          />
        )}
      </section>
      <section className="card wide">
        <div className="section-title">
          <div>
            <span>CGII resolution</span>
            <h2>Configuration candidate set</h2>
          </div>
          <Pill tone="blue">
            {report?.cgii?.feasible_candidate_count ?? 0} feasible /{" "}
            {report?.cgii?.total_candidates ?? 0} total
          </Pill>
        </div>
        <div className="candidate-grid">
          {report?.cgii?.prediction_set?.map((x) => (
            <article key={x} className="candidate">
              <ShieldCheck size={17} />
              <code>{x}</code>
              <b>{pct(report.cgii.posterior?.[x])}</b>
              <span>supported candidate</span>
            </article>
          ))}
          {!report?.cgii?.prediction_set?.length && (
            <Empty
              title="No resolved candidate set"
              detail="Evidence conflict, missing data, or no capture may prevent inference."
            />
          )}
        </div>
      </section>
    </div>
  );
  const reports = (
    <div className="reports-layout">
      <section className="report-hero card">
        <div className="eyebrow">
          <FileText size={14} />
          Handoff-ready outputs
        </div>
        <h1>
          Reports for both
          <br />
          <em>decisions and detail.</em>
        </h1>
        <p>
          Export the full machine-readable ledger or focused reports for
          executives and technical analysts.
        </p>
        <div className="report-actions">
          <button
            className="button primary"
            disabled={!report}
            onClick={() => window.vpnguardx?.exportReport("executive")}
          >
            <Download size={17} />
            Executive report
          </button>
          <button
            className="button secondary"
            disabled={!report}
            onClick={() => window.vpnguardx?.exportReport("technical")}
          >
            <Download size={17} />
            Technical report
          </button>
          <button
            className="button secondary"
            disabled={!report}
            onClick={() => window.vpnguardx?.exportReport("json")}
          >
            <Download size={17} />
            Evidence JSON
          </button>
        </div>
      </section>
      <section className="card report-preview">
        <span>Report contents</span>
        <ul>
          {[
            "Executive security posture and policy-risk interval",
            "Technical evidence ledger with source and rationale",
            "IKE/ESP session and metadata analysis",
            "AI inference, confidence, OOD/unknown state",
            "Threat matrix and configuration remediation",
          ].map((x) => (
            <li key={x}>
              <CheckCircle2 />
              {x}
            </li>
          ))}
        </ul>
        <p className="fine-print">
          Exports retain evidence boundaries: encrypted fields are never
          represented as observed without authorized telemetry.
        </p>
      </section>
      <section className="card case-index">
        <div className="section-title">
          <div>
            <span>Local analyst continuity</span>
            <h2>Recent case index</h2>
          </div>
          <Pill tone="slate">metadata only</Pill>
        </div>
        {caseHistory.length ? (
          <div className="case-list">
            {caseHistory.slice(0, 5).map((entry) => (
              <div className="case-row" key={entry.run_id}>
                <div>
                  <b>{entry.run_id}</b>
                  <small>{new Date(entry.created_at_utc).toLocaleString()} · {String(entry.source_kind).replaceAll("_", " ")}</small>
                </div>
                <div className="case-metrics">
                  <span>{entry.packet_count ?? "—"} packets</span>
                  <span>{entry.risk_minimum != null ? `${Math.round(entry.risk_minimum * 100)}–${Math.round(entry.risk_maximum * 100)} risk` : "risk pending"}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No local cases indexed" detail="Completed assessments appear here as metadata only; export reports whenever you need a permanent copy." />
        )}
        <p className="fine-print">This local SQLite index never stores raw PCAP payloads, decrypted content, secrets, or key material.</p>
      </section>
    </div>
  );
  const coverage = (
    <SIHCoverage
      report={report}
      evidence={evidence}
      onReviewEvidence={() => setPage("evidence")}
    />
  );
  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={22} />
          </span>
          <div>
            <b>VPNGUARD</b>
            <small>X / ANALYST</small>
          </div>
        </div>
        <nav>
          {nav.map(([id, Icon, label]) => (
            <button
              key={id}
              className={page === id ? "nav active" : "nav"}
              onClick={() => setPage(id)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {id === "assessment" && findings.length > 0 && (
                <i>{findings.length}</i>
              )}
            </button>
          ))}
        </nav>
        <div className="side-footer">
          <Pill
            tone={
              backend === "ready"
                ? "green"
                : backend === "failed" || backend === "unavailable"
                  ? "red"
                  : "amber"
            }
          >
            <span className="pulse" />
            {backend === "ready"
              ? "System ready"
              : backend === "checking"
                ? "Starting local engine…"
                : "Backend unavailable"}
          </Pill>
          <small>
            Evidence-bounded analysis
            <br />
            Authorized use only
          </small>
        </div>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div>
            <span className="breadcrumb">VPNGUARD-X / {page}</span>
            <b>{message}</b>
          </div>
          <div className="topbar-right">
            <Pill
              tone={
                state === "capturing" || state === "analyzing"
                  ? "amber"
                  : backend === "ready"
                    ? "green"
                    : backend === "failed" || backend === "unavailable"
                      ? "red"
                      : "slate"
              }
            >
              <Activity size={12} />
              {state === "capturing"
                ? "Live capture"
                : state === "analyzing"
                  ? "Analyzing"
                  : backend === "ready"
                    ? "Engine online"
                    : backend === "checking"
                      ? "Checking engine"
                      : "Backend unavailable"}
            </Pill>
            <span className="run-id">
              {report?.run?.run_id || "NO ACTIVE CASE"}
            </span>
          </div>
        </header>
        <div className="content">
          <AnimatePresence mode="wait">
            <motion.div
              key={page}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.28 }}
            >
              {page === "command" && command}
              {page === "live" && live}
              {page === "gateway" && gateway}
              {page === "coverage" && coverage}
              {page === "evidence" && ledger}
              {page === "assessment" && assessment}
              {page === "reports" && reports}
            </motion.div>
          </AnimatePresence>
        </div>
      </section>
    </main>
  );
}
