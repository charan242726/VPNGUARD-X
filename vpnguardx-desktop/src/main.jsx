import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// Mock Electron IPC for browser testing
if (!window.vpnguardx) {
  window.vpnguardx = {
    getInterfaces: async () => [{ name: 'eth0', description: 'Mock Interface' }],
    selectPcap: async () => 'artifacts/smoke_demo/synthetic_ikev2_esp.pcap',
    selectCooperativeTelemetry: async () => ({ name: 'authorized-gateway-telemetry.json', path: null, propertyCount: 0 }),
    collectLocalGatewayTelemetry: async () => ({ name: 'Local gateway telemetry', path: null, propertyCount: 0, collectedAt: new Date().toISOString() }),
    startCapture: async () => 'mock.pcap',
    stopCapture: async () => true,
    runAnalysis: async () => ({
      run_id: 'test-123',
      capture: { packet_count: 42, sha256: 'a1b2c3d4...', evidence: [{property_name: 'ike.version', value: 'IKEV2', status: 'OBSERVED', source: 'IKE_HEADER'}] },
      cgii: { prediction_set: ['MODERN_V4_NATIVE_TRANSPORT_CBC14'], eliminated: {'LEGACY_IKEV1_V4_3DES': ['EVIDENCE_EQ::ike.version']}, posterior: {'MODERN_V4_NATIVE_TRANSPORT_CBC14': 1.0} },
      policy: { findings: [{rule_id: 'no_legacy', status: 'NOT_SUPPORTED', field: 'version', expected: 'IKEV2', operator: '=='}] },
      risk: { minimum: 0.12, maximum: 0.45, expected_model_dependent: 0.2 },
      application: { status: 'UNKNOWN/UNOBSERVABLE', reason_code: 'MODEL_NOT_SUPPLIED' }
    }),
    exportReport: async () => 'exported.md',
    getDemoPcaps: async () => [{name: 'synthetic_ikev2_esp.pcap', path: 'artifacts/smoke_demo/synthetic_ikev2_esp.pcap'}]
  };
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
