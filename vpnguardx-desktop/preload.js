const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vpnguardx', {
  isDesktop: true,
  getBackendHealth: () => ipcRenderer.invoke('get-backend-health'),
  getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
  selectPcap: () => ipcRenderer.invoke('select-pcap'),
  selectCooperativeTelemetry: () => ipcRenderer.invoke('select-cooperative-telemetry'),
  collectLocalGatewayTelemetry: () => ipcRenderer.invoke('collect-local-gateway-telemetry'),
  startCapture: (iface, durationSeconds) => ipcRenderer.invoke('start-capture', iface, durationSeconds),
  stopCapture: () => ipcRenderer.invoke('stop-capture'),
  startIpsecWatch: (iface) => ipcRenderer.invoke('start-ipsec-watch', iface),
  getIpsecWatchStatus: () => ipcRenderer.invoke('get-ipsec-watch-status'),
  stopIpsecWatch: () => ipcRenderer.invoke('stop-ipsec-watch'),
  getCaseHistory: () => ipcRenderer.invoke('get-case-history'),
  runAnalysis: (pcapPath, telemetryPath) => ipcRenderer.invoke('run-analysis', pcapPath, telemetryPath),
  exportReport: (format) => ipcRenderer.invoke('export-report', format),
  getDemoPcaps: () => ipcRenderer.invoke('get-demo-pcaps'),
});
