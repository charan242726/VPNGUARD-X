const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vpnguardx', {
  getInterfaces: () => ipcRenderer.invoke('get-interfaces'),
  selectPcap: () => ipcRenderer.invoke('select-pcap'),
  selectCooperativeTelemetry: () => ipcRenderer.invoke('select-cooperative-telemetry'),
  collectLocalGatewayTelemetry: () => ipcRenderer.invoke('collect-local-gateway-telemetry'),
  startCapture: (iface, durationSeconds) => ipcRenderer.invoke('start-capture', iface, durationSeconds),
  stopCapture: () => ipcRenderer.invoke('stop-capture'),
  runAnalysis: (pcapPath, telemetryPath) => ipcRenderer.invoke('run-analysis', pcapPath, telemetryPath),
  exportReport: (format) => ipcRenderer.invoke('export-report', format),
  getDemoPcaps: () => ipcRenderer.invoke('get-demo-pcaps'),
});
