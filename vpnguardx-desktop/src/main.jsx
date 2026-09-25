import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// A Vite browser tab has no privileged Electron bridge.  Rendering an
// analyst-looking mock console here would falsely imply that PCAP analysis,
// live capture, and model inference are working.
function BrowserPreviewBlocked() {
  return (
    <main style={{ maxWidth: 720, margin: '12vh auto', padding: 32, fontFamily: 'system-ui, sans-serif', color: '#e9f1ff' }}>
      <p style={{ color: '#65b4ff', letterSpacing: '0.12em', fontSize: 12 }}>VPNGUARD-X / DESKTOP REQUIRED</p>
      <h1>This browser preview cannot analyze traffic.</h1>
      <p>Launch VPNGUARD-X through Electron using <code>./scripts/launch-desktop.sh</code>. The desktop app verifies its local Python backend and model bundle before analysis is enabled.</p>
    </main>
  );
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    {window.vpnguardx?.isDesktop ? <App /> : <BrowserPreviewBlocked />}
  </React.StrictMode>
);
