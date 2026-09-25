const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

app.setName('VPNGUARD-X');
let mainWindow;
let latestReportDirectory = null;

function backendDirectory() {
  return app.isPackaged ? path.join(process.resourcesPath, 'backend') : path.join(__dirname, '..');
}

function pythonExecutable(backendDir) {
  const candidates = [
    process.env.VPNGUARDX_PYTHON,
    // install.sh creates this exact app-local environment for both source and
    // packaged Electron.  Do not silently prefer a random system Python.
    path.join(app.getPath('userData'), '.venv', 'bin', 'python'),
    path.join(backendDir, '.venv', 'bin', 'python'),
    'python3', 'python'
  ].filter(Boolean);
  return candidates.find(candidate => candidate === 'python3' || candidate === 'python' || fs.existsSync(candidate));
}

function spawnBackend(backendDir, args) {
  return spawn(pythonExecutable(backendDir), args, {
    cwd: backendDir,
    env: { ...process.env, PATH: `${path.join(app.getPath('userData'), '.venv', 'bin')}:${path.join(backendDir, '.venv', 'bin')}:${process.env.PATH}` }
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  if (process.env.NODE_ENV === 'development') {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile('dist/index.html');
  }
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Handlers

ipcMain.handle('get-interfaces', async () => {
  return new Promise((resolve, reject) => {
    // dumpcap is deliberately the only binary granted capture capability by
    // install.sh; listing and capture must use that same constrained tool.
    exec('dumpcap -D', (error, stdout, stderr) => {
      if (error) return resolve([]);
      const lines = stdout.split('\n').filter(l => l.trim().length > 0);
      const interfaces = lines.map(line => {
        const match = line.match(/^\d+\.(\S+)(?:\s+\[(.*?)\]|\s+(.*))?/);
        if (match) {
          return { name: match[1], description: match[2] || match[3] || match[1] };
        }
        return { name: line, description: line };
      }).filter(i => i.name);
      resolve(interfaces);
    });
  });
});

ipcMain.handle('select-pcap', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    title: 'Select an authorized IPsec capture',
    properties: ['openFile'],
    filters: [{ name: 'Classic PCAP', extensions: ['pcap', 'cap'] }]
  });
  return canceled ? null : filePaths[0];
});

function containsSensitiveKey(value) {
  const forbidden = new Set(['key', 'keys', 'secret', 'secrets', 'psk', 'private_key', 'key_material', 'session_key']);
  if (Array.isArray(value)) return value.some(containsSensitiveKey);
  if (!value || typeof value !== 'object') return false;
  return Object.entries(value).some(([key, nested]) => {
    const normalized = String(key).toLowerCase();
    return forbidden.has(normalized) || normalized.includes('secret') || normalized.endsWith('_key') || containsSensitiveKey(nested);
  });
}

ipcMain.handle('select-cooperative-telemetry', async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog({
    title: 'Select approved gateway telemetry',
    properties: ['openFile'],
    filters: [{ name: 'Normalized telemetry JSON', extensions: ['json'] }]
  });
  if (canceled) return null;
  const selected = filePaths[0];
  const stats = fs.statSync(selected);
  if (stats.size > 1024 * 1024) throw new Error('Telemetry JSON exceeds the 1 MiB desktop safety limit.');
  let data;
  try { data = JSON.parse(fs.readFileSync(selected, 'utf8')); }
  catch { throw new Error('Telemetry file is not valid JSON.'); }
  if (!data || Array.isArray(data) || typeof data !== 'object') throw new Error('Telemetry root must be a JSON object.');
  if (containsSensitiveKey(data)) throw new Error('Telemetry contains prohibited secret or key-material fields.');
  return { path: selected, name: path.basename(selected), propertyCount: Object.keys(data).length };
});

let captureProcess = null;

ipcMain.handle('start-capture', async (event, iface, durationSeconds) => {
  return new Promise((resolve, reject) => {
    if (!Number.isInteger(durationSeconds) || durationSeconds < 5 || durationSeconds > 3600) {
      return reject(new Error('Capture duration must be a whole number between 5 and 3600 seconds.'));
    }
    if (typeof iface !== 'string' || !iface) return reject(new Error('Select a valid capture interface.'));
    const startedAt = new Date().toISOString();
    const pcapPath = path.join(app.getPath('temp'), `vpnguardx-capture-${Date.now()}.pcap`);
    const filter = 'udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50';
    // Capture exactly the selected interface. Do not use tcpdump rotation here:
    // a single completed PCAP is required for traceable analysis and reporting.
    const process = spawn('dumpcap', ['-i', iface, '-s', '0', '-f', filter, '-w', pcapPath, '-F', 'pcap']);
    captureProcess = process;
    let errorMsg = '';
    process.on('error', (error) => {
      if (captureProcess === process) captureProcess = null;
      reject(new Error(`Unable to start dumpcap: ${error.message}`));
    });
    process.stderr.on('data', (data) => {
      errorMsg += data.toString();
    });

    process.on('close', (code) => {
      if (captureProcess === process) captureProcess = null;
      if (code !== 0 && code !== null) {
        return reject(new Error(`dumpcap failed (code ${code}): ${errorMsg}`));
      }
      if (!fs.existsSync(pcapPath) || fs.statSync(pcapPath).size <= 24) {
        return reject(new Error(`No IKE, NAT-T, or ESP packets were captured on ${iface}. Choose the interface carrying the IPsec outer traffic, create authorized VPN traffic, then try again.`));
      }
      {
        const manifest = {
          interface: iface,
          filter,
          duration_seconds: durationSeconds,
          started_at_utc: startedAt,
          completed_at_utc: new Date().toISOString(),
          packet_count: null,
          capture_sha256: crypto.createHash('sha256').update(fs.readFileSync(pcapPath)).digest('hex'),
          authorization_acknowledged: true,
          active_probe_performed: false
        };
        fs.writeFileSync(`${pcapPath}.manifest.json`, JSON.stringify(manifest, null, 2));
        resolve(pcapPath);
      }
    });

    // Automatically kill after duration + 2 seconds just in case
    setTimeout(() => {
      if (captureProcess === process) {
        process.kill('SIGINT');
      }
    }, (durationSeconds + 2) * 1000);
  });
});

ipcMain.handle('stop-capture', async () => {
  if (captureProcess) {
    captureProcess.kill('SIGINT');
    captureProcess = null;
    return true;
  }
  return false;
});

ipcMain.handle('run-analysis', async (event, pcapPath, telemetryPath = null) => {
  return new Promise((resolve, reject) => {
    // Find the python backend directory (parent of desktop-app)
    const backendDir = backendDirectory();
    
    const outputDirectory = path.join(app.getPath('temp'), `vpnguardx-assessment-${Date.now()}`);
    const args = [
      'vpnguardx.py', 'analyze', pcapPath,
      '--deployment', path.join(backendDir, 'artifacts', 'deployment_bundle'),
      '--allow-demo-deployment', '--output', outputDirectory
    ];
    const manifestPath = `${pcapPath}.manifest.json`;
    if (fs.existsSync(manifestPath)) args.push('--capture-metadata', manifestPath);
    if (telemetryPath) args.push('--cooperative-json', telemetryPath, '--cooperative-source', 'GATEWAY_TELEMETRY');
    const pyProcess = spawnBackend(backendDir, args);

    let stderr = '';
    pyProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    pyProcess.on('error', error => reject(new Error(`Unable to start Python analysis runtime: ${error.message}`)));

    pyProcess.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Analysis failed (code ${code}): ${stderr}`));
      } else {
        // Read the result
        const reportPath = path.join(outputDirectory, 'assessment.json');
        try {
          const data = fs.readFileSync(reportPath, 'utf8');
          latestReportDirectory = outputDirectory;
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error(`Could not read assessment report: ${err.message}`));
        }
      }
    });
  });
});

ipcMain.handle('export-report', async (event, format) => {
  const latestDir = latestReportDirectory;
  if (!latestDir) throw new Error('Report not found. Run analysis first.');
  let srcFile = '';
  
  if (format === 'json') srcFile = path.join(latestDir, 'assessment.json');
  else if (format === 'technical') srcFile = path.join(latestDir, 'technical_report.pdf');
  else if (format === 'executive') srcFile = path.join(latestDir, 'executive_report.pdf');
  else throw new Error('Unsupported report format.');
  
  if (!fs.existsSync(srcFile)) {
    throw new Error('Report not found. Run analysis first.');
  }

  const { canceled, filePath } = await dialog.showSaveDialog({
    defaultPath: `vpnguardx-${format}-report.${format === 'json' ? 'json' : 'pdf'}`
  });

  if (!canceled && filePath) {
    fs.copyFileSync(srcFile, filePath);
    return filePath;
  }
  return null;
});

ipcMain.handle('collect-local-gateway-telemetry', async () => {
  const backendDir = backendDirectory();
  const outputPath = path.join(app.getPath('temp'), `vpnguardx-gateway-${Date.now()}.json`);
  return new Promise((resolve, reject) => {
    const collector = spawnBackend(backendDir, [
      'vpnguardx.py', 'telemetry', '--output', outputPath, '--i-am-authorized'
    ]);
    let stderr = '';
    collector.stderr.on('data', data => { stderr += data.toString(); });
    collector.on('error', error => reject(new Error(`Unable to start Python telemetry runtime: ${error.message}`)));
    collector.on('close', code => {
      if (code !== 0) return reject(new Error(`Gateway telemetry unavailable: ${stderr || 'no readable local IPsec SA state.'}`));
      try {
        const data = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
        if (containsSensitiveKey(data)) throw new Error('Collector returned prohibited secret/key-material fields.');
        resolve({ path: outputPath, name: 'Local gateway telemetry', propertyCount: Object.keys(data).length, collectedAt: new Date().toISOString() });
      } catch (error) { reject(error); }
    });
  });
});

ipcMain.handle('get-backend-health', async () => {
  const backendDir = backendDirectory();
  return new Promise((resolve, reject) => {
    const health = spawnBackend(backendDir, [
      'vpnguardx.py', 'health',
      '--deployment', path.join(backendDir, 'artifacts', 'deployment_bundle'),
      '--allow-demo-deployment'
    ]);
    let stdout = '';
    let stderr = '';
    health.stdout.on('data', data => { stdout += data.toString(); });
    health.stderr.on('data', data => { stderr += data.toString(); });
    health.on('error', error => reject(new Error(`Unable to start Python runtime: ${error.message}`)));
    health.on('close', code => {
      if (code !== 0) return reject(new Error(`Backend/model health check failed: ${stderr || 'unknown error'}`));
      try { resolve(JSON.parse(stdout)); }
      catch { reject(new Error('Backend health check returned invalid JSON.')); }
    });
  });
});

ipcMain.handle('get-demo-pcaps', async () => {
  const backendDir = backendDirectory();
  const roots = [
    { directory: path.join(backendDir, 'artifacts', 'smoke_demo'), kind: 'SYNTHETIC_PROTOCOL_FIXTURE' },
    { directory: path.join(backendDir, 'artifacts', 'demo_extensions'), kind: 'DEMO_EXTENSION_OOD' }
  ];
  const discovered = [];
  for (const root of roots) {
    if (!fs.existsSync(root.directory)) continue;
    const visit = (directory) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const selected = path.join(directory, entry.name);
        if (entry.isDirectory()) visit(selected);
        else if (entry.isFile() && (entry.name.endsWith('.pcap') || entry.name.endsWith('.cap'))) {
          discovered.push({ name: entry.name, path: selected, kind: root.kind });
        }
      }
    };
    visit(root.directory);
  }
  return discovered;
});
