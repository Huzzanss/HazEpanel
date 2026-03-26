/**
 * PteroPanel v2 — Full-featured local game server panel
 * node server.js  →  http://localhost:3000
 */
const express   = require('express');
const http      = require('http');
const WebSocket = require('ws');
const { spawn, exec } = require('child_process');
const fs        = require('fs');
const path      = require('path');
const os        = require('os');
const crypto    = require('crypto');

// ─── CONFIG ────────────────────────────────────────────────────────────────
const CONFIG = {
  PORT:           3000,
  SERVERS_DIR:    path.join(__dirname, 'servers'),
  LOG_LINES:      2000,
  STATS_INTERVAL: 1500,
};

// ─── DIRS ──────────────────────────────────────────────────────────────────
const DATA_DIR   = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');
[DATA_DIR, BACKUP_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ─── STATE ─────────────────────────────────────────────────────────────────
const servers     = {};
const wsConsole   = {};
const broadcastWs = new Set();

// ─── DATA HELPERS ──────────────────────────────────────────────────────────
function loadData(id) {
  const fp = path.join(DATA_DIR, id + '.json');
  if (!fs.existsSync(fp)) return { databases: [], schedules: [], users: [], backups: [], allocations: [], settings: {} };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return { databases: [], schedules: [], users: [], backups: [], allocations: [], settings: {} }; }
}
function saveData(id, data) {
  fs.writeFileSync(path.join(DATA_DIR, id + '.json'), JSON.stringify(data, null, 2));
}
function uid() { return '_' + Math.random().toString(36).slice(2, 10) + Date.now().toString(36); }


// ─── AUTH HELPERS ─────────────────────────────────────────────────────────
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const sessions = new Map();

function defaultAuth() {
  return { username: 'admin', password: hashPassword('administrator') };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string' || !stored.includes('$')) return false;
  const [salt, hash] = stored.split('$');
  const test = crypto.scryptSync(String(password), salt, 64).toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex')); }
  catch { return false; }
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

function issueSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expires: Date.now() + SESSION_TTL_MS });
  return token;
}

function clearSession(token) {
  if (token) sessions.delete(token);
}

function currentSession(req) {
  const token = parseCookies(req).haze_session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expires < Date.now()) { sessions.delete(token); return null; }
  return { token, ...session };
}

function currentUser(req) {
  const session = currentSession(req);
  if (!session) return null;
  const d = loadPanelData();
  if (d.auth?.username !== session.username) return null;
  return { username: d.auth.username, displayName: d.account?.displayName || d.auth.username, email: d.account?.email || '' };
}

function authCookie(token) {
  return `haze_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`;
}

function isLoginRoute(pathname) {
  return pathname === '/login' || pathname === '/api/auth/login' || pathname === '/api/auth/logout' || pathname === '/api/auth/me';
}

function requireAuth(req, res, next) {
  if (isLoginRoute(req.path)) return next();
  if (req.path.startsWith('/api/')) {
    if (!currentUser(req)) return res.status(401).json({ error: 'Unauthorized' });
    return next();
  }
  if (!currentUser(req)) return res.redirect('/login');
  return next();
}

// ─── TYPE DETECTION ────────────────────────────────────────────────────────
function detectType(dir) {
  const raw   = fs.readdirSync(dir);
  const lower = raw.map(f => f.toLowerCase());

  if (lower.includes('bedrock_server.exe'))
    return { type:'bedrock', label:'Minecraft: Bedrock', eggName:'Bedrock Server',
             start:{ cmd:'bedrock_server.exe', args:[] } };

  if (lower.includes('server.jar')) {
    const bat = raw.find(f => f.toLowerCase() === 'start.bat');
    return { type:'minecraft', label:'Minecraft: Java Edition', eggName:'Paper / Spigot / Vanilla',
             start: bat ? { cmd:'cmd.exe', args:['/c', bat] }
                        : { cmd:'java', args:['-Xmx2G','-Xms1G','-jar','server.jar','nogui'] } };
  }
  if (lower.includes('package.json')) {
    let start = { cmd:'node', args:['index.js'] };
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8'));
      if (pkg.scripts?.start) start = { cmd:'npm.cmd', args:['start'] };
      else if (pkg.main)      start = { cmd:'node',    args:[pkg.main] };
    } catch {}
    return { type:'nodejs', label:'Node.js', eggName:'Generic: Node.js', start };
  }
  const py = raw.find(f => ['main.py','app.py','run.py','bot.py','server.py'].includes(f.toLowerCase()));
  if (py)
    return { type:'python', label:'Python', eggName:'Generic: Python', start:{ cmd:'python', args:[py] } };
  const bat = raw.find(f => f.toLowerCase() === 'start.bat');
  if (bat) return { type:'generic', label:'Generic: Batch', eggName:'Batch Script', start:{ cmd:'cmd.exe', args:['/c',bat] } };
  const sh = raw.find(f => f.toLowerCase() === 'start.sh');
  if (sh)  return { type:'generic', label:'Generic: Shell', eggName:'Shell Script', start:{ cmd:'bash', args:[sh] } };
  const exe = raw.find(f => f.toLowerCase().endsWith('.exe') && !['unins000.exe','uninst.exe','uninstall.exe'].includes(f.toLowerCase()));
  if (exe) return { type:'generic', label:'Generic: Binary', eggName:'Generic: Binary', start:{ cmd:exe, args:[] } };
  return { type:'unknown', label:'Unknown', eggName:'Unknown', start:null };
}

// ─── LOAD SERVERS ──────────────────────────────────────────────────────────
function loadServers() {
  if (!fs.existsSync(CONFIG.SERVERS_DIR)) { try { fs.mkdirSync(CONFIG.SERVERS_DIR, { recursive:true }); } catch {} }
  for (const e of fs.readdirSync(CONFIG.SERVERS_DIR, { withFileTypes:true })) {
    if (!e.isDirectory()) continue;
    const id  = e.name.toLowerCase().replace(/[^a-z0-9_-]/g,'_');
    const dir = path.join(CONFIG.SERVERS_DIR, e.name);
    if (!servers[id]) registerServer(id, e.name, dir);
  }
  console.log(`[LOAD] ${Object.keys(servers).length} server(s) from ${CONFIG.SERVERS_DIR}`);
}

function registerServer(id, name, dir) {
  const info = detectType(dir);
  // Apply saved name override
  const d = loadData(id);
  const savedName = d.settings?.name;
  servers[id] = {
    id, name: savedName || name, dir, ...info,
    process: null, logs: [], status: 'offline',
    startedAt: null, pid: null,
    stats: { cpu:0, memoryMB:0, memBytes:0, diskMB:0 },
    node: { name:'local', location:'Local Machine' },
    allocation: { ip:'127.0.0.1', port: d.settings?.port || detectPort(dir) },
    limits: { memory:2048, cpu:100, disk:10240 },
  };
  wsConsole[id] = new Set();
}

function detectPort(dir) {
  try {
    const pf = path.join(dir, 'server.properties');
    if (fs.existsSync(pf)) {
      const m = fs.readFileSync(pf,'utf8').match(/^server-port=(\d+)/m);
      if (m) return parseInt(m[1]);
    }
  } catch {}
  return 25565;
}

function slugifyName(name) {
  return String(name || 'server')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'server';
}

function ensureDir(pth) {
  fs.mkdirSync(pth, { recursive: true });
}

function writeStarterServer(dir, type, name, port) {
  ensureDir(dir);
  const title = name || 'New Server';
  const common = `# ${title}\nGenerated by HazEPanel on ${new Date().toLocaleString()}\n`;
  const nodeLabel = JSON.stringify(title + ' is running\n');
  const nodeListen = JSON.stringify(title + ' listening on ');
  const pyLabel = JSON.stringify(title + ' is running\n');
  if (type === 'node') {
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
      name: slugifyName(title),
      version: '1.0.0',
      private: true,
      main: 'index.js',
      scripts: { start: 'node index.js' }
    }, null, 2));
    const nodeFile = [
      "const http = require('http');",
      `const port = process.env.PORT || ${port || 3000};`,
      'const server = http.createServer((req, res) => {',
      "  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });",
      `  res.end(${nodeLabel});`,
      '});',
      `server.listen(port, () => console.log(${nodeListen} + port));`,
      ''
    ].join(String.fromCharCode(10));
    fs.writeFileSync(path.join(dir, 'index.js'), nodeFile);
    fs.writeFileSync(path.join(dir, 'README.md'), common + 'Edit index.js to build your app.\n');
  } else if (type === 'python') {
    const pyFile = [
      'from http.server import BaseHTTPRequestHandler, HTTPServer',
      'import os',
      `port = int(os.environ.get('PORT', '${port || 8000}'))`,
      'class Handler(BaseHTTPRequestHandler):',
      '    def do_GET(self):',
      '        self.send_response(200)',
      "        self.send_header('Content-type', 'text/plain; charset=utf-8')",
      '        self.end_headers()',
      `        self.wfile.write(${pyLabel}.encode())`,
      "HTTPServer(('0.0.0.0', port), Handler).serve_forever()",
      ''
    ].join(String.fromCharCode(10));
    fs.writeFileSync(path.join(dir, 'app.py'), pyFile);
    fs.writeFileSync(path.join(dir, 'README.md'), common + 'Run with python app.py.\n');
  } else if (type === 'batch') {
    fs.writeFileSync(path.join(dir, 'start.bat'), `@echo off\r\necho ${title} is running\r\npause\r\n`);
    fs.writeFileSync(path.join(dir, 'README.txt'), common + 'Replace this batch file with your real startup command.\r\n');
  } else if (type === 'shell') {
    fs.writeFileSync(path.join(dir, 'start.sh'), `#!/usr/bin/env bash\necho \"${title} is running\"\n`);
    fs.writeFileSync(path.join(dir, 'README.txt'), common + 'Make the script executable before use.\n');
  } else if (type === 'minecraft') {
    fs.writeFileSync(path.join(dir, 'start.bat'), '@echo off\r\njava -Xmx2G -Xms1G -jar server.jar nogui\r\npause\r\n');
    fs.writeFileSync(path.join(dir, 'server.properties'), `server-port=${port || 25565}\nlevel-name=world\nenable-command-block=false\n`);
    fs.writeFileSync(path.join(dir, 'eula.txt'), 'eula=false\n');
    fs.writeFileSync(path.join(dir, 'README.txt'), common + 'Add server.jar, then accept the EULA.\r\n');
  } else {
    fs.writeFileSync(path.join(dir, 'README.txt'), common + 'Add your startup files here.\n');
  }
}
// ─── PROCESS CONTROL ───────────────────────────────────────────────────────
function startServer(id) {
  const s = servers[id];
  if (!s)                    return { ok:false, error:'Server not found' };
  if (s.status === 'online') return { ok:false, error:'Already running' };
  if (!s.start)              return { ok:false, error:'No start command configured' };
  s.status = 'starting'; s.logs = [];
  broadcast(id, { type:'status', status:'starting' });
  broadcastAll({ type:'server_update', server:safeServer(s) });
  let proc;
  try { proc = spawn(s.start.cmd, s.start.args, { cwd:s.dir, shell:false, env:{...process.env, PORT:String(s.allocation?.port || process.env.PORT || '')} } ); }
  catch(e) { s.status='error'; broadcastAll({ type:'server_update', server:safeServer(s) }); return { ok:false, error:e.message }; }
  s.process = proc; s.pid = proc.pid; s.startedAt = Date.now(); s.status = 'online';
  broadcast(id, { type:'status', status:'online' });
  broadcastAll({ type:'server_update', server:safeServer(s) });
  const push = (src, data) => {
    data.toString().split(/\r?\n/).forEach(m => {
      const entry = { t:Date.now(), s:src, m };
      s.logs.push(entry); if (s.logs.length > CONFIG.LOG_LINES) s.logs.shift();
      broadcast(id, { type:'log', ...entry });
    });
  };
  proc.stdout.on('data', d => push('out', d));
  proc.stderr.on('data', d => push('err', d));
  proc.on('close', code => {
    push('sys', `\n[System] Process exited with code ${code}`);
    s.process=null; s.pid=null; s.status='offline'; s.startedAt=null;
    s.stats = { cpu:0, memoryMB:0, memBytes:0, diskMB:0 };
    broadcast(id, { type:'status', status:'offline' });
    broadcastAll({ type:'server_update', server:safeServer(s) });
  });
  proc.on('error', err => { push('sys', `[System] Error: ${err.message}`); s.status='error'; broadcastAll({ type:'server_update', server:safeServer(s) }); });
  return { ok:true };
}

function stopServer(id) {
  const s = servers[id];
  if (!s?.process) return { ok:false, error:'Not running' };
  s.status = 'stopping';
  broadcast(id, { type:'status', status:'stopping' });
  broadcastAll({ type:'server_update', server:safeServer(s) });
  try { require('tree-kill')(s.process.pid, 'SIGTERM'); } catch { s.process.kill(); }
  return { ok:true };
}
function killServer(id) {
  const s = servers[id];
  if (!s?.process) return { ok:false, error:'Not running' };
  try { require('tree-kill')(s.process.pid, 'SIGKILL'); } catch { s.process.kill('SIGKILL'); }
  return { ok:true };
}
function sendCommand(id, cmd) {
  const s = servers[id];
  if (!s?.process || s.status !== 'online') return { ok:false, error:'Not running' };
  try { s.process.stdin.write(cmd + '\n'); broadcast(id, { type:'log', t:Date.now(), s:'in', m:`> ${cmd}` }); return { ok:true }; }
  catch(e) { return { ok:false, error:e.message }; }
}

// ─── STATS ──────────────────────────────────────────────────────────────────
async function pollStats() {
  let pu; try { pu = require('pidusage'); } catch { return; }
  for (const s of Object.values(servers)) {
    if (s.status !== 'online' || !s.pid) continue;
    try {
      const st = await pu(s.pid);
      s.stats = { cpu: Math.round(st.cpu*10)/10, memoryMB: Math.round(st.memory/1024/1024*10)/10, memBytes: st.memory, diskMB: 0 };
      broadcast(s.id, { type:'stats', stats:s.stats });
      broadcastAll({ type:'stats_update', id:s.id, stats:s.stats });
    } catch {}
  }
}
setInterval(pollStats, CONFIG.STATS_INTERVAL);

// ─── BACKUP ────────────────────────────────────────────────────────────────
function createBackup(sourceDir, destFile) {
  return new Promise((resolve, reject) => {
    const isWin = process.platform === 'win32';
    let cmd, args;
    if (isWin) {
      cmd  = 'powershell';
      args = ['-NoProfile','-NonInteractive','-Command',
              `Compress-Archive -LiteralPath '${sourceDir}' -DestinationPath '${destFile}' -Force`];
    } else {
      cmd  = 'tar';
      args = ['-czf', destFile, '-C', sourceDir, '.'];
    }
    const p = spawn(cmd, args, { shell: false });
    p.on('close', c => c === 0 ? resolve() : reject(new Error(`Backup failed (exit ${c})`)));
    p.on('error', reject);
  });
}

function restoreBackup(sourceFile, destDir) {
  return new Promise((resolve, reject) => {
    const isWin = process.platform === 'win32';
    let cmd, args;
    if (isWin) {
      cmd  = 'powershell';
      args = ['-NoProfile','-NonInteractive','-Command',
              `Expand-Archive -LiteralPath '${sourceFile}' -DestinationPath '${destDir}' -Force`];
    } else {
      cmd  = 'tar';
      args = ['-xzf', sourceFile, '-C', destDir];
    }
    const p = spawn(cmd, args, { shell: false });
    p.on('close', c => c === 0 ? resolve() : reject(new Error(`Restore failed (exit ${c})`)));
    p.on('error', reject);
  });
}

// ─── SCHEDULES ─────────────────────────────────────────────────────────────
function matchCron(expr, date) {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return false;
  const [min, hour, dom, mon, dow] = parts;
  const match = (field, val) => {
    if (field === '*') return true;
    if (field.includes('/')) { const [r,s]=field.split('/'); return r==='*' ? val%parseInt(s)===0 : val>=parseInt(r)&&(val-parseInt(r))%parseInt(s)===0; }
    if (field.includes(',')) return field.split(',').some(f => match(f, val));
    if (field.includes('-')) { const [a,b]=field.split('-').map(Number); return val>=a&&val<=b; }
    return parseInt(field)===val;
  };
  return match(min,date.getMinutes()) && match(hour,date.getHours()) &&
         match(dom,date.getDate())    && match(mon,date.getMonth()+1) &&
         match(dow,date.getDay());
}

function runScheduleAction(serverId, sch) {
  const s  = servers[serverId];
  const now = Date.now();
  const d  = loadData(serverId);
  const idx = (d.schedules||[]).findIndex(x => x.id===sch.id);
  if (idx !== -1) { d.schedules[idx].lastRun = now; saveData(serverId, d); }
  broadcast(serverId, { type:'log', t:now, s:'sys', m:`[Schedule] Running "${sch.name}"` });
  switch (sch.action) {
    case 'command':
      if (s && sch.command) sendCommand(serverId, sch.command);
      break;
    case 'backup': {
      const bdir = path.join(BACKUP_DIR, serverId);
      if (!fs.existsSync(bdir)) fs.mkdirSync(bdir, { recursive:true });
      const name = `scheduled-${new Date(now).toISOString().replace(/[:.]/g,'-').slice(0,19)}`;
      const ext  = process.platform==='win32' ? '.zip' : '.tar.gz';
      const fn   = name + ext;
      const dest = path.join(bdir, fn);
      const bk   = { id:'bk'+uid(), name, filename:fn, status:'in_progress', created:now };
      const d2   = loadData(serverId);
      d2.backups = d2.backups||[]; d2.backups.push(bk); saveData(serverId, d2);
      if (s) createBackup(s.dir, dest).then(()=>{ bk.status='complete'; const d3=loadData(serverId); const bi=d3.backups.findIndex(b=>b.id===bk.id); if(bi!==-1){d3.backups[bi]=bk;saveData(serverId,d3);} broadcast(serverId,{type:'backup_update',backup:bk}); }).catch(()=>{ bk.status='failed'; });
      break;
    }
    case 'restart':
      if (s?.status==='online') { stopServer(serverId); setTimeout(()=>startServer(serverId), 3500); }
      break;
    case 'kill':
      killServer(serverId);
      break;
  }
}

// Run schedule check every minute
setInterval(() => {
  const now = new Date();
  for (const id of Object.keys(servers)) {
    const d = loadData(id);
    for (const sch of (d.schedules||[])) {
      if (!sch.enabled) continue;
      if (matchCron(sch.cron, now)) runScheduleAction(id, sch);
    }
  }
}, 60000);

// ─── WS HELPERS ────────────────────────────────────────────────────────────
const wsSend = (ws, p) => { try { if (ws.readyState===WebSocket.OPEN) ws.send(JSON.stringify(p)); } catch {} };
function broadcast(id, p)  { wsConsole[id]?.forEach(ws => wsSend(ws, p)); }
function broadcastAll(p)   { broadcastWs.forEach(ws => wsSend(ws, p)); }

function safeServer(s) {
  return { id:s.id, name:s.name, type:s.type, label:s.label, eggName:s.eggName,
           status:s.status, pid:s.pid, startedAt:s.startedAt, dir:s.dir,
           stats:s.stats, node:s.node, allocation:s.allocation, limits:s.limits,
           start:s.start };
}

// ─── EXPRESS ───────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(requireAuth);
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const d = loadPanelData();
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!d.auth || d.auth.username !== username || !verifyPassword(password, d.auth.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = issueSession(d.auth.username);
  res.setHeader('Set-Cookie', authCookie(token));
  res.json({ ok: true, user: { username: d.auth.username, displayName: d.account?.displayName || d.auth.username, email: d.account?.email || '' } });
});
app.post('/api/auth/logout', (req, res) => {
  const token = parseCookies(req).haze_session;
  clearSession(token);
  res.setHeader('Set-Cookie', 'haze_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/auth/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ ok: true, user });
});
app.use(express.static(path.join(__dirname, 'public')));
app.get('/server/:id', (_, res) => res.sendFile(path.join(__dirname, 'public', 'console.html')));

// Core
app.get('/api/servers',             (_, res) => res.json(Object.values(servers).map(safeServer)));
app.get('/api/servers/:id',         (req, res) => { const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'}); res.json({...safeServer(s),logs:s.logs.slice(-400)}); });
app.post('/api/servers/:id/start',  (req, res) => res.json(startServer(req.params.id)));
app.post('/api/servers/:id/stop',   (req, res) => res.json(stopServer(req.params.id)));
app.post('/api/servers/:id/kill',   (req, res) => res.json(killServer(req.params.id)));
app.post('/api/servers/:id/restart', async (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  if (s.status==='online') { stopServer(req.params.id); await new Promise(r=>setTimeout(r,2500)); }
  res.json(startServer(req.params.id));
});
app.post('/api/servers/:id/command', (req, res) => { const {command}=req.body; if(!command?.trim()) return res.status(400).json({error:'No command'}); res.json(sendCommand(req.params.id, command)); });
app.delete('/api/servers/:id/logs', (req, res) => { const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'}); s.logs=[]; res.json({ok:true}); });
app.post('/api/rescan', (_, res) => {
  if (fs.existsSync(CONFIG.SERVERS_DIR)) {
    for (const e of fs.readdirSync(CONFIG.SERVERS_DIR, { withFileTypes:true })) {
      if (!e.isDirectory()) continue;
      const id=e.name.toLowerCase().replace(/[^a-z0-9_-]/g,'_');
      if (!servers[id]) registerServer(id, e.name, path.join(CONFIG.SERVERS_DIR, e.name));
    }
  }
  res.json(Object.values(servers).map(safeServer));
});

app.post('/api/servers/create', (req, res) => {
  try {
    const rawName = String(req.body?.name || '').trim();
    if (!rawName) return res.status(400).json({ error: 'Server name required' });
    const type = String(req.body?.type || 'node').toLowerCase();
    const folderId = slugifyName(req.body?.id || rawName);
    const baseDir = CONFIG.SERVERS_DIR;
    const port = parseInt(req.body?.port || 3000, 10);
    ensureDir(baseDir);
    const dir = path.join(baseDir, folderId);
    if (fs.existsSync(dir)) return res.status(409).json({ error: 'Server folder already exists' });
    ensureDir(dir);
    writeStarterServer(dir, type, rawName, port);
    const d = loadData(folderId);
    d.settings = { ...(d.settings || {}), name: rawName, description: req.body?.description || '', port };
    saveData(folderId, d);
    registerServer(folderId, rawName, dir);
    if (servers[folderId]) servers[folderId].allocation.port = port;
    broadcastAll({ type: 'server_update', server: safeServer(servers[folderId]) });
    res.json({ ok: true, server: safeServer(servers[folderId]) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Files
const guardPath = (base, sub) => { const p=path.resolve(base,sub||''); if(!p.startsWith(path.resolve(base))) throw new Error('Forbidden'); return p; };
app.get('/api/servers/:id/files', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  try {
    const t=guardPath(s.dir, req.query.path||'');
    const items=fs.readdirSync(t,{withFileTypes:true}).map(e=>{
      let size=null,mtime=null;
      try{const st=fs.statSync(path.join(t,e.name));size=st.size;mtime=st.mtimeMs;}catch{}
      return {name:e.name,isDir:e.isDirectory(),size,mtime};
    }).sort((a,b)=>a.isDir!==b.isDir?(a.isDir?-1:1):a.name.localeCompare(b.name));
    res.json({path:req.query.path||'',items});
  } catch(e){res.status(e.message==='Forbidden'?403:500).json({error:e.message});}
});
app.get('/api/servers/:id/file', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  try { const fp=guardPath(s.dir,req.query.path||''); const st=fs.statSync(fp); if(st.size>2e6) return res.status(413).json({error:'File too large'}); res.json({content:fs.readFileSync(fp,'utf8')}); }
  catch(e){res.status(500).json({error:e.message});}
});
app.put('/api/servers/:id/file', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  try { fs.writeFileSync(guardPath(s.dir,req.query.path||''), req.body.content||''); res.json({ok:true}); }
  catch(e){res.status(500).json({error:e.message});}
});
app.delete('/api/servers/:id/file', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  try { const fp=guardPath(s.dir,req.query.path||''); const st=fs.statSync(fp); if(st.isDirectory()) fs.rmdirSync(fp,{recursive:true}); else fs.unlinkSync(fp); res.json({ok:true}); }
  catch(e){res.status(500).json({error:e.message});}
});
app.post('/api/servers/:id/mkdir', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  try { fs.mkdirSync(guardPath(s.dir, req.body.path||''), { recursive:true }); res.json({ok:true}); }
  catch(e){ res.status(500).json({error:e.message}); }
});
app.post('/api/servers/:id/upload', (req, res) => {
  const s = servers[req.params.id]; if (!s) return res.status(404).json({error:'Not found'});
  try {
    const dest = guardPath(s.dir, req.query.path || '');
    const ct = req.headers['content-type'] || '';
    const bnd = ct.split('boundary=')[1];
    if (!bnd) return res.status(400).json({error:'No boundary'});
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const buf = Buffer.concat(chunks);
        const sep = Buffer.from('\r\n--' + bnd);
        let saved = 0, pos = buf.indexOf('--' + bnd);
        while (pos !== -1) {
          const start = buf.indexOf('\r\n\r\n', pos);
          const hdr = buf.slice(pos, start).toString();
          const nm = hdr.match(/filename="([^"]+)"/);
          if (nm) {
            const end = buf.indexOf(sep, start + 4);
            const content = end === -1 ? buf.slice(start + 4) : buf.slice(start + 4, end);
            fs.writeFileSync(path.join(dest, nm[1]), content);
            saved++;
          }
          pos = buf.indexOf('--' + bnd, pos + 4);
          if (buf.slice(pos, pos + bnd.length + 4).includes('--\r\n')) break;
        }
        res.json({ok: true, saved});
      } catch(e) { res.status(500).json({error: e.message}); }
    });
  } catch(e) { res.status(500).json({error: e.message}); }
});

// Databases
app.get('/api/servers/:id/databases', (req, res) => { const d=loadData(req.params.id); res.json(d.databases||[]); });
app.post('/api/servers/:id/databases', (req, res) => {
  const d=loadData(req.params.id);
  const db={ id:'db'+uid(), name:req.body.name, host:req.body.host||'127.0.0.1', port:req.body.port||3306,
              username:'u_'+Math.random().toString(36).slice(2,8),
              password:Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2),
              connections_from:req.body.connections_from||'%', max_connections:req.body.max_connections||0, created:Date.now() };
  d.databases=d.databases||[]; d.databases.push(db); saveData(req.params.id,d); res.json(db);
});
app.delete('/api/servers/:id/databases/:dbid', (req, res) => {
  const d=loadData(req.params.id); d.databases=(d.databases||[]).filter(x=>x.id!==req.params.dbid);
  saveData(req.params.id,d); res.json({ok:true});
});

// Schedules
app.get('/api/servers/:id/schedules', (req, res) => { const d=loadData(req.params.id); res.json(d.schedules||[]); });
app.post('/api/servers/:id/schedules', (req, res) => {
  const d=loadData(req.params.id);
  const sch={ id:'sch'+uid(), name:req.body.name, cron:req.body.cron, action:req.body.action,
               command:req.body.command||'', enabled:req.body.enabled!==false, lastRun:null, created:Date.now() };
  d.schedules=d.schedules||[]; d.schedules.push(sch); saveData(req.params.id,d); res.json(sch);
});
app.put('/api/servers/:id/schedules/:sid', (req, res) => {
  const d=loadData(req.params.id); const idx=(d.schedules||[]).findIndex(s=>s.id===req.params.sid);
  if(idx===-1) return res.status(404).json({error:'Not found'});
  d.schedules[idx]={...d.schedules[idx],...req.body}; saveData(req.params.id,d); res.json(d.schedules[idx]);
});
app.delete('/api/servers/:id/schedules/:sid', (req, res) => {
  const d=loadData(req.params.id); d.schedules=(d.schedules||[]).filter(s=>s.id!==req.params.sid);
  saveData(req.params.id,d); res.json({ok:true});
});
app.post('/api/servers/:id/schedules/:sid/run', (req, res) => {
  const d=loadData(req.params.id); const sch=(d.schedules||[]).find(s=>s.id===req.params.sid);
  if(!sch) return res.status(404).json({error:'Not found'});
  runScheduleAction(req.params.id, sch); res.json({ok:true});
});

// Users
app.get('/api/servers/:id/users', (req, res) => { const d=loadData(req.params.id); res.json(d.users||[]); });
app.post('/api/servers/:id/users', (req, res) => {
  const d=loadData(req.params.id);
  const user={ id:'usr'+uid(), email:req.body.email, username:req.body.email.split('@')[0],
                permissions:req.body.permissions||['console.read','files.read'], created:Date.now() };
  d.users=d.users||[]; d.users.push(user); saveData(req.params.id,d); res.json(user);
});
app.put('/api/servers/:id/users/:uid2', (req, res) => {
  const d=loadData(req.params.id); const idx=(d.users||[]).findIndex(u=>u.id===req.params.uid2);
  if(idx===-1) return res.status(404).json({error:'Not found'});
  d.users[idx]={...d.users[idx],...req.body}; saveData(req.params.id,d); res.json(d.users[idx]);
});
app.delete('/api/servers/:id/users/:uid2', (req, res) => {
  const d=loadData(req.params.id); d.users=(d.users||[]).filter(u=>u.id!==req.params.uid2);
  saveData(req.params.id,d); res.json({ok:true});
});

// Backups
app.get('/api/servers/:id/backups', (req, res) => {
  const d=loadData(req.params.id);
  const bdir=path.join(BACKUP_DIR,req.params.id);
  const bk=(d.backups||[]).map(b=>{ const fp=path.join(bdir,b.filename); return fs.existsSync(fp)?{...b,size:fs.statSync(fp).size}:b; });
  res.json(bk);
});
app.post('/api/servers/:id/backups', async (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const bdir=path.join(BACKUP_DIR,req.params.id); if(!fs.existsSync(bdir)) fs.mkdirSync(bdir,{recursive:true});
  const name=req.body.name||`backup-${new Date().toISOString().replace(/[:.]/g,'-').slice(0,19)}`;
  const ext=process.platform==='win32'?'.zip':'.tar.gz';
  const fn=name+ext; const dest=path.join(bdir,fn);
  const bk={ id:'bk'+uid(), name, filename:fn, status:'in_progress', created:Date.now(), size:null };
  const d=loadData(req.params.id); d.backups=d.backups||[]; d.backups.push(bk); saveData(req.params.id,d);
  res.json(bk);
  createBackup(s.dir,dest).then(()=>{
    bk.status='complete'; bk.completedAt=Date.now();
    const d2=loadData(req.params.id); const bi=d2.backups.findIndex(b=>b.id===bk.id);
    if(bi!==-1){d2.backups[bi]=bk;saveData(req.params.id,d2);}
    broadcast(req.params.id,{type:'backup_update',backup:bk});
  }).catch(err=>{
    bk.status='failed';
    const d2=loadData(req.params.id); const bi=d2.backups.findIndex(b=>b.id===bk.id);
    if(bi!==-1){d2.backups[bi]=bk;saveData(req.params.id,d2);}
    broadcast(req.params.id,{type:'backup_update',backup:bk});
  });
});
app.post('/api/servers/:id/backups/:bid/restore', async (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  if(s.status==='online') return res.status(400).json({error:'Stop the server before restoring a backup'});
  const d=loadData(req.params.id); const bk=(d.backups||[]).find(b=>b.id===req.params.bid);
  if(!bk) return res.status(404).json({error:'Backup not found'});
  const fp=path.join(BACKUP_DIR,req.params.id,bk.filename);
  if(!fs.existsSync(fp)) return res.status(404).json({error:'Backup file not found on disk'});
  res.json({ok:true,message:'Restore started in background'});
  restoreBackup(fp,s.dir).then(()=>{
    broadcast(req.params.id,{type:'log',t:Date.now(),s:'sys',m:`[Restore] Backup "${bk.name}" restored successfully`});
  }).catch(err=>{
    broadcast(req.params.id,{type:'log',t:Date.now(),s:'err',m:`[Restore] Failed: ${err.message}`});
  });
});
app.get('/api/servers/:id/backups/:bid/download', (req, res) => {
  const d=loadData(req.params.id); const bk=(d.backups||[]).find(b=>b.id===req.params.bid);
  if(!bk) return res.status(404).json({error:'Not found'});
  const fp=path.join(BACKUP_DIR,req.params.id,bk.filename);
  if(!fs.existsSync(fp)) return res.status(404).json({error:'File not found'});
  res.download(fp, bk.filename);
});
app.delete('/api/servers/:id/backups/:bid', (req, res) => {
  const d=loadData(req.params.id); const bk=(d.backups||[]).find(b=>b.id===req.params.bid);
  if(bk){ const fp=path.join(BACKUP_DIR,req.params.id,bk.filename); if(fs.existsSync(fp)) try{fs.unlinkSync(fp);}catch{} }
  d.backups=(d.backups||[]).filter(b=>b.id!==req.params.bid); saveData(req.params.id,d); res.json({ok:true});
});

// Network
app.get('/api/servers/:id/network', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const d=loadData(req.params.id);
  const allocs=d.allocations?.length ? d.allocations :
    [{ id:'alloc_primary', ip:s.allocation.ip||'127.0.0.1', port:s.allocation.port||25565, primary:true, notes:'' }];
  res.json({ allocations:allocs, stats:s.stats });
});
app.post('/api/servers/:id/network/allocations', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const d=loadData(req.params.id);
  const alloc={ id:'alloc'+uid(), ip:req.body.ip||'127.0.0.1', port:req.body.port, primary:false, notes:req.body.notes||'' };
  d.allocations=d.allocations||[{ id:'alloc_primary', ip:s.allocation.ip||'127.0.0.1', port:s.allocation.port||25565, primary:true, notes:'' }];
  d.allocations.push(alloc); saveData(req.params.id,d); res.json(alloc);
});
app.delete('/api/servers/:id/network/allocations/:aid', (req, res) => {
  const d=loadData(req.params.id); d.allocations=(d.allocations||[]).filter(a=>a.id!==req.params.aid);
  saveData(req.params.id,d); res.json({ok:true});
});

// Startup
app.get('/api/servers/:id/startup', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const d=loadData(req.params.id);
  let envVars=[];
  if ((s.type==='minecraft'||s.type==='bedrock') && fs.existsSync(path.join(s.dir,'server.properties'))) {
    try {
      const lines=fs.readFileSync(path.join(s.dir,'server.properties'),'utf8').split('\n');
      for(const line of lines){
        const t=line.trim(); if(t.startsWith('#')||!t.includes('=')) continue;
        const [k,...vs]=t.split('='); envVars.push({key:k.trim(),value:vs.join('=').trim(),source:'server.properties'});
      }
    } catch {}
  } else {
    envVars=d.startup?.envVars||[];
  }
  res.json({ startup:s.start?`${s.start.cmd} ${(s.start.args||[]).join(' ')}`:'', image:'local/'+s.type, eggName:s.eggName, envVars });
});
app.put('/api/servers/:id/startup', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const d=loadData(req.params.id);
  if(req.body.envVars && (s.type==='minecraft'||s.type==='bedrock')) {
    const pf=path.join(s.dir,'server.properties');
    if(fs.existsSync(pf)){
      try {
        let content=fs.readFileSync(pf,'utf8');
        for(const ev of req.body.envVars){
          const re=new RegExp(`^${ev.key}=.*`,'m');
          if(re.test(content)) content=content.replace(re,`${ev.key}=${ev.value}`);
        }
        fs.writeFileSync(pf,content);
        // update port in memory
        const pm=content.match(/^server-port=(\d+)/m); if(pm) s.allocation.port=parseInt(pm[1]);
      } catch {}
    }
  } else if(req.body.envVars) {
    d.startup={ ...(d.startup||{}), envVars:req.body.envVars };
  }
  if(req.body.startupCommand) {
    const parts=req.body.startupCommand.trim().split(/\s+/);
    s.start={ cmd:parts[0], args:parts.slice(1) };
  }
  saveData(req.params.id,d); res.json({ok:true});
});

// Settings
app.get('/api/servers/:id/settings', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  const d=loadData(req.params.id);
  res.json({ name:s.name, description:d.settings?.description||'', sftp:{ host:'127.0.0.1:2022', username:req.params.id } });
});
app.put('/api/servers/:id/settings', (req, res) => {
  const s=servers[req.params.id]; if(!s) return res.status(404).json({error:'Not found'});
  if(req.body.name) s.name=req.body.name;
  const d=loadData(req.params.id); d.settings={...(d.settings||{}),...req.body}; saveData(req.params.id,d);
  broadcastAll({type:'server_update',server:safeServer(s)});
  res.json({ok:true});
});

// System
app.get('/api/system', (_, res) => {
  const total=os.totalmem(),free=os.freemem();
  res.json({ hostname:os.hostname(), platform:os.platform(), arch:os.arch(),
             cpuModel:os.cpus()[0]?.model||'Unknown', cpuCount:os.cpus().length,
             totalMem:total, freeMem:free, usedMem:total-free, uptime:os.uptime(),
             serversDir:CONFIG.SERVERS_DIR, serverCount:Object.keys(servers).length });
});

// ─── WEBSOCKET ──────────────────────────────────────────────────────────────
const httpServer = http.createServer(app);
const wss = new WebSocket.Server({ server:httpServer });
wss.on('connection', (ws, req) => {
  const url=new URL(req.url,'http://localhost');
  const sid=url.searchParams.get('server');
  const type=url.searchParams.get('type')||'console';
  if (type==='dashboard'||sid==='_all') {
    broadcastWs.add(ws); ws.on('close',()=>broadcastWs.delete(ws)); return;
  }
  if (sid && wsConsole[sid]) {
    wsConsole[sid].add(ws);
    servers[sid]?.logs.slice(-200).forEach(l=>wsSend(ws,{type:'log',...l}));
    wsSend(ws,{type:'status',status:servers[sid]?.status||'offline'});
    wsSend(ws,{type:'stats',stats:servers[sid]?.stats});
    ws.on('close',()=>wsConsole[sid]?.delete(ws));
  }
});

// ─── BOOT ───────────────────────────────────────────────────────────────────
loadServers();
httpServer.listen(CONFIG.PORT, () => {
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║  🦕  PteroPanel v2 — Ready           ║`);
  console.log(`╠══════════════════════════════════════╣`);
  console.log(`║  http://localhost:${CONFIG.PORT}               ║`);
  console.log(`║  Dir: ${CONFIG.SERVERS_DIR.slice(0,29).padEnd(29)} ║`);
  console.log(`╚══════════════════════════════════════╝\n`);
});

// ─── ACCOUNT & ADMIN APIS ──────────────────────────────────────────────────
const PANEL_DATA_FILE = path.join(DATA_DIR, '_panel.json');

function loadPanelData() {
  if (!fs.existsSync(PANEL_DATA_FILE)) return {
    account: { username:'admin', email:'admin@local', displayName:'Administrator', apiKeys:[], activityLog:[] },
    auth: defaultAuth(),
    panelSettings: { panelName:'PteroPanel', serversDir: CONFIG.SERVERS_DIR, port: CONFIG.PORT, theme:'dark', language:'en' },
    nodes: [{ id:'node_local', name:'Local Machine', fqdn:'127.0.0.1', scheme:'http', port:8080, memory:os.totalmem(), disk:0, online:true, public:false, location:'Local', description:'Auto-detected local node' }]
  };
  try {
    const d = JSON.parse(fs.readFileSync(PANEL_DATA_FILE,'utf8'));
    if (!d.account) d.account = { username:'admin', email:'admin@local', displayName:'Administrator', apiKeys:[], activityLog:[] };
    if (!d.auth || !d.auth.username || !d.auth.password) d.auth = defaultAuth();
    if (!d.panelSettings) d.panelSettings = { panelName:'PteroPanel', serversDir: CONFIG.SERVERS_DIR, port: CONFIG.PORT, theme:'dark', language:'en' };
    if (!d.nodes) d.nodes = [{ id:'node_local', name:'Local Machine', fqdn:'127.0.0.1', scheme:'http', port:8080, memory:os.totalmem(), disk:0, online:true, public:false, location:'Local', description:'Auto-detected local node' }];
    return d;
  }
  catch { return { account: { username:'admin', email:'admin@local', displayName:'Administrator', apiKeys:[], activityLog:[] }, auth: defaultAuth(), panelSettings: { panelName:'PteroPanel', serversDir: CONFIG.SERVERS_DIR, port: CONFIG.PORT, theme:'dark', language:'en' }, nodes: [{ id:'node_local', name:'Local Machine', fqdn:'127.0.0.1', scheme:'http', port:8080, memory:os.totalmem(), disk:0, online:true, public:false, location:'Local', description:'Auto-detected local node' }] }; }
}
function savePanelData(d) { fs.writeFileSync(PANEL_DATA_FILE, JSON.stringify(d, null, 2)); }

// Account
app.get('/account', (_, res) => res.sendFile(path.join(__dirname,'public','account.html')));
app.get('/api/account', (_, res) => {
  const d = loadPanelData();
  const { apiKeys, ...safe } = d.account;
  res.json({ ...safe, apiKeyCount: apiKeys.length });
});
app.put('/api/account', (req, res) => {
  const d = loadPanelData();
  const { username, email, displayName } = req.body;
  if (username) { d.account.username = username; d.auth.username = username; }
  if (email)    d.account.email    = email;
  if (displayName) d.account.displayName = displayName;
  d.account.activityLog = d.account.activityLog || [];
  d.account.activityLog.unshift({ t: Date.now(), action: 'Account updated', ip: '127.0.0.1' });
  if (d.account.activityLog.length > 50) d.account.activityLog = d.account.activityLog.slice(0, 50);
  savePanelData(d); res.json({ ok:true });
});
app.put('/api/account/password', (req, res) => {
  const { current, newPassword } = req.body;
  if (!current || !newPassword) return res.status(400).json({ error:'Both current and new password required' });
  if (newPassword.length < 8) return res.status(400).json({ error:'Password must be at least 8 characters' });
  const d = loadPanelData();
  if (!d.auth || !verifyPassword(current, d.auth.password)) return res.status(401).json({ error:'Current password is incorrect' });
  d.auth.password = hashPassword(newPassword);
  d.account.activityLog = d.account.activityLog || [];
  d.account.activityLog.unshift({ t: Date.now(), action: 'Password changed', ip: '127.0.0.1' });
  savePanelData(d);
  res.json({ ok:true });
});
app.get('/api/account/apikeys', (_, res) => {
  const d = loadPanelData();
  res.json((d.account.apiKeys || []).map(k => ({ ...k, token: k.token.slice(0,8) + '…' })));
});
app.post('/api/account/apikeys', (req, res) => {
  const d = loadPanelData();
  const key = { id:'key'+Math.random().toString(36).slice(2,10), description: req.body.description||'Unnamed Key',
                 token: 'ptlc_' + require('crypto').randomBytes(20).toString('hex'),
                 created: Date.now(), lastUsed: null };
  d.account.apiKeys = d.account.apiKeys||[]; d.account.apiKeys.push(key); savePanelData(d);
  res.json(key);
});
app.delete('/api/account/apikeys/:kid', (req, res) => {
  const d = loadPanelData();
  d.account.apiKeys = (d.account.apiKeys||[]).filter(k => k.id !== req.params.kid);
  savePanelData(d); res.json({ ok:true });
});
app.get('/api/account/activity', (_, res) => {
  const d = loadPanelData();
  res.json(d.account.activityLog || []);
});

// Admin
app.get('/admin', (_, res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/api/admin/settings', (_, res) => {
  const d = loadPanelData();
  res.json(d.panelSettings || {});
});
app.put('/api/admin/settings', (req, res) => {
  const d = loadPanelData();
  d.panelSettings = { ...(d.panelSettings||{}), ...req.body };
  if (req.body.serversDir) CONFIG.SERVERS_DIR = req.body.serversDir;
  savePanelData(d); res.json({ ok:true });
});
app.get('/api/admin/overview', (_, res) => {
  const total  = os.totalmem(), free = os.freemem();
  const srvList = Object.values(servers);
  res.json({
    system: { hostname:os.hostname(), platform:os.platform(), uptime:os.uptime(),
              cpuCount:os.cpus().length, cpuModel:os.cpus()[0]?.model||'',
              totalMem:total, freeMem:free, usedMem:total-free },
    servers: { total:srvList.length, online:srvList.filter(s=>s.status==='online').length,
               offline:srvList.filter(s=>s.status==='offline').length,
               starting:srvList.filter(s=>s.status==='starting').length },
    list: srvList.map(safeServer)
  });
});
app.get('/api/admin/nodes', (_, res) => {
  const d = loadPanelData();
  const nodes = (d.nodes||[]).map(n => ({ ...n, memory: os.totalmem(), freeMemory: os.freemem(), uptime: os.uptime() }));
  res.json(nodes);
});
app.post('/api/admin/nodes', (req, res) => {
  const d = loadPanelData();
  const node = { id:'node_'+Math.random().toString(36).slice(2,8), name:req.body.name, fqdn:req.body.fqdn||'127.0.0.1',
                  scheme:req.body.scheme||'http', port:req.body.port||8080,
                  location:req.body.location||'Local', description:req.body.description||'', online:false, public:false };
  d.nodes = d.nodes||[]; d.nodes.push(node); savePanelData(d); res.json(node);
});
app.delete('/api/admin/nodes/:nid', (req, res) => {
  const d = loadPanelData(); d.nodes = (d.nodes||[]).filter(n=>n.id!==req.params.nid);
  savePanelData(d); res.json({ ok:true });
});
