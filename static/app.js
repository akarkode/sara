const STATE = {
    scanning: false, scanId: null, domain: null, timerStart: 0, timerInterval: null, eventSource: null,
    selectedTools: new Set(), toolsMeta: {}, wordlistMode: 'default', store: {},
    stats: { liveHosts: 0, risks: 0, totalSteps: 0, completedSteps: 0 },
    currentView: 'scan'
};

const $ = id => document.getElementById(id);

function showView(view) {
    STATE.currentView = view;
    $('recon-view').style.display = view === 'scan' ? 'block' : 'none';
    $('history-view').style.display = view === 'history' ? 'block' : 'none';
    $('nav-scan').classList.toggle('active', view === 'scan');
    $('nav-history').classList.toggle('active', view === 'history');
    $('view-title').textContent = view === 'scan' ? 'Infrastructure Reconnaissance' : 'Mission History';
    if (view === 'history') loadHistory();
}

let CURRENT_INSTALL_ID = null;

async function loadTools() {
    try {
        const r = await fetch('/tools');
        const d = await r.json();
        STATE.toolsMeta = d.tools;
        const os = d.os;
        
        // Display OS Info
        const osText = os.distro || `${os.system} ${os.release}`;
        $('os-display').textContent = osText;
        $('os-display').title = `${os.system} ${os.release} (${os.machine})`;

        const defs = ['httpx'];
        const grid = $('toolsGrid');
        grid.innerHTML = '';
        
        Object.entries(STATE.toolsMeta).sort((a, b) => a[1].order - b[1].order).forEach(([id, info]) => {
            const available = info.available;
            if (available && defs.includes(id)) STATE.selectedTools.add(id);
            
            const el = document.createElement('div');
            el.className = 'tool-chip' + (STATE.selectedTools.has(id) ? ' active' : '') + (!available ? ' missing' : '');
            el.onclick = () => { if (!STATE.scanning && available) toggleTool(id, el); };
            
            el.innerHTML = `
                <div class="chip-header">
                    <span class="chip-name">${info.name || id}</span>
                    ${available ? '<div class="check-circle"></div>' : '<span class="missing-tag">Missing</span>'}
                </div>
                ${!available ? `<button class="install-btn" data-id="${id}" onclick="event.stopPropagation(); installTool('${id}', this)">Install</button>` : ''}
            `;
            grid.appendChild(el);
        });
    } catch (e) { console.error('Failed to load tools:', e); }
}

async function installTool(id, btn, password = null) {
    if (!btn) btn = document.querySelector(`.install-btn[data-id="${id}"]`);
    const originalText = btn ? btn.textContent : 'Install';
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Installing...';
    }
    
    try {
        const res = await fetch(`/install-tool/${id}`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });
        const data = await res.json();
        
        if (data.status === 'success') {
            logTerminal(`<b style="color:var(--green)">Tool ${id} installed successfully.</b>`);
            closePasswordModal();
            loadTools(); 
        } else if (data.code === 'SUDO_PASSWORD_REQUIRED' || data.code === 'INCORRECT_PASSWORD') {
            if (data.code === 'INCORRECT_PASSWORD') alert('Incorrect password, please try again.');
            CURRENT_INSTALL_ID = id;
            showPasswordModal();
            if (btn) {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        } else {
            alert(data.detail || 'Installation failed');
            if (btn) {
                btn.textContent = originalText;
                btn.disabled = false;
            }
        }
    } catch (e) {
        alert(e.message);
        if (btn) {
            btn.textContent = originalText;
            btn.disabled = false;
        }
    }
}

function showPasswordModal() {
    $('passwordModal').style.display = 'flex';
    $('sudoPassword').value = '';
    $('sudoPassword').focus();
}

function closePasswordModal() {
    $('passwordModal').style.display = 'none';
}

$('confirmSudoBtn').onclick = () => {
    const pw = $('sudoPassword').value;
    if (!pw) return alert('Password required');
    installTool(CURRENT_INSTALL_ID, null, pw);
};

$('sudoPassword').onkeyup = e => {
    if (e.key === 'Enter') $('confirmSudoBtn').click();
};

function toggleTool(id, el) {
    if (STATE.selectedTools.has(id)) {
        STATE.selectedTools.delete(id);
        el.classList.remove('active');
    } else {
        STATE.selectedTools.add(id);
        el.classList.add('active');
    }
}

function setWl(m) {
    STATE.wordlistMode = m;
    $('wlDef').classList.toggle('active', m === 'default');
    $('wlCust').classList.toggle('active', m === 'custom');
    $('wlCustArea').style.display = m === 'custom' ? 'block' : 'none';
}

function handleWlSelect(input) {
    const file = input.files[0];
    if (file) $('wlFileName').textContent = file.name;
}

async function uploadWordlist(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch('/upload-wordlist', { method: 'POST', body: formData });
    if (!res.ok) throw new Error('Failed to upload wordlist');
    const data = await res.json();
    return data.path;
}

async function startScan() {
    const domain = $('domainInput').value.trim();
    if (!domain || STATE.scanning) return;
    if (!STATE.selectedTools.size) { alert('Select at least one sub-engine'); return; }
    
    let wl = 'default';
    if (STATE.wordlistMode === 'custom') {
        const file = $('wlFileInput').files[0];
        if (!file) { alert('Please select a .txt wordlist file'); return; }
        try {
            setScanUI(true);
            logTerminal('Uploading custom wordlist...');
            wl = await uploadWordlist(file);
        } catch (e) {
            alert(e.message);
            setScanUI(false);
            return;
        }
    }
    
    setScanUI(true);
    clearResults();
    logTerminal(`Initiating scan for target: ${domain}`);
    
    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, tools: [...STATE.selectedTools], wordlist: wl })
        });
        
        if (!res.ok) {
            const e = await res.json();
            alert(e.detail || 'Scan failed to initialize');
            setScanUI(false);
            return;
        }
        
        const d = await res.json();
        STATE.scanId = d.scan_id;
        STATE.domain = domain;
        startTimer();
        connectSSE(STATE.scanId);
    } catch (e) {
        alert(e.message);
        setScanUI(false);
    }
}

function setScanUI(on) {
    STATE.scanning = on;
    document.querySelector('.logo-box').classList.toggle('scanning', on);
    $('scanBtn').disabled = on;
    $('scanBtn').style.display = on ? 'none' : 'flex';
    $('stopBtn').style.display = on ? 'flex' : 'none';
    $('btnLbl').textContent = on ? 'Executing...' : 'Engage Discovery';
    $('btnSpinner').style.display = on ? 'block' : 'none';
    $('domainInput').disabled = on;
    $('timerDot').className = on ? 'pulse' : 'pulse inactive';
    $('statusLbl').textContent = on ? 'Engine Active' : 'Engine Standby';
    $('terminalSection').style.display = on ? 'block' : 'none';
    $('scanProgress').style.display = on ? 'block' : 'none';
    document.querySelectorAll('.tool-chip').forEach(el => el.style.opacity = on ? '0.5' : '1');
}

async function stopScan() {
    if (!STATE.scanId || !STATE.scanning) return;
    if (!confirm('Are you sure you want to abort the current mission? Background processes will be terminated.')) return;
    
    try {
        const res = await fetch(`/scan/${STATE.scanId}/stop`, { method: 'POST' });
        if (res.ok) {
            logTerminal('<b style="color:var(--red)">Scan cancellation requested...</b>');
        } else {
            const e = await res.json();
            alert(e.detail || 'Failed to stop scan');
        }
    } catch (e) { alert(e.message); }
}

function logTerminal(msg) {
    const t = $('terminalBody');
    const line = document.createElement('div');
    line.innerHTML = `<span style="color:var(--txt-light); opacity: 0.6;">[${new Date().toLocaleTimeString()}]</span> ${msg}`;
    t.appendChild(line);
    t.scrollTop = t.scrollHeight;
}

function startTimer() {
    STATE.timerStart = Date.now();
    clearInterval(STATE.timerInterval);
    STATE.timerInterval = setInterval(() => {
        const s = Math.floor((Date.now() - STATE.timerStart) / 1000);
        $('elTime').textContent = String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0');
    }, 1000);
}

function updateProgress() {
    if (STATE.stats.totalSteps === 0) return;
    const p = (STATE.stats.completedSteps / STATE.stats.totalSteps) * 100;
    $('progressBar').style.width = `${p}%`;
}

function connectSSE(id) {
    if (STATE.eventSource) STATE.eventSource.close();
    STATE.eventSource = new EventSource(`/scan/${id}/stream`);
    
    STATE.eventSource.onmessage = e => {
        let d; try { d = JSON.parse(e.data); } catch { return; }
        switch (d.type) {
            case 'plan': 
                STATE.stats.totalSteps = d.tools?.length || 0;
                STATE.stats.completedSteps = 0;
                onPlan(d); 
                break;
            case 'status': 
                if (['completed','error','timeout','cancelled'].includes(d.status)) finishScan(d.status); 
                break;
            case 'step_start': 
                logTerminal(`Starting module: <b style="color:var(--blue)">${d.tool}</b>`); 
                break;
            case 'step_done': 
                STATE.stats.completedSteps++;
                updateProgress();
                logTerminal(`Module <b style="color:var(--green)">${d.tool}</b> completed with ${d.count} findings`); 
                break;
            case 'line': onLine(d); break;
        }
    };
    STATE.eventSource.onerror = () => {
        STATE.eventSource.close();
        if (STATE.scanning) finishScan('error');
    };
}

function onPlan(event) {
    const tools = event.tools || [];
    tools.forEach(t => { STATE.store[t] = []; });
    buildResultPanels(tools);
    $('resultsSection').style.display = 'block';
}

function buildResultPanels(tools) {
    const container = $('resultPanels');
    container.innerHTML = '';
    tools.forEach(tool => {
        const panel = document.createElement('div');
        panel.className = 'panel';
        panel.id = `panel-${tool}`;
        panel.innerHTML = `
            <div class="panel-head" onclick="togglePanel('${tool}')">
                <span class="tool-tag">${tool}</span>
                <span class="panel-name">${STATE.toolsMeta[tool]?.name || tool}</span>
                <span class="panel-meta" id="count-${tool}">0 records</span>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
            </div>
            <div class="table-box">
                <table id="table-${tool}">
                    <thead id="thead-${tool}"></thead>
                    <tbody id="tbody-${tool}"></tbody>
                </table>
            </div>
        `;
        container.appendChild(panel);
    });
}

function onLine(event) {
    const { tool, data } = event;
    if (!data || Object.keys(data).length === 0) return;
    
    if (!STATE.store[tool]) STATE.store[tool] = [];
    STATE.store[tool].push(data);
    
    updateCount(tool);
    renderRow(tool, data);
    updateGlobalStats(tool, data);
}

function updateCount(tool) {
    const countEl = $(`count-${tool}`);
    if (countEl) countEl.textContent = `${STATE.store[tool].length} records`;
}

function renderRow(tool, data) {
    const tbody = $(`tbody-${tool}`);
    const thead = $(`thead-${tool}`);
    if (!tbody) return;

    const toolHeaders = {
        'httpx': ['url', 'status_code', 'title', 'tech'],
        'nmap': ['port', 'protocol', 'service', 'version'],
        'dig': ['type', 'name', 'value'],
        'ffuf': ['path', 'status_code', 'size']
    };

    if (thead.innerHTML === '') {
        const headers = toolHeaders[tool] || Object.keys(data).filter(k => typeof data[k] !== 'object');
        thead.innerHTML = `<tr>${headers.map(h => `<th>${h.replace(/_/g, ' ')}</th>`).join('')}</tr>`;
    }

    const headers = toolHeaders[tool] || Object.keys(data).filter(k => typeof data[k] !== 'object');
    const tr = document.createElement('tr');
    tr.innerHTML = headers.map(h => {
        let val = data[h];
        if (val === undefined || val === null) return '<td>—</td>';
        
        if (h === 'status_code') {
            const sc = parseInt(val);
            let color = 'b-4xx';
            if (sc >= 200 && sc < 300) color = 'b-2xx';
            else if (sc >= 300 && sc < 400) color = 'b-3xx';
            else if (sc >= 500) color = 'b-5xx';
            return `<td><span class="badge ${color}">${val}</span></td>`;
        }
        
        if (Array.isArray(val)) {
            return `<td><div style="display:flex;gap:4px;flex-wrap:wrap">${val.slice(0, 3).map(t => `<span class="mono-val" style="font-size:10px">${t}</span>`).join('')}</div></td>`;
        }

        if (typeof val === 'string' && (val.startsWith('http') || h === 'url' || h === 'path')) {
            const url = val.startsWith('http') ? val : `http://${val}`;
            return `<td><a href="${url}" target="_blank" class="mono-val" style="color:var(--blue); text-decoration: none; border-bottom: 1px dashed var(--blue);">${val}</a></td>`;
        }

        return `<td>${val}</td>`;
    }).join('');
    tbody.appendChild(tr);
}

function filterResults() {
    const q = $('globalSearch').value.toLowerCase();
    document.querySelectorAll('.panel tbody tr').forEach(tr => {
        const text = tr.textContent.toLowerCase();
        tr.style.display = text.includes(q) ? '' : 'none';
    });
}

function updateGlobalStats(tool, data) {
    if (tool === 'httpx') {
        STATE.stats.liveHosts++;
        $('stat-hosts').textContent = STATE.stats.liveHosts;
    }
    if (data.status_code && parseInt(data.status_code) >= 400) {
        STATE.stats.risks++;
        $('stat-risks').textContent = STATE.stats.risks;
    }
}

function finishScan(status) {
    setScanUI(false);
    clearInterval(STATE.timerInterval);
    if (status === 'completed') $('progressBar').style.width = '100%';
    logTerminal(`Scan finished with status: <b style="color:${status==='completed'?'var(--green)':'var(--red)'}">${status.toUpperCase()}</b>`);
    $('expPdf').disabled = status !== 'completed';
    $('expCsv').disabled = status !== 'completed';
}

function clearResults() {
    STATE.store = {};
    STATE.stats = { liveHosts: 0, risks: 0, totalSteps: 0, completedSteps: 0 };
    $('stat-hosts').textContent = '0';
    $('stat-risks').textContent = '0';
    $('progressBar').style.width = '0%';
    $('resultPanels').innerHTML = '';
    $('terminalBody').innerHTML = '';
    $('terminalSection').style.display = 'none';
    $('resultsSection').style.display = 'none';
    $('globalSearch').value = '';
}

async function loadHistory() {
    try {
        const r = await fetch('/scans');
        const d = await r.json();
        const scans = d.scans || [];
        const b = $('histRows');
        const e = $('histEmpty');
        
        if (!scans.length) {
            b.innerHTML = '';
            e.style.display = 'block';
            return;
        }
        
        e.style.display = 'none';
        b.innerHTML = scans.map(s => `
            <tr>
                <td><span class="mono-val">${s.domain}</span></td>
                <td><span class="badge ${s.status === 'completed' ? 'b-2xx' : 'b-5xx'}">${s.status}</span></td>
                <td><div style="display:flex;gap:4px">${(s.tools || []).map(t => `<span class="tool-tag" style="font-size:9px">${t}</span>`).join('')}</div></td>
                <td style="font-size:12px;color:var(--txt-dim)">${new Date(s.created_at * 1000).toLocaleString()}</td>
                <td style="font-family:var(--font-mono);font-size:12px">${s.finished_at ? Math.floor((s.finished_at - s.created_at) / 60) + 'm ' + (Math.floor(s.finished_at - s.created_at) % 60) + 's' : '—'}</td>
                <td><button class="nav-item" style="padding:4px 10px;font-size:11px" onclick="viewScan('${s.id}')">View</button></td>
            </tr>
        `).join('');
    } catch (e) { console.error('Failed to load history:', e); }
}

async function viewScan(id) {
    showView('scan');
    try {
        const r = await fetch(`/scan/${id}/result`);
        const data = await r.json();
        STATE.scanId = id;
        STATE.domain = data.scan.domain;
        $('domainInput').value = data.scan.domain;
        
        clearResults();
        onPlan({ tools: data.scan.tools });
        
        data.results.forEach(res => {
            if (res.tool !== 'system') onLine({ tool: res.tool, data: res.data });
        });
        
        finishScan(data.scan.status);
    } catch (e) { alert(e.message); }
}

function doExport(f) {
    if (STATE.scanId) window.open(`/scan/${STATE.scanId}/export/${f}`, '_blank');
}

function togglePanel(tool) {
    $(`panel-${tool}`).classList.toggle('collapsed');
}

document.addEventListener('DOMContentLoaded', () => {
    loadTools();
});
