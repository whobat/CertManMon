let certs = [];
let deleteTargetId = null;
let editMode = false;
let pendingCertData = null; // holds PEM text from uploaded file
let currentFile = null;    // tracks the last selected file for PFX re-parse
let availableGroups = [];
let availableUsers = [];
let currentCertId = null;  // cert being edited (for URL management)
let pendingUrls   = [];    // URLs queued in add mode (saved after cert is created)

window.userRole = null;

const $ = id => document.getElementById(id);

// --- API ---
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  if (res.status === 401) { window.location.href = '/login'; return null; }
  if (res.status === 204) return null;
  return res.json();
}

// --- Auth ---
async function initAuth() {
  const res = await fetch('/api/auth/me');
  if (res.status === 401) { window.location.href = '/login'; return; }
  const data = await res.json();
  $('headerUser').textContent = data.display_name || data.username;
  window.userRole = data.role;
  window.userRestricted = !!data.restricted;
  checkForcePasswordChange(data);

  // Show settings link for admins
  if (data.role === 'admin') {
    $('settingsLink').style.display = '';
  }

  // Hide add button for viewers
  if (data.role === 'viewer') {
    $('addBtn').style.display = 'none';
  }
}

$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login';
});

// --- Users (for responsible-person autocomplete) ---
async function loadUserSuggestions() {
  try {
    const res = await fetch('/api/users/suggestions');
    if (!res.ok) return;
    availableUsers = await res.json();
    const dl = $('userSuggestions');
    dl.innerHTML = availableUsers.map(u =>
      `<option value="${esc(u.username)}">${esc(u.email)}</option>`
    ).join('');
  } catch (_) {}
}

// --- URL monitoring ---

function renderPendingUrls() {
  const container = $('certUrlList');
  if (!pendingUrls.length) {
    container.innerHTML = '<div class="url-empty">No URLs added — they will be checked after saving</div>';
    return;
  }
  container.innerHTML = pendingUrls.map((url, i) => `
    <div class="url-item">
      <span class="url-status-badge url-status-pending">Pending</span>
      <div class="url-item-info">
        <span class="url-text">${esc(url)}</span>
        <span class="url-meta">Will be checked when the certificate is saved</span>
      </div>
      <div class="url-item-actions">
        <button class="btn btn-icon danger" onclick="removePendingUrl(${i})" title="Remove URL">&#215;</button>
      </div>
    </div>`).join('');
}

window.removePendingUrl = function(index) {
  pendingUrls.splice(index, 1);
  renderPendingUrls();
};

async function loadCertUrls(certId) {
  currentCertId = certId;
  const urls = await api('GET', `/certificates/${certId}/urls`);
  renderUrlList(urls || [], certId);
}

function renderUrlList(urls, certId) {
  const container = $('certUrlList');
  if (!urls.length) {
    container.innerHTML = '<div class="url-empty">No URLs added yet</div>';
    return;
  }
  container.innerHTML = urls.map(u => {
    const labels = { match: 'Match', mismatch: 'Mismatch', error: 'Error', pending: 'Pending' };
    const checked = u.last_checked ? new Date(u.last_checked + 'Z').toLocaleString() : 'Never';
    const liveInfo = u.live_expiry ? ` · Live: ${u.live_expiry}` : '';
    const errInfo  = u.last_error  ? ` · ${u.last_error}` : '';
    return `
      <div class="url-item">
        <span class="url-status-badge url-status-${u.last_status}">${labels[u.last_status] || u.last_status}</span>
        <div class="url-item-info">
          <span class="url-text">${esc(u.url)}</span>
          <span class="url-meta">${checked}${liveInfo}${errInfo}</span>
        </div>
        <div class="url-item-actions">
          <button class="btn btn-icon" onclick="recheckCertUrl(${certId},${u.id})" title="Re-check now">&#8635;</button>
          <button class="btn btn-icon danger" onclick="deleteCertUrl(${certId},${u.id})" title="Remove URL">&#215;</button>
        </div>
      </div>`;
  }).join('');
}

window.deleteCertUrl = async function(certId, urlId) {
  const res = await fetch(`/api/certificates/${certId}/urls/${urlId}`, { method: 'DELETE' });
  if (res.ok || res.status === 204) loadCertUrls(certId);
};

window.recheckCertUrl = async function(certId, urlId) {
  const res = await fetch(`/api/certificates/${certId}/urls/${urlId}/check`, { method: 'POST' });
  if (res.ok) loadCertUrls(certId);
};

// --- Groups ---
async function loadGroups() {
  try {
    const res = await fetch('/api/groups');
    if (res.ok) {
      availableGroups = await res.json();
    }
  } catch (_) {
    availableGroups = [];
  }
}

function populateGroupCheckList(selectedGroupIds = []) {
  const container = $('groupCheckList');
  container.innerHTML = '';
  if (availableGroups.length === 0) {
    // empty — CSS :empty::after will show "No groups defined"
    return;
  }
  const selectedSet = new Set(selectedGroupIds.map(id => parseInt(id, 10)));
  availableGroups.forEach(g => {
    const label = document.createElement('label');
    label.className = 'group-check-item';
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = g.id;
    checkbox.checked = selectedSet.has(g.id);
    label.appendChild(checkbox);
    label.appendChild(document.createTextNode(g.name));
    container.appendChild(label);
  });
}

function getSelectedGroupIds() {
  return Array.from($('groupCheckList').querySelectorAll('input[type="checkbox"]:checked'))
    .map(cb => parseInt(cb.value, 10));
}

// --- Status helpers ---
function getDaysLeft(expDate) {
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const exp = new Date(expDate);
  return Math.floor((exp - now) / 86400000);
}

function getStatus(days) {
  if (days < 0) return 'expired';
  if (days < 14) return 'critical';
  if (days < 30) return 'warning';
  return 'valid';
}

function statusBadge(days) {
  const s = getStatus(days);
  const labels = { valid: 'Valid', warning: 'Warning', critical: 'Critical', expired: 'Expired' };
  return `<span class="badge badge-${s}">${labels[s]}</span>`;
}

function daysLabel(days) {
  const cls = getStatus(days);
  if (days < 0) return `<span class="days-expired">Expired ${Math.abs(days)}d ago</span>`;
  return `<span class="days-${cls}">${days}d</span>`;
}

// --- Render ---
function renderStats() {
  const now = new Date(); now.setHours(0, 0, 0, 0);
  let valid = 0, warning = 0, critical = 0, expired = 0;
  certs.forEach(c => {
    const d = getDaysLeft(c.expiration_date);
    const s = getStatus(d);
    if (s === 'valid') valid++;
    else if (s === 'warning') warning++;
    else if (s === 'critical') critical++;
    else expired++;
  });

  $('stats').innerHTML = `
    <div class="stat-card"><div class="stat-label">Total</div><div class="stat-value">${certs.length}</div></div>
    <div class="stat-card"><div class="stat-label">Valid</div><div class="stat-value green">${valid}</div></div>
    <div class="stat-card"><div class="stat-label">Expiring &lt;30d</div><div class="stat-value yellow">${warning}</div></div>
    <div class="stat-card"><div class="stat-label">Critical &lt;14d</div><div class="stat-value red">${critical}</div></div>
    <div class="stat-card"><div class="stat-label">Expired</div><div class="stat-value gray">${expired}</div></div>
  `;
}

function renderTable() {
  const search = $('search').value.toLowerCase();
  const filterStatus = $('filterStatus').value;
  const isViewer = window.userRole === 'viewer';

  const filtered = certs.filter(c => {
    const days = getDaysLeft(c.expiration_date);
    const status = getStatus(days);
    if (filterStatus !== 'all' && status !== filterStatus) return false;
    if (search) {
      const haystack = [c.name, c.fqdn, ...(c.hosts || []).flatMap(h => [h.hostname, h.responsible_person])].join(' ').toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    $('certBody').innerHTML = '<tr><td colspan="11" class="empty">No certificates found</td></tr>';
    return;
  }

  $('certBody').innerHTML = filtered.map(c => {
    const days = getDaysLeft(c.expiration_date);
    const hosts = (c.hosts || []).map(h =>
      `<span class="host-tag">${esc(h.hostname)}${h.responsible_person ? `<span class="host-tag-person">${esc(h.responsible_person)}</span>` : ''}</span>`
    ).join('');
    const groupBadges = (c.groups || []).map(g =>
      `<span class="group-badge">${esc(g.name)}</span>`
    ).join(' ');
    const expFormatted = new Date(c.expiration_date + 'T00:00:00').toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric'
    });
    const dlBtn = !c.has_cert
      ? `<button class="btn btn-icon" disabled title="No certificate file stored" style="opacity:0.35;cursor:default">&#8659;</button>`
      : window.userRestricted
        ? `<button class="btn btn-icon" disabled title="Download not permitted for your account" style="opacity:0.35;cursor:default">&#8659;</button>`
        : `<a class="btn btn-icon" href="/api/certificates/${c.id}/download" download title="Download certificate">&#8659;</a>`;
    const pwCell = (c.password && !window.userRestricted)
      ? `<div class="pw-cell">
           <span class="pw-mask" data-pw="${esc(c.password)}">••••••••</span>
           <button class="btn-show-password pw-toggle" title="Show/hide password">
             <svg class="icon-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
             <svg class="icon-eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
           </button>
         </div>`
      : `<span style="color:var(--text-muted)">—</span>`;

    const editDeleteBtns = isViewer ? '' : `
      <button class="btn btn-icon" onclick="openEdit(${c.id})" title="Edit">&#9998;</button>
      <button class="btn btn-icon danger" onclick="openDelete(${c.id}, '${esc(c.name)}')" title="Delete">&#128465;</button>
    `;

    const urlTags = (c.urls && c.urls.length)
      ? c.urls.map(u => {
          let host = u.url;
          try { host = new URL(u.url).hostname; } catch (_) {}
          const labels = { match: 'Match', mismatch: 'Mismatch', error: 'Error', pending: 'Pending' };
          return `<a href="${esc(u.url)}" target="_blank" rel="noopener" class="url-tag url-tag-${u.last_status}" title="${esc(u.url)} · ${labels[u.last_status] || u.last_status}">${esc(host)}</a>`;
        }).join('')
      : `<span style="color:var(--text-muted)">—</span>`;

    return `
      <tr data-id="${c.id}">
        <td>${statusBadge(days)}</td>
        <td><strong>${esc(c.name)}</strong></td>
        <td><code style="color:var(--primary);font-size:13px">${esc(c.fqdn)}</code></td>
        <td>${expFormatted}</td>
        <td>${daysLabel(days)}</td>
        <td class="note-cell">${c.note ? `<span class="note-text" title="${esc(c.note)}">${esc(c.note)}</span>` : '<span style="color:var(--text-muted)">—</span>'}</td>
        <td>${pwCell}</td>
        <td><div class="host-tags">${groupBadges || '<span style="color:var(--text-muted)">—</span>'}</div></td>
        <td><div class="host-tags">${hosts || '<span style="color:var(--text-muted)">—</span>'}</div></td>
        <td><div class="url-tags">${urlTags}</div></td>
        <td>
          <div class="action-btns">
            ${dlBtn}
            ${editDeleteBtns}
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function loadCerts() {
  certs = await api('GET', '/certificates');
  renderStats();
  renderTable();
}

// --- Modal: Add/Edit ---
function openModal(title) {
  $('modalTitle').textContent = title;
  populateGroupCheckList([]);
  $('modalOverlay').classList.add('open');
}

function closeModal() {
  $('modalOverlay').classList.remove('open');
  $('certForm').reset();
  $('certId').value = '';
  $('hostList').innerHTML = '';
  $('groupCheckList').innerHTML = '';
  $('certPassword').type = 'password';
  $('certPasswordToggle').querySelector('.icon-eye').style.display = '';
  $('certPasswordToggle').querySelector('.icon-eye-off').style.display = 'none';
  $('fileLabel').textContent = 'Drop .pem / .crt / .cer / .pfx here or click to browse';
  $('fileDrop').classList.remove('file-drop-loaded');
  $('parseError').textContent = '';
  $('certFileInfo').textContent = '';
  $('pfxPasswordSection').style.display = 'none';
  $('pfxPassword').value = '';
  pendingCertData = null;
  currentFile = null;
  editMode = false;
  currentCertId = null;
  pendingUrls = [];
  $('urlMonitorSection').style.display = 'none';
  $('certUrlList').innerHTML = '';
  $('certUrlInput').value = '';
}

function addHostRow(hostname = '', responsible_person = '') {
  const row = document.createElement('div');
  row.className = 'host-row';
  row.innerHTML = `
    <input type="text" class="host-input" placeholder="e.g. server01.example.com" value="${esc(hostname)}" />
    <div style="flex:1;min-width:0">
      <input type="text" class="person-input" placeholder="Responsible person" value="${esc(responsible_person)}" list="userSuggestions" autocomplete="off" style="width:100%" />
      <div class="person-not-found" style="display:none;font-size:12px;color:var(--warning,#f59e0b);margin-top:3px"></div>
    </div>
    <button type="button" class="remove-host" title="Remove">&#215;</button>
  `;
  row.querySelector('.remove-host').addEventListener('click', () => row.remove());

  const personInput = row.querySelector('.person-input');
  const hint = row.querySelector('.person-not-found');

  personInput.addEventListener('blur', () => {
    const val = personInput.value.trim();
    if (!val) { hint.style.display = 'none'; return; }
    const known = availableUsers.some(u =>
      u.username.toLowerCase() === val.toLowerCase() ||
      (u.display_name && u.display_name.toLowerCase() === val.toLowerCase())
    );
    if (known) { hint.style.display = 'none'; return; }
    hint.innerHTML = `User not found. <a href="#" class="create-user-link">Create "${esc(val)}"</a>`;
    hint.style.display = 'block';
    hint.querySelector('.create-user-link').addEventListener('click', e => {
      e.preventDefault();
      openQuickCreateUser(val, personInput, hint);
    });
  });

  personInput.addEventListener('input', () => { hint.style.display = 'none'; });

  $('hostList').appendChild(row);
}

function getHostValues() {
  return Array.from($('hostList').querySelectorAll('.host-row')).map(row => ({
    hostname: row.querySelector('.host-input').value.trim(),
    responsible_person: row.querySelector('.person-input').value.trim()
  })).filter(h => h.hostname);
}

window.openEdit = function(id) {
  const c = certs.find(x => x.id === id);
  if (!c) return;
  editMode = true;
  pendingCertData = null;
  $('certId').value = c.id;
  $('certName').value = c.name;
  $('certFqdn').value = c.fqdn;
  $('certExpiry').value = c.expiration_date;
  $('certPassword').value = c.password || '';
  $('certNote').value = c.note || '';
  $('certPassword').type = 'password';
  $('certPasswordToggle').querySelector('.icon-eye').style.display = '';
  $('certPasswordToggle').querySelector('.icon-eye-off').style.display = 'none';
  $('hostList').innerHTML = '';
  (c.hosts || []).forEach(h => addHostRow(h.hostname, h.responsible_person));
  $('pfxPasswordSection').style.display = 'none';
  $('pfxPassword').value = '';
  if (c.has_cert) {
    $('fileLabel').textContent = 'Certificate file stored — drop a new file to replace';
    $('fileDrop').classList.add('file-drop-loaded');
    $('certFileInfo').textContent = '';
  }
  // Pre-check current group ids
  const currentGroupIds = (c.groups || []).map(g => g.id);
  populateGroupCheckList(currentGroupIds);
  $('urlMonitorSection').style.display = '';
  loadCertUrls(c.id);
  openModal('Edit Certificate');
};

window.openDelete = function(id, name) {
  deleteTargetId = id;
  $('deleteMsg').textContent = `Are you sure you want to delete "${name}"? This action cannot be undone.`;
  $('deleteOverlay').classList.add('open');
};

// --- Events ---
$('addBtn').addEventListener('click', () => {
  pendingUrls = [];
  openModal('Add Certificate');
  $('urlMonitorSection').style.display = '';
  renderPendingUrls();
});
$('modalClose').addEventListener('click', closeModal);
$('cancelBtn').addEventListener('click', closeModal);
$('addHostBtn').addEventListener('click', () => addHostRow());

$('addCertUrlBtn').addEventListener('click', async () => {
  const input = $('certUrlInput');
  const url = input.value.trim();
  if (!url) return;

  if (currentCertId) {
    // Edit mode — save and check immediately
    const btn = $('addCertUrlBtn');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    try {
      const res = await fetch(`/api/certificates/${currentCertId}/urls`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (res.ok) {
        input.value = '';
        await loadCertUrls(currentCertId);
      } else {
        const data = await res.json();
        alert(data.error || 'Failed to add URL');
      }
    } finally {
      btn.disabled = false;
      btn.textContent = '+ Add URL';
    }
  } else {
    // Add mode — queue for after save
    if (pendingUrls.includes(url)) { alert('This URL is already in the list'); return; }
    pendingUrls.push(url);
    input.value = '';
    renderPendingUrls();
  }
});

$('certUrlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); $('addCertUrlBtn').click(); }
});

$('modalOverlay').addEventListener('click', e => { if (e.target === $('modalOverlay')) closeModal(); });

$('certForm').addEventListener('submit', async e => {
  e.preventDefault();
  const payload = {
    name: $('certName').value.trim(),
    fqdn: $('certFqdn').value.trim(),
    expiration_date: $('certExpiry').value,
    password: $('certPassword').value,
    note: $('certNote').value.trim(),
    hosts: getHostValues(),
    cert_data: pendingCertData,
    group_ids: getSelectedGroupIds()
  };
  const id = $('certId').value;
  if (editMode && id) {
    await api('PUT', `/certificates/${id}`, payload);
  } else {
    const created = await api('POST', '/certificates', payload);
    if (created && created.id && pendingUrls.length) {
      await Promise.all(pendingUrls.map(url =>
        fetch(`/api/certificates/${created.id}/urls`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        }).catch(() => {})
      ));
    }
  }
  closeModal();
  await loadCerts();
});

// --- File upload & parse ---
function isPfx(file) {
  return /\.(pfx|p12)$/i.test(file.name);
}

async function parseCertFile(file, password = '') {
  $('parseError').textContent = '';
  $('certFileInfo').textContent = '';
  $('fileLabel').textContent = 'Parsing\u2026';

  const formData = new FormData();
  formData.append('cert', file);
  if (password) formData.append('password', password);

  try {
    const res = await fetch('/api/certificates/parse', { method: 'POST', body: formData });
    const data = await res.json();

    if (!res.ok) {
      if (data.needsPassword) {
        // Wrong or missing password — show password field
        $('pfxPasswordSection').style.display = 'flex';
        $('parseError').textContent = password ? 'Incorrect password — try again' : 'This PFX is password protected — enter the password below';
        $('fileLabel').textContent = file.name;
        $('fileDrop').classList.remove('file-drop-loaded');
      } else {
        $('parseError').textContent = data.error || 'Failed to parse certificate';
        $('fileLabel').textContent = 'Drop .pem / .crt / .cer / .pfx here or click to browse';
        $('fileDrop').classList.remove('file-drop-loaded');
        $('pfxPasswordSection').style.display = 'none';
      }
      return;
    }

    // Success
    pendingCertData = data.cert_data;
    $('pfxPasswordSection').style.display = 'none';

    if (data.expiration_date) $('certExpiry').value = data.expiration_date;
    if (data.name && !$('certName').value) $('certName').value = data.name;
    if (data.fqdn && !$('certFqdn').value) $('certFqdn').value = data.fqdn;
    if (password && !$('certPassword').value) $('certPassword').value = password;

    $('fileLabel').textContent = file.name + (isPfx(file) ? ' (cert extracted)' : '');
    $('fileDrop').classList.add('file-drop-loaded');
    $('certFileInfo').textContent = `Expires: ${new Date(data.expiration_date + 'T00:00:00').toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}`;
  } catch {
    $('parseError').textContent = 'Upload failed — check server connection';
    $('fileLabel').textContent = 'Drop .pem / .crt / .cer / .pfx here or click to browse';
    $('fileDrop').classList.remove('file-drop-loaded');
  }
}

function handleFileSelect(file) {
  currentFile = file;
  $('pfxPassword').value = '';
  $('pfxPasswordSection').style.display = 'none';
  parseCertFile(file, '');
}

$('certFile').addEventListener('change', e => {
  if (e.target.files[0]) handleFileSelect(e.target.files[0]);
});

$('pfxParseBtn').addEventListener('click', () => {
  if (currentFile) parseCertFile(currentFile, $('pfxPassword').value);
});

$('pfxPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); if (currentFile) parseCertFile(currentFile, $('pfxPassword').value); }
});

$('pfxPasswordToggle').addEventListener('click', () => {
  const input = $('pfxPassword');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('eyeIcon').style.display = showing ? '' : 'none';
  $('eyeOffIcon').style.display = showing ? 'none' : '';
});

// Drag-and-drop on the file drop zone
const fileDrop = $('fileDrop');
fileDrop.addEventListener('dragover', e => { e.preventDefault(); fileDrop.classList.add('file-drop-hover'); });
fileDrop.addEventListener('dragleave', () => fileDrop.classList.remove('file-drop-hover'));
fileDrop.addEventListener('drop', e => {
  e.preventDefault();
  fileDrop.classList.remove('file-drop-hover');
  const file = e.dataTransfer.files[0];
  if (file) handleFileSelect(file);
});

$('deleteClose').addEventListener('click', () => $('deleteOverlay').classList.remove('open'));
$('deleteCancelBtn').addEventListener('click', () => $('deleteOverlay').classList.remove('open'));
$('deleteOverlay').addEventListener('click', e => { if (e.target === $('deleteOverlay')) $('deleteOverlay').classList.remove('open'); });

$('deleteConfirmBtn').addEventListener('click', async () => {
  if (!deleteTargetId) return;
  await api('DELETE', `/certificates/${deleteTargetId}`);
  deleteTargetId = null;
  $('deleteOverlay').classList.remove('open');
  await loadCerts();
});

$('search').addEventListener('input', renderTable);
$('filterStatus').addEventListener('change', renderTable);

// Password reveal toggles in the table (event delegation)
$('certBody').addEventListener('click', e => {
  const btn = e.target.closest('.pw-toggle');
  if (!btn) return;
  const cell = btn.closest('.pw-cell');
  const mask = cell.querySelector('.pw-mask');
  const showing = mask.dataset.showing === 'true';
  mask.textContent = showing ? '••••••••' : mask.dataset.pw;
  mask.dataset.showing = showing ? 'false' : 'true';
  btn.querySelector('.icon-eye').style.display = showing ? '' : 'none';
  btn.querySelector('.icon-eye-off').style.display = showing ? 'none' : '';
});

// Password show/hide toggle in the form
$('certPasswordToggle').addEventListener('click', () => {
  const input = $('certPassword');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('certPasswordToggle').querySelector('.icon-eye').style.display = showing ? '' : 'none';
  $('certPasswordToggle').querySelector('.icon-eye-off').style.display = showing ? 'none' : '';
});

// --- Quick Create User ---
let quickUserTargetInput = null;
let quickUserTargetHint = null;

function populateQuickUserGroups() {
  const container = $('quickUserGroupList');
  if (!availableGroups.length) {
    container.innerHTML = '<span style="font-size:13px;color:var(--text-muted)">No groups defined</span>';
    return;
  }
  container.innerHTML = availableGroups.map(g => `
    <label class="group-check-item">
      <input type="checkbox" name="quickUserGroup" value="${g.id}" />
      <span>${esc(g.name)}${g.restricted ? ' <span class="badge-restricted">System</span>' : ''}</span>
    </label>
  `).join('');
}

function getQuickUserGroupIds() {
  return Array.from($('quickUserGroupList').querySelectorAll('input[name="quickUserGroup"]:checked'))
    .map(cb => parseInt(cb.value, 10));
}

function openQuickCreateUser(prefill, inputEl, hintEl) {
  quickUserTargetInput = inputEl;
  quickUserTargetHint = hintEl;
  $('quickUserUsername').value = prefill;
  $('quickUserDisplayName').value = '';
  $('quickUserEmail').value = '';
  $('quickUserRole').value = 'viewer';
  $('quickUserError').style.display = 'none';
  populateQuickUserGroups();
  $('quickUserOverlay').classList.add('open');
  $('quickUserEmail').focus();
}

function closeQuickUserModal() {
  $('quickUserOverlay').classList.remove('open');
  $('quickUserForm').reset();
  $('quickUserError').style.display = 'none';
  quickUserTargetInput = null;
  quickUserTargetHint = null;
}

$('quickUserClose').addEventListener('click', closeQuickUserModal);
$('quickUserCancelBtn').addEventListener('click', closeQuickUserModal);
$('quickUserOverlay').addEventListener('click', e => { if (e.target === $('quickUserOverlay')) closeQuickUserModal(); });

$('quickUserForm').addEventListener('submit', async e => {
  e.preventDefault();
  const errEl = $('quickUserError');
  errEl.style.display = 'none';

  const username = $('quickUserUsername').value.trim();
  const display_name = $('quickUserDisplayName').value.trim();
  const email = $('quickUserEmail').value.trim();
  const role = $('quickUserRole').value;

  // Generate a password server-side by sending a random one; user must change on first login
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
  const arr = new Uint8Array(14);
  crypto.getRandomValues(arr);
  const password = Array.from(arr, b => chars[b % chars.length]).join('');

  const btn = $('quickUserSaveBtn');
  btn.disabled = true;
  btn.textContent = 'Creating…';

  const res = await fetch('/api/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, display_name, email, password, role, auth_provider: 'local', active: 1 })
  });
  const data = await res.json();
  btn.disabled = false;
  btn.textContent = 'Create User';

  if (!res.ok) {
    errEl.textContent = data.error || 'Failed to create user';
    errEl.style.display = 'block';
    return;
  }

  // Assign selected groups
  const groupIds = getQuickUserGroupIds();
  if (groupIds.length) {
    await fetch(`/api/users/${data.id}/groups`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ group_ids: groupIds })
    });
  }

  // Add to local suggestions and datalist
  availableUsers.push({ username: data.username, display_name: data.display_name, email: data.email });
  const dl = $('userSuggestions');
  dl.innerHTML = availableUsers.map(u =>
    `<option value="${esc(u.username)}">${esc(u.email)}</option>`
  ).join('');

  // Fill the triggering input and hide the hint
  if (quickUserTargetInput) quickUserTargetInput.value = data.username;
  if (quickUserTargetHint) quickUserTargetHint.style.display = 'none';

  closeQuickUserModal();
});

// Initial load
initAuth();
Promise.all([loadCerts(), loadGroups(), loadUserSuggestions()]);
