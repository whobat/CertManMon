const $ = id => document.getElementById(id);

let deleteUserTargetId = null;
let editUserMode = false;
let allGroupsForUserModal = [];

let logsCurrentPage = 1;
let logsCurrentAction = '';
let logsCurrentSearch = '';

// --- Auth check ---
async function initAuth() {
  const res = await fetch('/api/auth/me');
  if (res.status === 401) { window.location.href = '/login'; return; }
  const data = await res.json();
  if (data.role !== 'admin') { window.location.href = '/'; return; }
  $('headerUser').textContent = data.display_name || data.username;
  checkForcePasswordChange(data);
}

$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' });
  window.location.href = '/login';
});

// --- Tabs ---
document.querySelectorAll('.settings-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.settings-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.settings-tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).classList.add('active');
    if (btn.dataset.tab === 'logs') loadLogs(logsCurrentPage);
    if (btn.dataset.tab === 'apikeys') loadApiKeys();
    if (btn.dataset.tab === 'cronjobs') loadCronJobs();
  });
});

// --- Role badge ---
function roleBadge(role) {
  const classes = { admin: 'badge-role-admin', editor: 'badge-role-editor', viewer: 'badge-role-viewer' };
  const labels = { admin: 'Admin', editor: 'Editor', viewer: 'Viewer' };
  return `<span class="badge-role ${classes[role] || ''}">${labels[role] || role}</span>`;
}

// --- Provider badge ---
function providerBadge(provider) {
  if (provider === 'entra') {
    return `<span class="badge-provider badge-provider-entra">
      <svg viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg" style="width:12px;height:12px;display:inline-block;vertical-align:middle;margin-right:4px">
        <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
        <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
        <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
        <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
      </svg>Entra ID</span>`;
  }
  return `<span class="badge-provider badge-provider-local">Local</span>`;
}

// --- Status badge ---
function activeBadge(active) {
  if (active) return `<span class="badge-status badge-status-active">Active</span>`;
  return `<span class="badge-status badge-status-inactive">Inactive</span>`;
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

window.toggleUserActive = async function(id, currentActive) {
  const newActive = currentActive ? 0 : 1;
  const res = await fetch(`/api/users/${id}/active`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: !!newActive })
  });
  const data = await res.json();
  if (!res.ok) {
    showUsersError(data.error || 'Failed to update user');
    return;
  }
  loadUsers();
};

// --- Load users ---
async function loadUsers() {
  const res = await fetch('/api/users');
  if (!res.ok) {
    showUsersError('Failed to load users');
    return;
  }
  const users = await res.json();

  if (users.length === 0) {
    $('usersBody').innerHTML = '<tr><td colspan="7" class="empty">No users found</td></tr>';
    return;
  }

  $('usersBody').innerHTML = users.map(u => {
    const lastLogin = u.last_login_at
      ? new Date(u.last_login_at + 'Z').toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
      : '<span style="color:var(--text-muted)">Never</span>';
    const toggleBtn = `<button class="btn btn-icon ${u.active ? 'danger' : 'btn-secondary'}"
      onclick="toggleUserActive(${u.id}, ${u.active ? 1 : 0})"
      title="${u.active ? 'Disable user' : 'Enable user'}">${u.active ? 'Disable' : 'Enable'}</button>`;
    return `
    <tr data-id="${u.id}">
      <td>
        <strong>${esc(u.username)}</strong>
        ${u.display_name ? `<br><span style="font-size:12px;color:var(--text-muted)">${esc(u.display_name)}</span>` : ''}
      </td>
      <td>${esc(u.email)}</td>
      <td>${roleBadge(u.role)}</td>
      <td>${providerBadge(u.auth_provider)}</td>
      <td>${activeBadge(u.active)}</td>
      <td>${lastLogin}</td>
      <td>
        <div class="action-btns">
          ${toggleBtn}
          <button class="btn btn-icon" onclick="openEditUser(${u.id})" title="Edit">&#9998;</button>
          <button class="btn btn-icon danger" onclick="openDeleteUser(${u.id}, '${esc(u.username)}')" title="Delete">&#128465;</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function showUsersError(msg) {
  const el = $('usersError');
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

// --- User Modal ---

function populateUserGroupList(selectedIds = []) {
  const container = $('userGroupCheckList');
  const hint = $('userGroupCheckHint');
  if (allGroupsForUserModal.length === 0) {
    container.innerHTML = '';
    hint.textContent = 'No groups defined yet.';
    hint.style.display = 'block';
    return;
  }
  hint.style.display = 'none';
  const selected = new Set(selectedIds.map(Number));
  container.innerHTML = allGroupsForUserModal.map(g => `
    <label class="group-check-item">
      <input type="checkbox" name="userGroup" value="${g.id}" ${selected.has(g.id) ? 'checked' : ''} />
      <span>${esc(g.name)}</span>
    </label>
  `).join('');
}

function getSelectedUserGroupIds() {
  return Array.from($('userGroupCheckList').querySelectorAll('input[name="userGroup"]:checked'))
    .map(cb => parseInt(cb.value, 10));
}

function generatePassword() {
  const chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*';
  const arr = new Uint8Array(14);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % chars.length]).join('');
}

async function openAddUser() {
  editUserMode = false;
  $('userId').value = '';
  $('userForm').reset();
  $('userModalTitle').textContent = 'Add User';
  $('userPassword').required = true;
  $('userModalError').style.display = 'none';

  // Auto-generate password and show it in plaintext
  const pw = generatePassword();
  $('userPassword').value = pw;
  $('userPassword').type = 'text';
  $('userPasswordHint').innerHTML = '* <span style="color:var(--text-muted);font-weight:400">auto-generated</span>';
  $('userPasswordToggle').querySelector('.icon-eye').style.display = 'none';
  $('userPasswordToggle').querySelector('.icon-eye-off').style.display = '';
  $('userPwGenBtn').style.display = '';
  $('userPwCopyBtn').style.display = '';

  // Refresh groups list then populate with nothing selected
  const gRes = await fetch('/api/groups');
  allGroupsForUserModal = gRes.ok ? await gRes.json() : [];
  populateUserGroupList([]);

  $('userModalOverlay').classList.add('open');
}

window.openEditUser = async function(id) {
  editUserMode = true;
  $('userModalError').style.display = 'none';
  $('userPassword').type = 'password';
  $('userPasswordToggle').querySelector('.icon-eye').style.display = '';
  $('userPasswordToggle').querySelector('.icon-eye-off').style.display = 'none';
  $('userPwGenBtn').style.display = 'none';
  $('userPwCopyBtn').style.display = 'none';
  $('userPasswordHint').textContent = '(leave blank to keep current)';

  const [usersRes, gRes, userGroupsRes] = await Promise.all([
    fetch('/api/users'),
    fetch('/api/groups'),
    fetch(`/api/users/${id}/groups`)
  ]);
  if (!usersRes.ok) return;
  const users = await usersRes.json();
  const u = users.find(x => x.id === id);
  if (!u) return;

  allGroupsForUserModal = gRes.ok ? await gRes.json() : [];
  const userGroups = userGroupsRes.ok ? await userGroupsRes.json() : [];

  $('userId').value = u.id;
  $('userUsername').value = u.username;
  $('userDisplayName').value = u.display_name || '';
  $('userEmail').value = u.email;
  $('userPassword').value = '';
  $('userPassword').required = false;
  $('userPasswordHint').textContent = '(leave blank to keep current)';
  $('userRole').value = u.role;
  $('userActive').value = String(u.active);
  $('userModalTitle').textContent = 'Edit User';

  populateUserGroupList(userGroups.map(g => g.id));

  $('userModalOverlay').classList.add('open');
};

function closeUserModal() {
  $('userModalOverlay').classList.remove('open');
  $('userForm').reset();
  $('userId').value = '';
  $('userModalError').style.display = 'none';
  $('userGroupCheckList').innerHTML = '';
  editUserMode = false;
}

window.openDeleteUser = function(id, username) {
  deleteUserTargetId = id;
  $('deleteUserMsg').textContent = `Are you sure you want to delete user "${username}"? This action cannot be undone.`;
  $('deleteUserError').style.display = 'none';
  $('deleteUserOverlay').classList.add('open');
};

function closeDeleteUserModal() {
  $('deleteUserOverlay').classList.remove('open');
  deleteUserTargetId = null;
  $('deleteUserError').style.display = 'none';
}

// Events
$('addUserBtn').addEventListener('click', () => openAddUser());
$('userModalClose').addEventListener('click', closeUserModal);
$('userCancelBtn').addEventListener('click', closeUserModal);
$('userModalOverlay').addEventListener('click', e => { if (e.target === $('userModalOverlay')) closeUserModal(); });

$('userPwGenBtn').addEventListener('click', () => {
  const pw = generatePassword();
  $('userPassword').value = pw;
  $('userPassword').type = 'text';
  $('userPasswordToggle').querySelector('.icon-eye').style.display = 'none';
  $('userPasswordToggle').querySelector('.icon-eye-off').style.display = '';
});

$('userPwCopyBtn').addEventListener('click', async () => {
  const pw = $('userPassword').value;
  if (!pw) return;
  await navigator.clipboard.writeText(pw);
  const btn = $('userPwCopyBtn');
  btn.textContent = '✓ Copied';
  setTimeout(() => { btn.innerHTML = '&#128203; Copy'; }, 1500);
});

$('userPasswordToggle').addEventListener('click', () => {
  const input = $('userPassword');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('userPasswordToggle').querySelector('.icon-eye').style.display = showing ? '' : 'none';
  $('userPasswordToggle').querySelector('.icon-eye-off').style.display = showing ? 'none' : '';
});

$('userForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('userModalError').style.display = 'none';

  const id = $('userId').value;
  const payload = {
    username: $('userUsername').value.trim(),
    display_name: $('userDisplayName').value.trim(),
    email: $('userEmail').value.trim(),
    role: $('userRole').value,
    active: parseInt($('userActive').value, 10)
  };
  const password = $('userPassword').value;
  if (password) payload.password = password;

  const url = editUserMode ? `/api/users/${id}` : '/api/users';
  const method = editUserMode ? 'PUT' : 'POST';

  if (!editUserMode) payload.auth_provider = 'local';

  const selectedGroupIds = getSelectedUserGroupIds();

  try {
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      const saved = await res.json();
      const userId = id || saved.id;
      // Save group memberships
      await fetch(`/api/users/${userId}/groups`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ group_ids: selectedGroupIds })
      });
      closeUserModal();
      await loadUsers();
    } else {
      const data = await res.json();
      const el = $('userModalError');
      el.textContent = data.error || 'Failed to save user';
      el.style.display = 'block';
    }
  } catch {
    const el = $('userModalError');
    el.textContent = 'Could not reach server';
    el.style.display = 'block';
  }
});

$('deleteUserClose').addEventListener('click', closeDeleteUserModal);
$('deleteUserCancelBtn').addEventListener('click', closeDeleteUserModal);
$('deleteUserOverlay').addEventListener('click', e => { if (e.target === $('deleteUserOverlay')) closeDeleteUserModal(); });

$('deleteUserConfirmBtn').addEventListener('click', async () => {
  if (!deleteUserTargetId) return;
  try {
    const res = await fetch(`/api/users/${deleteUserTargetId}`, { method: 'DELETE' });
    if (res.ok || res.status === 204) {
      closeDeleteUserModal();
      await loadUsers();
    } else {
      const data = await res.json();
      const el = $('deleteUserError');
      el.textContent = data.error || 'Failed to delete user';
      el.style.display = 'block';
    }
  } catch {
    const el = $('deleteUserError');
    el.textContent = 'Could not reach server';
    el.style.display = 'block';
  }
});

// --- Entra Settings ---
async function loadEntraSettings() {
  const res = await fetch('/api/settings/entra');
  if (!res.ok) return;
  const data = await res.json();

  $('entraEnabled').checked = data.entra_enabled === 'true';
  $('entraTenantId').value = data.entra_tenant_id || '';
  $('entraClientId').value = data.entra_client_id || '';
  // Never pre-fill the secret; show a placeholder indicating whether one is saved
  $('entraClientSecret').value = '';
  $('entraClientSecret').placeholder = data.entra_client_secret ? '(saved — enter new value to change)' : 'Enter client secret';
  $('entraRedirectUri').value = data.entra_redirect_uri || '';

  // Auto-suggest redirect URI
  if (!data.entra_redirect_uri) {
    const suggested = window.location.origin + '/api/auth/entra/callback';
    $('entraRedirectUri').value = suggested;
    $('entraRedirectHint').textContent = 'Auto-filled based on current origin. Update if needed.';
  }
}

$('entraForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('entraError').style.display = 'none';
  $('entraSuccess').style.display = 'none';

  const payload = {
    entra_enabled: $('entraEnabled').checked,
    entra_tenant_id: $('entraTenantId').value.trim(),
    entra_client_id: $('entraClientId').value.trim(),
    entra_client_secret: $('entraClientSecret').value,
    entra_redirect_uri: $('entraRedirectUri').value.trim()
  };

  try {
    const res = await fetch('/api/settings/entra', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      $('entraSuccess').textContent = 'Settings saved successfully.';
      $('entraSuccess').style.display = 'block';
      await loadEntraSettings();
    } else {
      const data = await res.json();
      $('entraError').textContent = data.error || 'Failed to save settings';
      $('entraError').style.display = 'block';
    }
  } catch {
    $('entraError').textContent = 'Could not reach server';
    $('entraError').style.display = 'block';
  }
});

$('entraSecretToggle').addEventListener('click', () => {
  const input = $('entraClientSecret');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('entraSecretToggle').querySelector('.icon-eye').style.display = showing ? '' : 'none';
  $('entraSecretToggle').querySelector('.icon-eye-off').style.display = showing ? 'none' : '';
});

// =============================================================================
// --- Groups ---
// =============================================================================

let deleteGroupTargetId = null;
let editGroupMode = false;
let currentGroupPanelId = null;

// Caches for panel dropdowns
let allUsers = [];
let allCerts = [];

function showGroupsError(msg) {
  const el = $('groupsError');
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

async function loadGroups() {
  const res = await fetch('/api/groups');
  if (!res.ok) {
    showGroupsError('Failed to load groups');
    return;
  }
  const groups = await res.json();

  if (groups.length === 0) {
    $('groupsBody').innerHTML = '<tr><td colspan="5" class="empty">No groups defined</td></tr>';
    return;
  }

  $('groupsBody').innerHTML = groups.map(g => `
    <tr data-id="${g.id}">
      <td>
        <strong>${esc(g.name)}</strong>
        ${g.restricted ? '<span class="badge-restricted">System</span>' : ''}
      </td>
      <td>${esc(g.description || '')}</td>
      <td>${g.user_count}</td>
      <td>${g.cert_count}</td>
      <td>
        <div class="action-btns">
          <button class="btn btn-secondary btn-icon" onclick="openGroupPanel(${g.id})" title="Manage members">Manage</button>
          ${!g.restricted ? `<button class="btn btn-icon" onclick="openEditGroup(${g.id}, '${esc(g.name)}', '${esc(g.description || '')}')" title="Edit">&#9998;</button>` : ''}
          ${!g.restricted ? `<button class="btn btn-icon danger" onclick="openDeleteGroup(${g.id}, '${esc(g.name)}')" title="Delete">&#128465;</button>` : ''}
        </div>
      </td>
    </tr>
  `).join('');
}

// --- Group Modal (Add/Edit) ---
function openAddGroup() {
  editGroupMode = false;
  $('groupId').value = '';
  $('groupForm').reset();
  $('groupModalTitle').textContent = 'Add Group';
  $('groupModalError').style.display = 'none';
  $('groupModalOverlay').classList.add('open');
}

window.openEditGroup = function(id, name, description) {
  editGroupMode = true;
  $('groupId').value = id;
  $('groupName').value = name;
  $('groupDescription').value = description;
  $('groupModalTitle').textContent = 'Edit Group';
  $('groupModalError').style.display = 'none';
  $('groupModalOverlay').classList.add('open');
};

function closeGroupModal() {
  $('groupModalOverlay').classList.remove('open');
  $('groupForm').reset();
  $('groupId').value = '';
  $('groupModalError').style.display = 'none';
  editGroupMode = false;
}

$('addGroupBtn').addEventListener('click', openAddGroup);
$('groupModalClose').addEventListener('click', closeGroupModal);
$('groupCancelBtn').addEventListener('click', closeGroupModal);
$('groupModalOverlay').addEventListener('click', e => { if (e.target === $('groupModalOverlay')) closeGroupModal(); });

$('groupForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('groupModalError').style.display = 'none';

  const id = $('groupId').value;
  const payload = {
    name: $('groupName').value.trim(),
    description: $('groupDescription').value.trim()
  };

  const url = editGroupMode ? `/api/groups/${id}` : '/api/groups';
  const method = editGroupMode ? 'PUT' : 'POST';

  try {
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      closeGroupModal();
      await loadGroups();
    } else {
      const data = await res.json();
      const el = $('groupModalError');
      el.textContent = data.error || 'Failed to save group';
      el.style.display = 'block';
    }
  } catch {
    const el = $('groupModalError');
    el.textContent = 'Could not reach server';
    el.style.display = 'block';
  }
});

// --- Delete Group Modal ---
window.openDeleteGroup = function(id, name) {
  deleteGroupTargetId = id;
  $('deleteGroupMsg').textContent = `Are you sure you want to delete group "${name}"? This action cannot be undone.`;
  $('deleteGroupError').style.display = 'none';
  $('deleteGroupOverlay').classList.add('open');
};

function closeDeleteGroupModal() {
  $('deleteGroupOverlay').classList.remove('open');
  deleteGroupTargetId = null;
  $('deleteGroupError').style.display = 'none';
}

$('deleteGroupClose').addEventListener('click', closeDeleteGroupModal);
$('deleteGroupCancelBtn').addEventListener('click', closeDeleteGroupModal);
$('deleteGroupOverlay').addEventListener('click', e => { if (e.target === $('deleteGroupOverlay')) closeDeleteGroupModal(); });

$('deleteGroupConfirmBtn').addEventListener('click', async () => {
  if (!deleteGroupTargetId) return;
  try {
    const res = await fetch(`/api/groups/${deleteGroupTargetId}`, { method: 'DELETE' });
    if (res.ok || res.status === 204) {
      closeDeleteGroupModal();
      await loadGroups();
    } else {
      const data = await res.json();
      const el = $('deleteGroupError');
      el.textContent = data.error || 'Failed to delete group';
      el.style.display = 'block';
    }
  } catch {
    const el = $('deleteGroupError');
    el.textContent = 'Could not reach server';
    el.style.display = 'block';
  }
});

// --- Group Panel ---
function closeGroupPanel() {
  $('groupPanel').classList.remove('open');
  $('groupPanelOverlay').classList.remove('open');
  currentGroupPanelId = null;
}

$('groupPanelClose').addEventListener('click', closeGroupPanel);
$('groupPanelOverlay').addEventListener('click', closeGroupPanel);

window.openGroupPanel = async function(groupId) {
  currentGroupPanelId = groupId;
  $('groupPanelName').textContent = 'Loading...';
  $('groupPanelDesc').textContent = '';
  $('groupPanelMembers').innerHTML = '<p style="color:var(--text-muted);font-size:13px">Loading...</p>';
  $('groupPanelCerts').innerHTML = '<p style="color:var(--text-muted);font-size:13px">Loading...</p>';
  $('groupPanel').classList.add('open');
  $('groupPanelOverlay').classList.add('open');

  await refreshGroupPanel(groupId);
};

async function refreshGroupPanel(groupId) {
  // Load group info, members, certs, all users, all certs in parallel
  const [groupsRes, membersRes, certsInGroupRes, allUsersRes, allCertsRes] = await Promise.all([
    fetch('/api/groups'),
    fetch(`/api/groups/${groupId}/users`),
    fetch(`/api/groups/${groupId}/certs`),
    fetch('/api/users'),
    fetch('/api/certificates')
  ]);

  const groups = groupsRes.ok ? await groupsRes.json() : [];
  const group = groups.find(g => g.id === groupId);
  const members = membersRes.ok ? await membersRes.json() : [];
  const certsInGroup = certsInGroupRes.ok ? await certsInGroupRes.json() : [];
  allUsers = allUsersRes.ok ? await allUsersRes.json() : [];
  allCerts = allCertsRes.ok ? await allCertsRes.json() : [];

  if (group) {
    $('groupPanelName').textContent = group.name;
    $('groupPanelDesc').textContent = group.description || '';
  }

  // Render members
  if (members.length === 0) {
    $('groupPanelMembers').innerHTML = '<p style="color:var(--text-muted);font-size:13px;padding:4px 0">No members yet</p>';
  } else {
    $('groupPanelMembers').innerHTML = members.map(u => `
      <div class="group-member-row">
        <div class="group-member-info">
          <span class="group-member-name">${esc(u.username)}</span>
          <span class="group-member-sub">${esc(u.email)} &middot; ${u.role}</span>
        </div>
        <button class="btn btn-icon danger" onclick="removeUserFromGroup(${groupId}, ${u.id})" title="Remove">&#215;</button>
      </div>
    `).join('');
  }

  // Populate add-user dropdown (exclude already members)
  const memberIds = new Set(members.map(u => u.id));
  const nonMembers = allUsers.filter(u => !memberIds.has(u.id));
  $('groupAddUserSelect').innerHTML = '<option value="">— Add user —</option>' +
    nonMembers.map(u => `<option value="${u.id}">${esc(u.username)} (${esc(u.role)})</option>`).join('');

  // Render certs in group
  if (certsInGroup.length === 0) {
    $('groupPanelCerts').innerHTML = '<p style="color:var(--text-muted);font-size:13px;padding:4px 0">No certificates assigned</p>';
  } else {
    $('groupPanelCerts').innerHTML = certsInGroup.map(c => `
      <div class="group-member-row">
        <div class="group-member-info">
          <span class="group-member-name">${esc(c.name)}</span>
          <span class="group-member-sub">${esc(c.fqdn)}</span>
        </div>
        <button class="btn btn-icon danger" onclick="removeCertFromGroup(${groupId}, ${c.id})" title="Remove">&#215;</button>
      </div>
    `).join('');
  }

  // Populate add-cert dropdown (exclude already assigned)
  const certIds = new Set(certsInGroup.map(c => c.id));
  const nonAssigned = allCerts.filter(c => !certIds.has(c.id));
  $('groupAddCertSelect').innerHTML = '<option value="">— Add certificate —</option>' +
    nonAssigned.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
}

window.removeUserFromGroup = async function(groupId, userId) {
  const membersRes = await fetch(`/api/groups/${groupId}/users`);
  if (!membersRes.ok) return;
  const members = await membersRes.json();
  const updatedIds = members.map(u => u.id).filter(id => id !== userId);

  await fetch(`/api/groups/${groupId}/users`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_ids: updatedIds })
  });

  await refreshGroupPanel(groupId);
  await loadGroups();
};

window.removeCertFromGroup = async function(groupId, certId) {
  const certsRes = await fetch(`/api/groups/${groupId}/certs`);
  if (!certsRes.ok) return;
  const certs = await certsRes.json();
  const updatedIds = certs.map(c => c.id).filter(id => id !== certId);

  await fetch(`/api/groups/${groupId}/certs`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cert_ids: updatedIds })
  });

  await refreshGroupPanel(groupId);
  await loadGroups();
};

$('groupAddUserBtn').addEventListener('click', async () => {
  const select = $('groupAddUserSelect');
  const userId = parseInt(select.value, 10);
  if (!userId || !currentGroupPanelId) return;

  const membersRes = await fetch(`/api/groups/${currentGroupPanelId}/users`);
  if (!membersRes.ok) return;
  const members = await membersRes.json();
  const updatedIds = [...members.map(u => u.id), userId];

  await fetch(`/api/groups/${currentGroupPanelId}/users`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_ids: updatedIds })
  });

  await refreshGroupPanel(currentGroupPanelId);
  await loadGroups();
});

$('groupAddCertBtn').addEventListener('click', async () => {
  const select = $('groupAddCertSelect');
  const certId = parseInt(select.value, 10);
  if (!certId || !currentGroupPanelId) return;

  const certsRes = await fetch(`/api/groups/${currentGroupPanelId}/certs`);
  if (!certsRes.ok) return;
  const certs = await certsRes.json();
  const updatedIds = [...certs.map(c => c.id), certId];

  await fetch(`/api/groups/${currentGroupPanelId}/certs`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cert_ids: updatedIds })
  });

  await refreshGroupPanel(currentGroupPanelId);
  await loadGroups();
});

// --- Notifications ---

async function loadNotificationSettings() {
  const res = await fetch('/api/settings/notifications');
  if (!res.ok) return;
  const s = await res.json();

  $('notifEnabled').checked = s.notifications_enabled === 'true';
  $('smtpHost').value = s.smtp_host || '';
  $('smtpPort').value = s.smtp_port || '587';
  $('smtpUser').value = s.smtp_user || '';
  $('smtpPass').value = s.smtp_pass || '';
  $('smtpFrom').value = s.smtp_from || '';
  $('smtpTls').checked = s.smtp_tls !== 'false';
  $('threshold1').value = s.threshold_1 || '30';
  $('threshold2').value = s.threshold_2 || '14';
  $('threshold3').value = s.threshold_3 || '7';
  $('adminEmails').value = s.admin_emails || '';
  $('notifyResponsible').checked = s.notify_responsible !== 'false';
  $('notifyRenewal').checked = s.notify_renewal === 'true';
  $('appUrl').value = s.app_url || '';
}

$('notifForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('notifError').style.display = 'none';
  $('notifSuccess').style.display = 'none';

  const payload = {
    notifications_enabled: $('notifEnabled').checked ? 'true' : 'false',
    smtp_host: $('smtpHost').value.trim(),
    smtp_port: $('smtpPort').value.trim() || '587',
    smtp_user: $('smtpUser').value.trim(),
    smtp_pass: $('smtpPass').value,
    smtp_from: $('smtpFrom').value.trim(),
    smtp_tls: $('smtpTls').checked ? 'true' : 'false',
    threshold_1: $('threshold1').value.trim() || '30',
    threshold_2: $('threshold2').value.trim() || '14',
    threshold_3: $('threshold3').value.trim() || '7',
    admin_emails: $('adminEmails').value.trim(),
    notify_responsible: $('notifyResponsible').checked ? 'true' : 'false',
    notify_renewal: $('notifyRenewal').checked ? 'true' : 'false',
    app_url: $('appUrl').value.trim(),
  };

  const res = await fetch('/api/settings/notifications', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (res.ok) {
    $('notifSuccess').textContent = 'Settings saved.';
    $('notifSuccess').style.display = 'block';
    setTimeout(() => { $('notifSuccess').style.display = 'none'; }, 3000);
    await loadNotificationSettings();
  } else {
    const err = await res.json().catch(() => ({}));
    $('notifError').textContent = err.error || 'Failed to save settings.';
    $('notifError').style.display = 'block';
  }
});

$('testEmailBtn').addEventListener('click', async () => {
  const to = $('testEmailTo').value.trim();
  $('notifTestError').style.display = 'none';
  $('notifTestSuccess').style.display = 'none';
  if (!to) {
    $('notifTestError').textContent = 'Enter a recipient address first.';
    $('notifTestError').style.display = 'block';
    return;
  }
  $('testEmailBtn').disabled = true;
  $('testEmailBtn').textContent = 'Sending…';
  const res = await fetch('/api/settings/notifications/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ to })
  });
  $('testEmailBtn').disabled = false;
  $('testEmailBtn').textContent = 'Send Test Email';
  if (res.ok) {
    $('notifTestSuccess').textContent = `Test email sent to ${to}.`;
    $('notifTestSuccess').style.display = 'block';
    setTimeout(() => { $('notifTestSuccess').style.display = 'none'; }, 4000);
  } else {
    const err = await res.json().catch(() => ({}));
    $('notifTestError').textContent = err.error || 'Failed to send test email.';
    $('notifTestError').style.display = 'block';
  }
});

$('runNowBtn').addEventListener('click', async () => {
  $('notifError').style.display = 'none';
  $('notifSuccess').style.display = 'none';
  $('runNowBtn').disabled = true;
  $('runNowBtn').textContent = 'Running…';
  const res = await fetch('/api/settings/notifications/run', { method: 'POST' });
  $('runNowBtn').disabled = false;
  $('runNowBtn').textContent = 'Run Check Now';
  if (res.ok) {
    $('notifSuccess').textContent = 'Notification check completed. Check server logs for details.';
    $('notifSuccess').style.display = 'block';
    setTimeout(() => { $('notifSuccess').style.display = 'none'; }, 5000);
  } else {
    const err = await res.json().catch(() => ({}));
    $('notifError').textContent = err.error || 'Check failed.';
    $('notifError').style.display = 'block';
  }
});

// Password show/hide for SMTP
$('smtpPassToggle').addEventListener('click', () => {
  const input = $('smtpPass');
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  $('smtpPassToggle').querySelector('.icon-eye').style.display = isHidden ? 'none' : '';
  $('smtpPassToggle').querySelector('.icon-eye-off').style.display = isHidden ? '' : 'none';
});

// --- API Keys ---

async function loadApiKeys() {
  const res = await fetch('/api/apikeys');
  if (!res.ok) {
    $('apiKeysError').textContent = 'Failed to load API keys.';
    $('apiKeysError').style.display = 'block';
    return;
  }
  $('apiKeysError').style.display = 'none';
  const keys = await res.json();

  if (keys.length === 0) {
    $('apiKeysBody').innerHTML = '<tr><td colspan="7" class="empty">No API keys yet</td></tr>';
    return;
  }

  $('apiKeysBody').innerHTML = keys.map(k => `
    <tr>
      <td><strong>${esc(k.name)}</strong></td>
      <td><code style="font-size:12px;color:var(--text-muted)">${esc(k.key_prefix)}…</code></td>
      <td>${k.permission === 'readwrite'
          ? '<span class="badge-role badge-role-editor">Read/Write</span>'
          : '<span class="badge-role badge-role-viewer">Read</span>'}</td>
      <td>${k.active
          ? '<span class="badge-status badge-status-active">Active</span>'
          : '<span class="badge-status badge-status-inactive">Inactive</span>'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${k.last_used_at ? esc(k.last_used_at) : '—'}</td>
      <td style="font-size:12px;color:var(--text-muted)">${esc(k.created_at || '')}</td>
      <td>
        <div class="action-btns">
          <button class="btn btn-secondary btn-sm" onclick="toggleApiKey(${k.id}, ${k.active})">${k.active ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-icon danger" onclick="deleteApiKey(${k.id}, '${esc(k.name)}')" title="Delete">&#128465;</button>
        </div>
      </td>
    </tr>
  `).join('');
}

window.toggleApiKey = async function(id, currentActive) {
  await fetch(`/api/apikeys/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active: currentActive ? 0 : 1 })
  });
  await loadApiKeys();
};

window.deleteApiKey = async function(id, name) {
  if (!confirm(`Delete API key "${name}"? Any scripts using it will stop working.`)) return;
  const res = await fetch(`/api/apikeys/${id}`, { method: 'DELETE' });
  if (res.ok || res.status === 204) await loadApiKeys();
};

function openApiKeyModal() {
  $('apiKeyForm').style.display = 'block';
  $('apiKeyResult').style.display = 'none';
  $('apiKeyModalError').style.display = 'none';
  $('apiKeyForm').reset();
  $('apiKeyModalOverlay').classList.add('open');
}

function closeApiKeyModal() {
  $('apiKeyModalOverlay').classList.remove('open');
  $('apiKeyForm').reset();
  $('apiKeyResult').style.display = 'none';
}

$('addApiKeyBtn').addEventListener('click', openApiKeyModal);
$('apiKeyModalClose').addEventListener('click', closeApiKeyModal);
$('apiKeyCancelBtn').addEventListener('click', closeApiKeyModal);
$('apiKeyModalOverlay').addEventListener('click', e => { if (e.target === $('apiKeyModalOverlay')) closeApiKeyModal(); });

$('apiKeyForm').addEventListener('submit', async e => {
  e.preventDefault();
  $('apiKeyModalError').style.display = 'none';
  const res = await fetch('/api/apikeys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: $('apiKeyName').value.trim(),
      permission: $('apiKeyPermission').value
    })
  });
  if (res.ok) {
    const data = await res.json();
    $('apiKeyForm').style.display = 'none';
    $('apiKeyValue').value = data.key;
    $('apiKeyResult').style.display = 'block';
    await loadApiKeys();
  } else {
    const err = await res.json().catch(() => ({}));
    $('apiKeyModalError').textContent = err.error || 'Failed to create key.';
    $('apiKeyModalError').style.display = 'block';
  }
});

$('copyApiKeyBtn').addEventListener('click', () => {
  const val = $('apiKeyValue').value;
  navigator.clipboard.writeText(val).then(() => {
    $('copyApiKeyBtn').textContent = 'Copied!';
    setTimeout(() => { $('copyApiKeyBtn').textContent = 'Copy'; }, 2000);
  });
});

// --- Logs ---

async function loadLogs(page = 1) {
  logsCurrentPage = page;
  const params = new URLSearchParams({
    page,
    limit: 50,
    action: logsCurrentAction,
    search: logsCurrentSearch
  });

  const res = await fetch('/api/logs?' + params);
  if (!res.ok) {
    $('logsError').textContent = 'Failed to load logs.';
    $('logsError').style.display = 'block';
    return;
  }
  $('logsError').style.display = 'none';
  const data = await res.json();

  if (data.rows.length === 0) {
    $('logsBody').innerHTML = '<tr><td colspan="6" class="empty">No log entries found</td></tr>';
  } else {
    $('logsBody').innerHTML = data.rows.map(r => {
      const actionClass = r.action.startsWith('auth') ? 'log-action-auth'
        : r.action.startsWith('cert') ? 'log-action-cert'
        : r.action.startsWith('user') ? 'log-action-user'
        : r.action.startsWith('group') ? 'log-action-group'
        : r.action.startsWith('notify') ? 'log-action-notify'
        : 'log-action-settings';
      return `<tr>
        <td style="white-space:nowrap;font-size:12px;color:var(--text-muted)">${esc(r.timestamp || '')}</td>
        <td><strong>${esc(r.username || '—')}</strong></td>
        <td><span class="log-action-badge ${actionClass}">${esc(r.action)}</span></td>
        <td>${esc(r.target || '—')}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(r.details || '')}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(r.ip || '')}</td>
      </tr>`;
    }).join('');
  }

  // Pagination
  const totalPages = Math.ceil(data.total / data.limit);
  if (totalPages <= 1) {
    $('logsPagination').innerHTML = '';
  } else {
    const pages = [];
    for (let i = 1; i <= totalPages; i++) {
      pages.push(`<button class="btn ${i === page ? 'btn-primary' : 'btn-secondary'} logs-page-btn" data-page="${i}">${i}</button>`);
    }
    $('logsPagination').innerHTML = `<span style="color:var(--text-muted);font-size:13px">${data.total} entries</span>` + pages.join('');
    $('logsPagination').querySelectorAll('.logs-page-btn').forEach(btn => {
      btn.addEventListener('click', () => loadLogs(parseInt(btn.dataset.page, 10)));
    });
  }
}

$('logsSearch').addEventListener('input', () => {
  logsCurrentSearch = $('logsSearch').value.trim();
  loadLogs(1);
});

$('logsActionFilter').addEventListener('change', () => {
  logsCurrentAction = $('logsActionFilter').value;
  loadLogs(1);
});

$('clearLogsBtn').addEventListener('click', async () => {
  if (!confirm('Clear all audit log entries? This cannot be undone.')) return;
  const res = await fetch('/api/logs', { method: 'DELETE' });
  if (res.ok) await loadLogs(1);
  else {
    $('logsError').textContent = 'Failed to clear logs.';
    $('logsError').style.display = 'block';
  }
});

// --- Scheduled Jobs ---
async function loadCronJobs() {
  const body = $('cronJobsBody');
  const err = $('cronJobsError');
  const suc = $('cronJobsSuccess');
  err.style.display = 'none';
  suc.style.display = 'none';
  body.innerHTML = '<tr><td colspan="4" class="empty">Loading...</td></tr>';
  try {
    const res = await fetch('/api/settings/cron');
    if (!res.ok) throw new Error(await res.text());
    const jobs = await res.json();
    body.innerHTML = jobs.map(job => `
      <tr>
        <td><strong>${job.name}</strong></td>
        <td>${job.description}</td>
        <td>
          <div style="display:flex;gap:6px;align-items:center">
            <input type="text" class="form-input" id="schedule-${job.id}" value="${job.schedule}" style="width:160px;font-family:monospace">
            <button class="btn btn-secondary" onclick="saveCronSchedule('${job.id}')">Save</button>
          </div>
        </td>
        <td>
          <button class="btn btn-primary" onclick="runCronJob('${job.id}')">Run Now</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    body.innerHTML = '<tr><td colspan="4" class="empty">Failed to load jobs.</td></tr>';
    err.textContent = e.message;
    err.style.display = '';
  }
}

async function saveCronSchedule(jobId) {
  const err = $('cronJobsError');
  const suc = $('cronJobsSuccess');
  err.style.display = 'none';
  suc.style.display = 'none';
  const schedule = $('schedule-' + jobId).value.trim();
  try {
    const res = await fetch(`/api/settings/cron/${jobId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ schedule }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to save');
    suc.textContent = 'Schedule updated successfully.';
    suc.style.display = '';
  } catch (e) {
    err.textContent = e.message;
    err.style.display = '';
  }
}

async function runCronJob(jobId) {
  const err = $('cronJobsError');
  const suc = $('cronJobsSuccess');
  err.style.display = 'none';
  suc.style.display = 'none';
  try {
    const res = await fetch(`/api/settings/cron/${jobId}/run`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to run job');
    suc.textContent = 'Job triggered successfully.';
    suc.style.display = '';
  } catch (e) {
    err.textContent = e.message;
    err.style.display = '';
  }
}

// --- Init ---
(async () => {
  await initAuth();
  await Promise.all([loadUsers(), loadGroups(), loadEntraSettings(), loadNotificationSettings()]);
  try {
    const v = await fetch('/api/version').then(r => r.json());
    const el = document.getElementById('versionBadge');
    if (el && v.version) el.textContent = 'v' + v.version;
  } catch (_) {}
})();
