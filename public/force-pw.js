(function () {
  function createModal() {
    const overlay = document.createElement('div');
    overlay.id = 'forcePwOverlay';
    overlay.className = 'modal-overlay open';
    overlay.style.cssText = 'z-index:9999;align-items:center';
    overlay.innerHTML = `
      <div class="modal" style="max-width:420px">
        <div class="modal-header" style="margin-bottom:12px">
          <h2>Change Your Password</h2>
        </div>
        <p style="margin-bottom:20px;color:var(--text-secondary);font-size:14px">
          Your account requires a password change before you can continue.
        </p>
        <div id="forcePwError" class="settings-error" style="display:none;margin-bottom:16px"></div>
        <form id="forcePwForm">
          <div class="form-group">
            <label for="forcePwNew">New Password <span style="color:var(--danger)">*</span></label>
            <input type="password" id="forcePwNew" required autocomplete="new-password" placeholder="Minimum 8 characters" />
          </div>
          <div class="form-group">
            <label for="forcePwConfirm">Confirm Password <span style="color:var(--danger)">*</span></label>
            <input type="password" id="forcePwConfirm" required autocomplete="new-password" />
          </div>
          <div class="modal-actions">
            <button type="submit" class="btn btn-primary">Set Password &amp; Continue</button>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(overlay);

    document.getElementById('forcePwForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const np = document.getElementById('forcePwNew').value;
      const cp = document.getElementById('forcePwConfirm').value;
      const errEl = document.getElementById('forcePwError');
      errEl.style.display = 'none';

      if (np.length < 8) {
        errEl.textContent = 'Password must be at least 8 characters';
        errEl.style.display = 'block';
        return;
      }
      if (np !== cp) {
        errEl.textContent = 'Passwords do not match';
        errEl.style.display = 'block';
        return;
      }

      const btn = e.target.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = 'Saving…';

      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_password: np })
      });
      const data = await res.json();
      btn.disabled = false;
      btn.textContent = 'Set Password & Continue';

      if (!res.ok) {
        errEl.textContent = data.error || 'Failed to change password';
        errEl.style.display = 'block';
        return;
      }
      overlay.remove();
    });
  }

  window.checkForcePasswordChange = function (meData) {
    if (meData && meData.must_change_password) createModal();
  };
})();
