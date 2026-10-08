/* Interface de gestion ZCode Proxy */
'use strict';

// ---- Infrastructure ----

async function api(path, opts = {}) {
  const init = {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
  const resp = await fetch(path, init);
  let data = null;
  try { data = await resp.json(); } catch (e) { /* empty */ }
  if (resp.status === 401 && !path.startsWith('/api/login')) {
    showLogin();
    throw new Error((data && data.error) || 'Non connecté ou session expirée');
  }
  if (!resp.ok) {
    const msg = (data && (data.error?.message || data.error || data.message)) || ('HTTP ' + resp.status);
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
  }
  return data;
}

let toastTimer = null;
function toast(msg, type = 'success') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast toast-' + type + ' show';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3200);
}

function openModal(html) {
  document.getElementById('modalBox').innerHTML = html;
  document.getElementById('modalOverlay').classList.add('show');
}
function closeModal() {
  document.getElementById('modalOverlay').classList.remove('show');
  // Fermer la modale : nettoyer le sondage OAuth pour éviter toute fuite de timer
  if (typeof cancelOAuth === 'function' && window._oauthState) cancelOAuth();
}

function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtNum(n) {
  n = Number(n || 0);
  if (n >= 1e9) return (Math.round(n / 1e8) / 10) + ' Md';
  if (n >= 1e6) return (Math.round(n / 1e5) / 10) + ' M';
  if (n >= 1e3) return (Math.round(n / 100) / 10) + ' k';
  return String(Math.round(n));
}

function fmtEpoch(sec) {
  if (!sec) return '-';
  const d = new Date(sec * 1000);
  return d.toLocaleString('fr-FR', { hour12: false });
}

function fmtAgo(sec) {
  if (!sec) return 'Jamais';
  const diff = Math.floor(Date.now() / 1000) - sec;
  if (diff < 60) return 'il y a ' + diff + ' s';
  if (diff < 3600) return 'il y a ' + Math.floor(diff / 60) + ' min';
  if (diff < 86400) return 'il y a ' + Math.floor(diff / 3600) + ' h';
  return 'il y a ' + Math.floor(diff / 86400) + ' j';
}

const STATUS_META = {
  active:    ['badge-success', 'Normal'],
  cooling:   ['badge-warning', 'En refroidissement'],
  exhausted: ['badge-danger', 'Quota épuisé'],
  invalid:   ['badge-danger', 'Identifiants invalides'],
  inactive:  ['badge-info', 'Inactif'],
  disabled:  ['badge-secondary', 'Désactivé'],
};
function statusBadge(st) {
  const m = STATUS_META[st] || ['badge-secondary', esc(st || '-')];
  return `<span class="badge ${m[0]}">${m[1]}</span>`;
}

// ---- Connexion ----

function showLogin() {
  document.getElementById('loginPage').style.display = 'flex';
  document.getElementById('mainApp').style.display = 'none';
}
function showApp(username) {
  document.getElementById('loginPage').style.display = 'none';
  document.getElementById('mainApp').style.display = 'block';
  document.getElementById('welcomeUser').textContent = username || 'admin';
  document.getElementById('userAvatar').textContent = (username || 'A')[0].toUpperCase();
  loadAll();
}

async function doLogin() {
  const username = document.getElementById('loginUser').value.trim() || 'admin';
  const password = document.getElementById('loginPass').value;
  const errEl = document.getElementById('loginError');
  errEl.textContent = '';
  errEl.style.display = 'none';
  const btn = document.querySelector('#loginPage .btn-primary');
  if (btn) btn.disabled = true;
  try {
    const data = await api('/api/login', { method: 'POST', body: { username, password } });
    showApp(data.username);
  } catch (e) {
    const msg = e.message || 'Échec de connexion';
    errEl.textContent = msg;
    errEl.style.display = 'block';   // Essentiel : afficher le bloc d'erreur
    toast(msg, 'error');             // Toast simultané pour garantir la visibilité
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function doLogout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  showLogin();
}

async function checkAuth() {
  try {
    await api('/api/auth/check');
    showApp('admin');
  } catch (e) {
    showLogin();
  }
}

document.getElementById('loginPass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

// ---- Navigation ----

document.querySelectorAll('.pill-nav .nav-link[data-section]').forEach(link => {
  link.addEventListener('click', () => switchSection(link.dataset.section));
});

function switchSection(name) {
  document.querySelectorAll('.pill-nav .nav-link').forEach(l => l.classList.toggle('active', l.dataset.section === name));
  document.querySelectorAll('.section').forEach(s => s.classList.toggle('active', s.id === 'section-' + name));
  if (name === 'dashboard') loadDashboard();
  if (name === 'accounts') { loadGroups(); loadAccounts(); }
  if (name === 'activity') { loadPlans(); loadClaimRecords(); loadPlanRuns(); }
  if (name === 'usage') { loadUsageStats(); loadUsageRecords(); }
  if (name === 'llmtest') { loadLlmKey(); }
  if (name === 'settings') loadSettings();
}

function navMoreDo(btn, fn) {
  btn.closest('.nav-more').classList.remove('open');
  fn();
}

function switchSettingsTab(tab) {
  document.querySelectorAll('.sub-tab').forEach(t => t.classList.toggle('active', t.dataset.stab === tab));
  ['security', 'strategy', 'proxy', 'tls', 'captcha', 'models'].forEach(t => {
    const el = document.getElementById('stab-' + t);
    if (el) el.style.display = t === tab ? '' : 'none';
  });
}

// ---- Tableau de bord ----

async function loadDashboard() {
  try {
    const d = await api('/api/dashboard');
    document.getElementById('statTotal').textContent = d.account_total ?? '-';
    document.getElementById('statSelectable').textContent = d.account_selectable ?? '-';
    document.getElementById('statRemaining').textContent = fmtNum(d.total_remaining);
    const u = d.usage_7d || {};
    document.getElementById('statRequests').textContent = fmtNum(u.requests);
    document.getElementById('statTokens').textContent = fmtNum(u.total_tokens);
    document.getElementById('statTtft').textContent = (u.avg_ttft_ms || 0) + 'ms';

    const cap = d.captcha || {};
    document.getElementById('dashStatus').innerHTML = `
      <div class="kv-grid">
        <div class="kv-item"><div class="k">Version client usurpée</div><div class="v">ZCode/${esc(d.app_version)}</div></div>
        <div class="kv-item"><div class="k">Paramètre captcha</div><div class="v">${cap.has_param ? (cap.fresh ? '✅ Frais' : '⏳ Tolérance (' + cap.param_age_s + 's)') : '— Non résolu'}</div></div>
        <div class="kv-item"><div class="k">Mode captcha</div><div class="v">${cap.manual_mode ? 'Manuel visible' : 'Auto headless'}</div></div>
        <div class="kv-item"><div class="k">Config captcha</div><div class="v">${cap.config ? (cap.config.enabled ? 'Amont activé scene=' + esc(cap.config.scene_id) : 'Amont désactivé') : 'Non récupérée'}</div></div>
      </div>`;

    const sc = d.status_count || {};
    const gc = d.group_count || {};
    document.getElementById('dashAccounts').innerHTML = `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
        ${Object.entries(sc).map(([k, v]) => statusBadge(k) + ' <b style="margin-right:10px">' + v + '</b>').join('')}
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${Object.entries(gc).map(([k, v]) => `<span class="pill-group">${esc(k)} · ${v}</span>`).join('')}
      </div>`;
  } catch (e) { /* silencieux si non connecté */ }
}

// ---- Groupes ----

let groupCache = [];
async function loadGroups() {
  try {
    const d = await api('/api/groups');
    groupCache = d.groups || [];
    const sel = document.getElementById('groupFilter');
    const cur = sel.value;
    sel.innerHTML = '<option value="">Tous les groupes</option>' + groupCache.map(g => `<option value="${esc(g)}">${esc(g)}</option>`).join('');
    sel.value = cur;
  } catch (e) { /* ignore */ }
}

function groupOptions(selected) {
  return '<option value="">Sans groupe</option>' + groupCache.map(g =>
    `<option value="${esc(g)}" ${g === selected ? 'selected' : ''}>${esc(g)}</option>`).join('') +
    '<option value="__new__">＋ Nouveau groupe…</option>';
}

// ---- Comptes ----

let accountsCache = [];

async function loadAccounts() {
  const group = document.getElementById('groupFilter').value;
  try {
    const d = await api('/api/accounts' + (group ? '?group=' + encodeURIComponent(group) : ''));
    accountsCache = d.accounts || [];
    renderAccounts();
  } catch (e) { toast(e.message, 'error'); }
}

function quotaCell(a) {
  if (!a.plan_tier && !a.total_units) return '<span style="color:var(--c-text-lighter)">Non actualisé</span>';
  const pct = a.total_units > 0 ? Math.min(100, a.used_units / a.total_units * 100) : 0;
  return `<div class="quota-bar"><div class="progress-track" style="flex:1"><div class="progress-fill" style="width:${pct}%"></div></div>
    <span class="quota-num">${fmtNum(a.remaining)} / ${fmtNum(a.total_units)}</span></div>
    <div style="font-size:11px;color:var(--c-text-lighter);margin-top:3px">${esc(a.plan_tier || '')}${a.plan_expire ? ' · expire ' + esc(a.plan_expire) : ''}</div>`;
}

// showQuotaModal : clic sur le quota → modale avec forfaits et détail
function showQuotaModal(id) {
  const a = (accountsCache || []).find(x => x.id === id);
  if (!a) return;
  const q = a.quota;
  const fmtT = (s) => s ? new Date(s * 1000).toLocaleString('fr-FR', { hour12: false }) : '-';
  const bar = (pct) => `<div class="progress-track" style="height:6px"><div class="progress-fill" style="width:${Math.min(100, pct || 0)}%"></div></div>`;
  let body;
  if (!q || (!q.plans || !q.plans.length) && (!q.items || !q.items.length)) {
    body = `<div class="empty"><p>Aucune donnée de quota (${esc(a.status)})</p></div>
      <div class="hint" style="margin-top:8px">${q && q.auth_failed ? 'Échec d’authentification (401/403), reconnectez ce compte.' : q && q.not_entitled ? 'Ce compte n’a pas de Coding Plan / inactif.' : 'Cliquez sur « Actualiser » de la ligne pour récupérer le quota.'}</div>`;
  } else {
    const slots = (q.plans && q.plans.length) ? q.plans : [{ plan_id: '-', name: q.plan_tier || 'Forfait', tier: q.plan_tier || '', status: a.status, expire: q.plan_expire, total: q.total, used: q.used, remaining: q.remaining, percent_used: q.percent_used, items: q.items || [] }];
    body = `
      <div class="kv-grid" style="margin-bottom:14px">
        <div class="kv-item"><div class="k">Niveau de forfait</div><div class="v">${esc(q.plan_tier || '-')}</div></div>
        <div class="kv-item"><div class="k">Expiration</div><div class="v">${esc(q.plan_expire || '-')}</div></div>
        <div class="kv-item"><div class="k">Total / Utilisé / Restant</div><div class="v">${fmtNum(q.total)} / ${fmtNum(q.used)} / ${fmtNum(q.remaining)}</div></div>
        <div class="kv-item"><div class="k">Part utilisée</div><div class="v">${(q.percent_used || 0).toFixed(1)}%</div></div>
        <div class="kv-item"><div class="k">Source</div><div class="v">${esc(q.source || '-')}</div></div>
        <div class="kv-item"><div class="k">Actualisé le</div><div class="v">${fmtT(q.refreshed_at)}</div></div>
      </div>
      ${slots.map(s => `
        <div style="border:1px solid var(--c-border);border-radius:10px;padding:12px 14px;margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:8px">
            <div style="font-weight:700">${esc(s.name || s.plan_id)} <span class="badge badge-purple">${esc(s.tier || '-')}</span> <span class="badge ${String(s.status).toLowerCase() === 'active' ? 'badge-success' : 'badge-secondary'}">${esc(s.status || '-')}</span></div>
            <div style="font-size:12px;color:var(--c-text-light)">${s.expire ? 'Expire ' + esc(s.expire) : ''}</div>
          </div>
          ${bar(s.percent_used)}
          <div style="font-size:12px;color:var(--c-text-light);margin:6px 0 8px">Total ${fmtNum(s.total)} · Utilisé ${fmtNum(s.used)} · Restant ${fmtNum(s.remaining)} (${(s.percent_used || 0).toFixed(1)}%)</div>
          ${(s.items && s.items.length) ? `<div class="table-wrap"><table>
            <thead><tr><th>Modèle / Droit</th><th>Total</th><th>Utilisé</th><th>Restant</th><th>Part</th><th>Cycle / Expiration</th></tr></thead>
            <tbody>${s.items.map(it => `<tr>
              <td>${esc(it.name)}</td>
              <td>${fmtNum(it.total)}</td>
              <td>${fmtNum(it.used)}</td>
              <td><b>${fmtNum(it.remaining)}</b></td>
              <td>${(it.percent_used || 0).toFixed(1)}%</td>
              <td style="font-size:11.5px;color:var(--c-text-light)">${esc(it.period_end || '-')}</td>
            </tr>`).join('')}</tbody></table></div>` : '<div class="hint">Ce forfait n’a aucun détail</div>'}
        </div>`).join('')}
    `;
  }
  openModal(`<h3>Forfait et quota · ${esc(a.display_name || a.email || ('#' + id))}</h3>
    ${body}
    <div class="actions">
      <button class="btn btn-secondary" onclick="refreshQuota(${id});closeModal()">Actualiser le quota</button>
      <button class="btn btn-secondary" onclick="closeModal()">Fermer</button>
    </div>`);
}

function renderAccounts() {
  const el = document.getElementById('accountsTable');
  if (!accountsCache.length) {
    el.innerHTML = '<div class="empty"><p>Aucun compte. Cliquez sur « Importer local » ou « Connexion OAuth » pour commencer</p></div>';
    return;
  }
  el.innerHTML = `<div class="table-wrap"><table>
    <thead><tr>
      <th>Compte</th><th>Groupe</th><th>Auth</th><th>Statut</th><th>Forfait / Quota restant</th>
      <th>Empreinte appareil</th><th>Util./Échecs</th><th>Dernière activité</th><th style="width:200px">Actions</th>
    </tr></thead>
    <tbody>${accountsCache.map(a => `
      <tr>
        <td><div style="font-weight:700">${esc(a.display_name || a.email || a.user_id)}</div>
            <div style="font-size:11px;color:var(--c-text-lighter)">${esc(a.email || '')}</div>
            ${a.remark ? `<div style="font-size:11px;color:var(--c-text-lighter)">Note : ${esc(a.remark)}</div>` : ''}</td>
        <td>${a.group ? `<span class="pill-group">${esc(a.group)}</span>` : '<span style="color:var(--c-text-lighter)">-</span>'}</td>
        <td><span class="badge ${a.auth_type === 'jwt' ? 'badge-info' : 'badge-purple'}">${a.auth_type === 'jwt' ? 'JWT' : 'API Key'}</span>
            ${a.has_api_key && a.auth_type === 'jwt' ? '<div style="font-size:10.5px;color:var(--c-text-lighter);margin-top:3px">+secours API Key</div>' : ''}</td>
        <td>${statusBadge(a.status)}${!a.enabled ? ' <span class="badge badge-secondary">Désactivé</span>' : ''}
            ${a.last_error ? `<div style="font-size:10.5px;color:var(--c-danger);margin-top:3px;max-width:160px;overflow:hidden;text-overflow:ellipsis" title="${esc(a.last_error)}">${esc(a.last_error)}</div>` : ''}</td>
        <td style="min-width:190px;cursor:pointer" title="Voir le forfait et le quota" onclick="showQuotaModal(${a.id})">${quotaCell(a)}</td>
        <td><span class="mono" title="${esc(a.device_mid)}">${a.device_mid ? esc(a.device_mid.slice(0, 8)) + '…' : '-'}</span></td>
        <td>${a.use_count} / ${a.fail_count}<div style="font-size:10.5px;color:var(--c-text-lighter)">${fmtAgo(a.last_used_at)}</div></td>
        <td style="max-width:170px">${a.last_claim_at ? `<div style="font-size:11px">${esc(a.last_claim_plan || '')}</div><div style="font-size:10.5px;color:var(--c-text-lighter)">${esc(a.last_claim_msg || '').slice(0, 40)}</div>` : '<span style="color:var(--c-text-lighter)">-</span>'}</td>
        <td class="actions-cell">
          <button class="btn btn-sm btn-secondary" onclick="refreshQuota(${a.id})">Actualiser</button>
          <button class="btn btn-sm btn-primary" onclick="claimNow(${a.id})">Récupérer</button>
          <button class="btn btn-sm btn-secondary" onclick="showAccountActions(${a.id})">Plus ▾</button>
        </td>
      </tr>`).join('')}
    </tbody></table></div>`;
}

// showAccountActions : menu modal pour les actions (le dropdown serait rogné par overflow)
function showAccountActions(id) {
  const a = (accountsCache || []).find(x => x.id === id);
  if (!a) return;
  openModal(`<h3>Actions · ${esc(a.display_name || a.email || ('#' + id))}</h3>
    <div style="display:grid;gap:8px">
      <button class="btn btn-secondary" style="justify-content:flex-start" onclick="detectNow(${id})">🔍 Détecter les activités</button>
      <button class="btn btn-secondary" style="justify-content:flex-start" onclick="activateNow(${id})">⚡ Activer le forfait</button>
      <button class="btn btn-secondary" style="justify-content:flex-start" onclick="resetQuota(${id})">♻️ Réinitialiser le quota (Coding Plan)</button>
      <button class="btn btn-secondary" style="justify-content:flex-start" onclick="editAccount(${id})">✏️ Modifier groupe / note</button>
      ${a.has_creds_snapshot || a.has_jwt ? `<button class="btn btn-secondary" style="justify-content:flex-start" onclick="switchBack(${id})">💾 Rebasculer vers le client local</button>` : ''}
      ${a.has_creds_snapshot ? `<button class="btn btn-secondary" style="justify-content:flex-start" onclick="restoreLocal(${id})">↩️ Restaurer le local depuis le snapshot</button>` : ''}
      <button class="btn btn-danger" style="justify-content:flex-start" onclick="deleteAccount(${id})">🗑 Supprimer le compte</button>
    </div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Fermer</button></div>`);
}

async function refreshQuota(id) {
  try {
    await api(`/api/accounts/${id}/refresh`, { method: 'POST' });
    toast('Quota actualisé');
    loadAccounts();
  } catch (e) { toast('Échec d’actualisation : ' + e.message, 'error'); }
}

async function refreshAllQuota() {
  toast('Actualisation des quotas de tous les comptes…', 'info');
  for (const a of accountsCache.length ? accountsCache : (await api('/api/accounts')).accounts || []) {
    try { await api(`/api/accounts/${a.id}/refresh`, { method: 'POST' }); } catch (e) { /* continuer si un compte échoue */ }
  }
  toast('Actualisation terminée');
  loadAccounts(); loadDashboard();
}

async function claimNow(id) {
  toast('Détection et récupération en cours (captcha inclus, env. 10-30 s)…', 'info');
  try {
    const r = await api(`/api/accounts/${id}/claim`, { method: 'POST' });
    if (r.ok) toast('Récupération réussie : ' + (r.plan_name || ''));
    else toast('Récupération non aboutie : ' + r.message, 'error');
    loadAccounts();
  } catch (e) { toast('Échec de récupération : ' + e.message, 'error'); }
}

async function detectNow(id) {
  closeModal();
  try {
    const r = await api(`/api/accounts/${id}/detect`);
    const plans = r.plans || [];
    openModal(`<h3>Détection d’activités</h3>
      ${plans.length ? plans.map(p => `
        <div style="border:1px solid var(--c-border);border-radius:10px;padding:12px 14px;margin-bottom:10px">
          <div style="font-weight:700;margin-bottom:4px">${esc(p.name)} <span class="badge badge-purple">Priorité ${p.priority}</span></div>
          <div style="font-size:12px;color:var(--c-text-light);margin-bottom:6px">${esc(p.description || '')}</div>
          ${(p.grants || []).map(g => `<div style="font-size:12.5px">🎁 ${esc(g)}</div>`).join('')}
          <div class="mono" style="color:var(--c-text-lighter);margin-top:6px">${esc(p.plan_id)}</div>
        </div>`).join('') : '<div class="empty"><p>Aucune activité à récupérer</p></div>'}
      <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Fermer</button>
      ${plans.length ? `<button class="btn btn-primary" onclick="claimNow(${id})">Récupérer la priorité la plus haute</button>` : ''}</div>`);
  } catch (e) { toast('Échec de détection : ' + e.message, 'error'); }
}

async function detectAllAccounts() {
  const list = accountsCache.length ? accountsCache : (await api('/api/accounts')).accounts || [];
  toast(`Détection des activités de ${list.length} comptes…`, 'info');
  let found = 0;
  for (const a of list) {
    try {
      const r = await api(`/api/accounts/${a.id}/detect`);
      if ((r.plans || []).length) found++;
    } catch (e) { /* continue */ }
  }
  toast(`Détection terminée : ${found}/${list.length} comptes ont des activités`);
  loadClaimRecords();
}

async function resetQuota(id) {
  closeModal();
  toast('Recherche des possibilités de réinitialisation…', 'info');
  try {
    const st = await api(`/api/accounts/${id}/reset-status`);
    if (!st.ok) {
      openModal(`<h3>Réinitialisation du quota</h3><div class="empty"><p>${esc(st.message || 'Indisponible')}</p></div>
        <div class="hint" style="margin-top:10px">Interface réservée aux comptes Coding Plan payants (Start Plan renvoie 3101 coding plan is required).</div>
        <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Fermer</button></div>`);
      return;
    }
    const s = st.status;
    const five = (s.available_five_hour_resets || []).length;
    const week = (s.available_week_resets || []).length;
    openModal(`<h3>Possibilités de réinitialisation</h3>
      <div class="kv-grid" style="margin-bottom:14px">
        <div class="kv-item"><div class="k">Fenêtre de 5 heures</div><div class="v">${five} disponible(s)</div></div>
        <div class="kv-item"><div class="k">Réinitialisation hebdo</div><div class="v">${week} disponible(s)</div></div>
        <div class="kv-item"><div class="k">Dernière 5 h</div><div class="v">${s.latest_five_hour_reset_history ? fmtEpoch(s.latest_five_hour_reset_history.used_at) : 'Aucune'}</div></div>
        <div class="kv-item"><div class="k">Dernière hebdo</div><div class="v">${s.latest_week_reset_history ? fmtEpoch(s.latest_week_reset_history.used_at) : 'Aucune'}</div></div>
      </div>
      <div class="hint">Consomme une possibilité pour restaurer immédiatement le quota de la fenêtre (priorité five_hour).</div>
      <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
      <button class="btn btn-warning" onclick="doReset(${id})" ${five + week === 0 ? 'disabled' : ''}>Exécuter</button></div>`);
  } catch (e) { toast(e.message, 'error'); }
}

async function doReset(id) {
  closeModal();
  toast('Réinitialisation du quota en cours…', 'info');
  try {
    const r = await api(`/api/accounts/${id}/reset`, { method: 'POST' });
    if (r.ok) toast(r.message || 'Réinitialisation réussie');
    else toast('Échec de réinitialisation : ' + r.message, 'error');
    loadAccounts();
  } catch (e) { toast(e.message, 'error'); }
}

async function activateNow(id) {
  closeModal();
  toast('Envoi de l’événement d’activation…', 'info');
  try {
    const r = await api(`/api/accounts/${id}/activate`, { method: 'POST' });
    if (r.ok) toast('Activation réussie : ' + (r.message || ''));
    else toast('Activation incomplète : ' + r.message, 'error');
    loadAccounts();
  } catch (e) { toast('Échec d’activation : ' + e.message, 'error'); }
}

function editAccount(id) {
  closeModal();
  const a = accountsCache.find(x => x.id === id);
  if (!a) return;
  openModal(`<h3>Modifier le compte</h3>
    <div class="form-group"><label>Groupe</label><select id="editGroup">${groupOptions(a.group)}</select></div>
    <div class="form-group"><label>Note</label><input type="text" id="editRemark" value="${esc(a.remark)}"></div>
    <div class="form-group"><label><input type="checkbox" id="editEnabled" ${a.enabled ? 'checked' : ''} style="width:auto;margin-right:6px">Activer (participe à la rotation)</label></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="submitEditAccount(${id})">Enregistrer</button></div>`);
}

async function submitEditAccount(id) {
  let group = document.getElementById('editGroup').value;
  if (group === '__new__') {
    group = prompt('Nom du nouveau groupe :');
    if (!group) return;
  }
  try {
    await api(`/api/accounts/${id}`, { method: 'PUT', body: {
      group, remark: document.getElementById('editRemark').value,
      enabled: document.getElementById('editEnabled').checked,
    }});
    closeModal(); toast('Enregistré'); loadGroups(); loadAccounts();
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteAccount(id) {
  closeModal();
  const a = accountsCache.find(x => x.id === id);
  if (!confirm(`Supprimer le compte ${a ? (a.email || a.display_name) : id} ? Cette action est irréversible.`)) return;
  try {
    await api(`/api/accounts/${id}`, { method: 'DELETE' });
    toast('Supprimé'); loadAccounts(); loadDashboard();
  } catch (e) { toast(e.message, 'error'); }
}

async function switchBack(id) {
  closeModal();
  const a = accountsCache.find(x => x.id === id);
  openModal(`<h3>Rebascule vers le client local</h3>
    <p style="font-size:13px;color:var(--c-text-light);margin-bottom:14px">
    Les identifiants du compte <b>${esc(a ? a.email || a.display_name : id)}</b> seront rechiffrés et réécrits sur cette machine
    dans <span class="mono">~/.zcode/v2/credentials.json</span> et <span class="mono">config.json</span> (les fichiers d’origine sont sauvegardés dans data/backups/).</p>
    <div class="form-group"><label><input type="checkbox" id="killClient" style="width:auto;margin-right:6px">Arrêter le processus ZCode.exe après écriture (effectif au prochain démarrage)</label></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-warning" onclick="doSwitchBack(${id})">Confirmer</button></div>`);
}

async function doSwitchBack(id) {
  const kill = document.getElementById('killClient').checked;
  try {
    const r = await api(`/api/accounts/${id}/switch-back`, { method: 'POST', body: { kill_client: kill } });
    closeModal(); toast(r.message || 'Rebasculé vers le client local');
  } catch (e) { toast('Échec de rebascule : ' + e.message, 'error'); }
}

async function restoreLocal(id) {
  closeModal();
  if (!confirm('Remplacer l’état de connexion du client local par le snapshot d’import de ce compte ?')) return;
  try {
    const r = await api(`/api/accounts/${id}/restore-local`, { method: 'POST' });
    toast(r.message || 'Restauré');
  } catch (e) { toast('Échec de restauration : ' + e.message, 'error'); }
}

// ---- Import de comptes ----

async function importLocalAccount() {
  toast('Import depuis le client ZCode local…', 'info');
  try {
    const group = document.getElementById('groupFilter')?.value || '';
    const r = await api('/api/accounts/import/local', { method: 'POST', body: { group } });
    toast('Import réussi : ' + (r.account.email || r.account.display_name));
    switchSection('accounts');
  } catch (e) { toast('Échec de l’import : ' + e.message, 'error'); }
}

function showPasteModal() {
  openModal(`<h3>Import par collage</h3>
    <div class="form-group"><label>Canal</label>
      <select id="pasteProvider"><option value="zai">Z.AI (zcode.z.ai)</option><option value="bigmodel">BigModel (open.bigmodel.cn)</option></select></div>
    <div class="form-group"><label>Nom (optionnel)</label><input type="text" id="pasteName" placeholder="Nom du compte"></div>
    <div class="form-group"><label>Identifiants (JWT ou clé API)</label>
      <textarea id="pasteSecret" placeholder="eyJhbGci… JWT à trois segments, ou clé API au format xxx.yyy"></textarea></div>
    <div class="form-group"><label>Groupe</label><select id="pasteGroup">${groupOptions('')}</select></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="submitPaste()">Importer</button></div>`);
}

async function submitPaste() {
  let group = document.getElementById('pasteGroup').value;
  if (group === '__new__') { group = prompt('Nom du nouveau groupe :'); if (!group) return; }
  try {
    const r = await api('/api/accounts/import/paste', { method: 'POST', body: {
      provider: document.getElementById('pasteProvider').value,
      name: document.getElementById('pasteName').value,
      secret: document.getElementById('pasteSecret').value.trim(),
      group,
    }});
    closeModal(); toast('Import réussi'); switchSection('accounts');
  } catch (e) { toast('Échec de l’import : ' + e.message, 'error'); }
}

// ---- Connexion OAuth ----

let oauthPollTimer = null;

function showOAuthModal() {
  openModal(`<h3>Connexion OAuth (nouveau compte)</h3>
    <div class="form-group"><label>Groupe</label><select id="oauthGroup">${groupOptions('')}</select></div>
    <div class="form-group"><label>Méthode</label>
      <select id="oauthMode">
        <option value="manual">Collage manuel (recommandé : Z.AI n’enregistre que le retour zcode.z.ai/login)</option>
        <option value="auto">Retour automatique loopback (expérimental : renvoie Redirect URI not registered)</option>
      </select></div>
    <div id="oauthStep2"></div>
    <div class="actions"><button class="btn btn-secondary" onclick="cancelOAuth()">Annuler</button>
    <button class="btn btn-primary" id="oauthStartBtn" onclick="startOAuth()">Démarrer</button></div>`);
}

async function startOAuth() {
  let group = document.getElementById('oauthGroup').value;
  if (group === '__new__') { group = prompt('Nom du nouveau groupe :'); if (!group) return; }
  const manual = document.getElementById('oauthMode').value === 'manual';
  const btn = document.getElementById('oauthStartBtn');
  btn.disabled = true;
  try {
    const r = await api('/api/accounts/oauth/start', { method: 'POST', body: { manual, group } });
    window._oauthState = r.state;
    if (!manual) {
      window.open(r.authorize_url, '_blank');
      document.getElementById('oauthStep2').innerHTML =
        `<div class="hint" style="margin-top:10px">La page d’autorisation Z.AI s’est ouverte dans un nouvel onglet ; après connexion et autorisation, retour automatique vers cette passerelle.</div>
         <div class="hint" style="margin-top:6px;color:var(--c-warning-dark)">Si le navigateur ne revient pas automatiquement (ou si la page Z.AI affiche une erreur), copiez l’URL complète de la barre d’adresse et repassez en mode « Collage manuel ».</div>
         <div id="oauthStatus" style="margin-top:8px;font-size:13px"></div>`;
      pollOAuth();
    } else {
      window.open(r.authorize_url, '_blank');
      document.getElementById('oauthStep2').innerHTML =
        `<div class="hint" style="margin-top:10px">La page d’autorisation Z.AI s’est ouverte dans un nouvel onglet. Étapes : ① connectez-vous et acceptez → ② le navigateur redirige vers <b>zcode.z.ai/login?code=…</b> → ③ copiez l’<b>URL complète</b> → ④ collez-la ci-dessous puis validez.</div>
         <div class="form-group" style="margin-top:10px"><label>Coller l’URL de retour (ou le code seul)</label>
         <textarea id="oauthManualInput" class="form-textarea" style="min-height:70px" placeholder="https://zcode.z.ai/login?code=...&state=..."></textarea></div>
         <button class="btn btn-success" onclick="submitOAuthManual()">Valider l’échange</button>
         <div id="oauthStatus" style="margin-top:8px;font-size:13px"></div>`;
    }
  } catch (e) {
    btn.disabled = false;
    toast('Échec du démarrage de connexion : ' + e.message, 'error');
  }
}

async function submitOAuthManual() {
  const input = document.getElementById('oauthManualInput').value.trim();
  if (!input) return toast('Collez l’URL de retour ou le code', 'error');
  const st = document.getElementById('oauthStatus');
  st.textContent = 'Échange en cours…';
  try {
    await api('/api/accounts/oauth/manual', { method: 'POST', body: { state: window._oauthState, input } });
    st.textContent = '';
    toast('Connexion réussie, compte enregistré');
    cancelOAuth();
    switchSection('accounts');
  } catch (e) { st.textContent = ''; toast(e.message, 'error'); }
}

function pollOAuth() {
  clearInterval(oauthPollTimer);
  oauthPollTimer = setInterval(async () => {
    if (!window._oauthState) return;
    try {
      const f = await api('/api/accounts/oauth/status?state=' + encodeURIComponent(window._oauthState));
      const el = document.getElementById('oauthStatus');
      if (f.status === 'ready') {
        clearInterval(oauthPollTimer);
        toast('Connexion réussie : ' + (f.email || ''));
        setTimeout(() => { closeModal(); switchSection('accounts'); }, 800);
      } else if (f.status === 'failed') {
        clearInterval(oauthPollTimer);
        if (el) el.innerHTML = `<span style="color:var(--c-danger)">${esc(f.message)}</span>`;
        document.getElementById('oauthStartBtn').disabled = false;
      } else if (el && f.status === 'exchanging') {
        el.textContent = 'Échange du token et extraction de la clé API…';
      }
    } catch (e) { /* flux expiré */ }
  }, 1500);
}

function cancelOAuth() {
  clearInterval(oauthPollTimer);
  window._oauthState = null;
  closeModal();
}

// ---- Plans d'activités ----

let plansCache = [];

async function loadPlans() {
  try {
    const d = await api('/api/plans');
    plansCache = d.plans || [];
    renderPlans();
  } catch (e) { toast(e.message, 'error'); }
}

const TASK_LABEL = { detect: 'Détecter', claim: 'Récupérer', activate: 'Activer', reset: 'Réinitialiser quota' };

function renderPlans() {
  const el = document.getElementById('plansTable');
  if (!plansCache.length) {
    el.innerHTML = '<div class="empty"><p>Aucun plan. Cliquez sur « + Nouveau plan » pour en créer un</p></div>';
    return;
  }
  el.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>Plan</th><th>Tâche</th><th>cron</th><th>Cible</th><th>Intervalle</th><th>Prochaine</th><th>Dernière</th><th>Statut</th><th style="width:190px">Actions</th></tr></thead>
    <tbody>${plansCache.map(p => `
      <tr>
        <td style="font-weight:700">${esc(p.plan_name)}</td>
        <td><span class="badge badge-info">${TASK_LABEL[p.task_type] || p.task_type}</span></td>
        <td class="mono">${esc(p.cron_expr)}</td>
        <td>${p.target_type === 'single_account' ? 'Compte #' + p.account_id : p.target_type === 'group' ? 'Groupe : ' + esc(p.account_group) : 'Tous les comptes'}</td>
        <td>${p.delay_seconds}s</td>
        <td style="font-size:12px">${esc(p.next_run_at || '-')}</td>
        <td style="font-size:12px">${esc(p.last_run_at || '-')}<div style="color:var(--c-text-lighter);font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(p.last_run_msg || '')}">${esc(p.last_run_msg || '')}</div></td>
        <td>${p.is_active ? '<span class="badge badge-success">Actif</span>' : '<span class="badge badge-secondary">Désactivé</span>'}
            ${p.last_run_status ? `<div style="margin-top:3px">${p.last_run_status === 'success' ? '✅' : '❌'}</div>` : ''}</td>
        <td class="actions-cell">
          <button class="btn btn-sm btn-primary" onclick="runPlan(${p.id})">Exécuter</button>
          <button class="btn btn-sm btn-secondary" onclick="showPlanModal(${p.id})">Modifier</button>
          <button class="btn btn-sm btn-danger" onclick="deletePlan(${p.id})">Supprimer</button>
        </td>
      </tr>`).join('')}</tbody></table></div>`;
}

function showPlanModal(id) {
  const p = plansCache.find(x => x.id === id) || {};
  const accountOpts = (accountsCache.length ? accountsCache : []).map(a =>
    `<option value="${a.id}" ${p.account_id === a.id ? 'selected' : ''}>${esc(a.email || a.display_name || ('#' + a.id))}</option>`).join('');
  openModal(`<h3>${id ? 'Modifier le plan' : 'Nouveau plan'}</h3>
    <div class="form-group"><label>Nom du plan</label><input type="text" id="planName" value="${esc(p.plan_name || '')}" placeholder="ex. : Récupération quotidienne"></div>
    <div class="form-group"><label>Type de tâche</label>
      <select id="planTask">
        <option value="claim" ${p.task_type === 'claim' ? 'selected' : ''}>Récupération complète (détection + captcha + récupération)</option>
        <option value="detect" ${p.task_type === 'detect' ? 'selected' : ''}>Détection seule</option>
        <option value="activate" ${p.task_type === 'activate' ? 'selected' : ''}>Activation du forfait (événement)</option>
        <option value="reset" ${p.task_type === 'reset' ? 'selected' : ''}>Réinitialisation du quota (restaure la fenêtre épuisée)</option>
      </select></div>
    <div class="form-group"><label>Expression cron (min heure jour mois semaine)</label>
      <input type="text" id="planCron" class="mono" value="${esc(p.cron_expr || '0 9 * * *')}" placeholder="0 9 * * *">
      <div class="hint">Exemples : 0 9 * * * = tous les jours à 09:00 ; */30 * * * * = toutes les 30 minutes</div></div>
    <div class="form-group"><label>Cible</label>
      <select id="planTarget" onchange="planTargetChange()">
        <option value="all_accounts" ${p.target_type === 'all_accounts' || !p.target_type ? 'selected' : ''}>Tous les comptes disponibles</option>
        <option value="group" ${p.target_type === 'group' ? 'selected' : ''}>Groupe précis</option>
        <option value="single_account" ${p.target_type === 'single_account' ? 'selected' : ''}>Un seul compte</option>
      </select></div>
    <div class="form-group" id="planGroupWrap" style="display:none"><label>Groupe</label><select id="planGroup">${groupOptions(p.account_group || '')}</select></div>
    <div class="form-group" id="planAccountWrap" style="display:none"><label>Compte</label><select id="planAccount"><option value="0">Choisir un compte</option>${accountOpts}</select></div>
    <div class="form-group"><label>Intervalle entre comptes (s, anti-contrôle, avec jitter aléatoire 0~50 %)</label>
      <input type="number" id="planDelay" value="${p.delay_seconds ?? 30}" min="0" max="3600"></div>
    <div class="form-group"><label><input type="checkbox" id="planActive" ${p.is_active !== false ? 'checked' : ''} style="width:auto;margin-right:6px">Activer</label></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="savePlan(${id || 0})">Enregistrer</button></div>`);
  planTargetChange();
}

function planTargetChange() {
  const t = document.getElementById('planTarget').value;
  document.getElementById('planGroupWrap').style.display = t === 'group' ? '' : 'none';
  document.getElementById('planAccountWrap').style.display = t === 'single_account' ? '' : 'none';
}

async function savePlan(id) {
  let group = '';
  const gw = document.getElementById('planGroupWrap');
  if (gw.style.display !== 'none') {
    group = document.getElementById('planGroup').value;
    if (group === '__new__') { group = prompt('Nom du nouveau groupe :'); if (!group) return; }
  }
  const body = {
    plan_name: document.getElementById('planName').value.trim() || 'Plan sans nom',
    task_type: document.getElementById('planTask').value,
    cron_expr: document.getElementById('planCron').value.trim(),
    target_type: document.getElementById('planTarget').value,
    account_group: group,
    account_id: Number(document.getElementById('planAccount')?.value || 0),
    delay_seconds: Number(document.getElementById('planDelay').value || 0),
    is_active: document.getElementById('planActive').checked,
    auto_pick: true,
  };
  try {
    if (id) await api('/api/plans/' + id, { method: 'PUT', body });
    else await api('/api/plans', { method: 'POST', body });
    closeModal(); toast('Plan enregistré'); loadPlans();
  } catch (e) { toast(e.message, 'error'); }
}

async function deletePlan(id) {
  if (!confirm('Supprimer ce plan ?')) return;
  try { await api('/api/plans/' + id, { method: 'DELETE' }); toast('Supprimé'); loadPlans(); }
  catch (e) { toast(e.message, 'error'); }
}

async function runPlan(id) {
  try { await api(`/api/plans/${id}/run`, { method: 'POST' }); toast('Exécution lancée, voir la progression en haut', 'info'); }
  catch (e) { toast(e.message, 'error'); }
}

async function pollRunning() {
  try {
    const d = await api('/api/plans/running');
    const bar = document.getElementById('planRunningBar');
    if (!bar) return;
    const running = d.running || [];
    if (!running.length) { bar.innerHTML = ''; return; }
    bar.innerHTML = running.map(s => `
      <div class="running-bar">
        <span class="rb-title">▶ ${esc(s.plan_name)} (${TASK_LABEL[s.task_type] || s.task_type})</span>
        <div class="progress-track" style="flex:1;min-width:120px"><div class="progress-fill" style="width:${s.total ? s.done / s.total * 100 : 0}%"></div></div>
        <span class="rb-meta">${s.done}/${s.total} · ✅${s.success} ❌${s.fail}${s.current_account ? ' · ' + esc(s.current_account) : ''}</span>
      </div>`).join('');
  } catch (e) { /* ignore */ }
}

async function loadClaimRecords() {
  try {
    const d = await api('/api/claim-records?limit=60');
    const el = document.getElementById('claimRecordsTable');
    const recs = d.records || [];
    if (!recs.length) { el.innerHTML = '<div class="empty"><p>Aucune récupération</p></div>'; return; }
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Date</th><th>Compte</th><th>Type</th><th>Activité</th><th>Résultat</th><th>Message</th></tr></thead>
      <tbody>${recs.map(r => `<tr>
        <td style="font-size:12px">${esc(r.created_at)}</td>
        <td>${esc(r.email || ('#' + r.account_id))}</td>
        <td><span class="badge badge-info">${TASK_LABEL[r.task_type] || r.task_type}</span></td>
        <td>${esc(r.plan_name || r.plan_id || '-')}</td>
        <td>${r.success ? '<span class="badge badge-success">Réussi</span>' : '<span class="badge badge-danger">Échec</span>'}${r.code ? ` <span class="mono" style="font-size:11px">code=${r.code}</span>` : ''}</td>
        <td style="max-width:280px" title="${esc(r.message)}">${esc(r.message || '')}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } catch (e) { /* ignore */ }
}

async function loadPlanRuns() {
  try {
    const d = await api('/api/plan-runs?limit=40');
    const el = document.getElementById('planRunsTable');
    const recs = d.records || [];
    if (!recs.length) { el.innerHTML = '<div class="empty"><p>Aucune exécution</p></div>'; return; }
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Date</th><th>Plan</th><th>Tâche</th><th>Statut</th><th>Réussis/Échecs</th><th>Durée</th><th>Résumé</th></tr></thead>
      <tbody>${recs.map(r => `<tr>
        <td style="font-size:12px">${esc(r.run_at)}</td>
        <td>${esc(r.plan_name)}</td>
        <td><span class="badge badge-info">${TASK_LABEL[r.task_type] || r.task_type}</span></td>
        <td>${r.status === 'success' ? '<span class="badge badge-success">Réussi</span>' : '<span class="badge badge-danger">Échec</span>'}</td>
        <td>${r.success_count} / ${r.fail_count}</td>
        <td>${(r.duration_ms / 1000).toFixed(1)}s</td>
        <td style="max-width:320px" title="${esc(r.message)}">${esc(r.message || '')}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } catch (e) { /* ignore */ }
}

// ---- Utilisation ----

async function loadUsageStats() {
  try {
    const u = await api('/api/stats?days=7');
    document.getElementById('uStatReq').textContent = fmtNum(u.requests);
    document.getElementById('uStatIn').textContent = fmtNum(u.prompt_tokens);
    document.getElementById('uStatOut').textContent = fmtNum(u.completion_tokens);
    document.getElementById('uStatDur').textContent = (u.avg_duration_ms || 0) + 'ms';
    document.getElementById('uStatTtft').textContent = (u.avg_ttft_ms || 0) + 'ms';
  } catch (e) { /* ignore */ }
}

async function loadUsageRecords() {
  try {
    const d = await api('/api/usage-records?limit=100');
    const el = document.getElementById('usageTable');
    const recs = d.records || [];
    if (!recs.length) { el.innerHTML = '<div class="empty"><p>Aucune utilisation</p></div>'; return; }
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Date</th><th>Compte</th><th>Modèle</th><th>Entrée</th><th>Sortie</th><th>Total</th><th>Stream</th><th>Statut</th><th>Durée</th><th>TTFT</th></tr></thead>
      <tbody>${recs.map(r => `<tr>
        <td style="font-size:12px">${esc(r.created_at)}</td>
        <td>${esc(r.email || ('#' + r.account_id))}</td>
        <td>${esc(r.model)}</td>
        <td>${fmtNum(r.prompt_tokens)}</td>
        <td>${fmtNum(r.completion_tokens)}</td>
        <td><b>${fmtNum(r.total_tokens)}</b></td>
        <td>${r.stream ? '✓' : '-'}</td>
        <td>${r.status_code === 200 ? '<span class="badge badge-success">200</span>' : `<span class="badge badge-danger">${r.status_code}</span>`}</td>
        <td>${(r.duration_ms / 1000).toFixed(1)}s</td>
        <td>${r.ttft_ms ? r.ttft_ms + 'ms' : '-'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  } catch (e) { /* ignore */ }
}

// ---- Paramètres ----

async function loadSettings() {
  try {
    const s = await api('/api/settings');
    document.getElementById('setStrategy').value = s.selection_strategy || 'round_robin';
    document.getElementById('setQuotaInterval').value = s.quota_refresh_interval || '60';
    document.getElementById('setGlobalProxy').value = s.upstream_proxy || '';
    document.getElementById('setCaptchaMode').value = s.captcha_mode || 'auto';
    document.getElementById('setGatewayModels').value = s.gateway_models || '';
    window._fpCurrent = s.fingerprint || 'chrome';
    window._ja3Current = s.custom_ja3 || '';
    loadGatewayKey();
    loadModels();
    loadCaptchaStatus();
    loadProxies();
    loadFingerprints();
  } catch (e) { /* ignore */ }
}

// ---- Empreinte TLS ----

async function loadFingerprints() {
  try {
    const d = await api('/api/fingerprints');
    const sel = document.getElementById('setFingerprint');
    const groups = {};
    (d.fingerprints || []).forEach(f => { (groups[f.group] = groups[f.group] || []).push(f); });
    sel.innerHTML = Object.entries(groups).map(([g, list]) =>
      `<optgroup label="${esc(g)}">` + list.map(f =>
        `<option value="${esc(f.id)}">${esc(f.label)}</option>`).join('') + '</optgroup>').join('');
    // Sélectionner la valeur active ; si absente (ancienne base), repli sur chrome
    const cur = window._fpCurrent || 'chrome';
    sel.value = [...sel.options].some(o => o.value === cur) ? cur : 'chrome';
    document.getElementById('setCustomJA3').value = window._ja3Current || '';
    const hint = document.getElementById('fpCurrentHint');
    if (hint) hint.textContent = 'En vigueur : ' + sel.value + ' (effectif pour les nouvelles connexions)';
    fpModeChange();
  } catch (e) { /* ignore */ }
}

function fpModeChange() {
  const v = document.getElementById('setFingerprint').value;
  document.getElementById('ja3Wrap').style.display = v === 'custom' ? '' : 'none';
}

async function saveFingerprint() {
  try {
    await api('/api/settings', { method: 'PUT', body: {
      fingerprint: document.getElementById('setFingerprint').value,
      custom_ja3: document.getElementById('setCustomJA3').value.trim(),
    }});
    toast('Paramètres d\'empreinte enregistrés (effectifs sur les nouvelles connexions)');
  } catch (e) { toast(e.message, 'error'); }
}

async function saveStrategySettings() {
  try {
    await api('/api/settings', { method: 'PUT', body: {
      selection_strategy: document.getElementById('setStrategy').value,
      quota_refresh_interval: document.getElementById('setQuotaInterval').value,
    }});
    toast('Stratégie enregistrée');
  } catch (e) { toast(e.message, 'error'); }
}

async function saveCaptchaSettings() {
  try {
    await api('/api/settings', { method: 'PUT', body: { captcha_mode: document.getElementById('setCaptchaMode').value } });
    toast('Paramètres captcha enregistrés');
  } catch (e) { toast(e.message, 'error'); }
}

async function saveModelsSettings() {
  try {
    await api('/api/settings', { method: 'PUT', body: { gateway_models: document.getElementById('setGatewayModels').value.trim() } });
    toast('Liste des modèles enregistrée'); loadModels();
  } catch (e) { toast(e.message, 'error'); }
}

async function loadModels() {
  try {
    const d = await api('/api/models');
    document.getElementById('currentModels').innerHTML =
      'En vigueur : ' + (d.models || []).map(m => `<span class="pill-group" style="margin:2px">${esc(m)}</span>`).join('');
    loadCatalog();
  } catch (e) { /* ignore */ }
}

async function loadCatalog() {
  try {
    const d = await api('/api/models/catalog');
    const el = document.getElementById('catalogModels');
    if (!el) return;
    const ms = d.models || [];
    el.innerHTML = ms.length
      ? ms.map(m => `<span class="pill-group" style="margin:2px" title="${esc(`ctx=${m.contextWindow} prio=${m.priority}${m.vision ? ' vision' : ''}`)}">${esc(m.modelId)}</span>`).join('')
      : '<span style="color:var(--c-text-lighter)">Non synchronisé, cliquez sur « Synchroniser le catalogue officiel »</span>';
  } catch (e) { /* ignore */ }
}

async function syncModelCatalog() {
  toast('Synchronisation du catalogue officiel…', 'info');
  try {
    const r = await api('/api/models/sync', { method: 'POST' });
    toast(`${r.total} modèle(s) synchronisé(s)`);
    loadCatalog();
  } catch (e) { toast(e.message, 'error'); }
}

async function applyCatalogToGateway() {
  try {
    const d = await api('/api/models/catalog');
    const ids = (d.models || []).map(m => m.modelId);
    if (!ids.length) return toast('Catalogue vide, veuillez d’abord synchroniser', 'error');
    await api('/api/settings', { method: 'PUT', body: { gateway_models: ids.join(',') } });
    toast('Catalogue appliqué à la liste de la passerelle');
    loadModels();
  } catch (e) { toast(e.message, 'error'); }
}

async function loadGatewayKey() {
  try {
    const d = await api('/api/settings/api-key');
    document.getElementById('gatewayKeyDisplay').value = d.api_key || '';
  } catch (e) { /* ignore */ }
}

async function generateAPIKey() {
  if (!confirm('L’ancienne clé sera immédiatement invalidée après régénération. Confirmer ?')) return;
  try {
    const d = await api('/api/settings/api-key/generate', { method: 'POST' });
    document.getElementById('gatewayKeyDisplay').value = d.api_key;
    toast('Nouvelle clé API générée');
  } catch (e) { toast(e.message, 'error'); }
}

function copyGatewayKey() {
  const v = document.getElementById('gatewayKeyDisplay').value;
  if (!v) return toast('Pas encore générée', 'error');
  navigator.clipboard.writeText(v).then(() => toast('Copié'));
}

async function changePassword() {
  try {
    await api('/api/auth/password', { method: 'POST', body: {
      old_password: document.getElementById('oldPassword').value,
      new_password: document.getElementById('newPassword').value,
    }});
    toast('Mot de passe modifié, veuillez vous reconnecter'); setTimeout(doLogout, 1200);
  } catch (e) { toast(e.message, 'error'); }
}

// ---- État du captcha ----

async function loadCaptchaStatus() {
  try {
    const c = await api('/api/captcha/status');
    const el = document.getElementById('captchaStatus');
    if (!el) return;
    el.innerHTML = c.has_param
      ? `Paramètre actuel : ${c.fresh ? '✅ Frais' : '⏳ Expiré (' + c.param_age_s + 's)'}${c.config ? ' · scene=' + esc(c.config.scene_id) : ''}`
      : 'Aucun paramètre en cache (résolu automatiquement à la prochaine requête)';
  } catch (e) { /* ignore */ }
}

async function solveCaptchaNow() {
  toast('Résolution du captcha en cours (navigateur headless env. 5-15 s)…', 'info');
  try {
    const r = await api('/api/captcha/solve', { method: 'POST', body: {} });
    if (r.success) toast(`Résolution réussie (paramètre de ${r.param_len} octets)`);
    else toast('La résolution n’a retourné aucun paramètre', 'error');
    loadCaptchaStatus();
  } catch (e) { toast('Échec de résolution : ' + e.message, 'error'); }
}

async function invalidateCaptcha() {
  try { await api('/api/captcha/invalidate', { method: 'POST' }); toast('Cache invalidé'); loadCaptchaStatus(); }
  catch (e) { toast(e.message, 'error'); }
}

// ---- Proxy de sortie ----

let proxiesCache = [];

async function loadProxies() {
  try {
    const d = await api('/api/proxies');
    proxiesCache = d.proxies || [];
    renderProxies();
  } catch (e) { /* ignore */ }
}

function renderProxies() {
  const el = document.getElementById('proxyTable');
  if (!el) return;
  if (!proxiesCache.length) {
    el.innerHTML = '<div class="empty"><p>Aucun nœud proxy (connexion directe si non configuré)</p></div>';
    return;
  }
  el.innerHTML = `<div class="table-wrap"><table>
    <thead><tr><th>Nom</th><th>Type</th><th>Adresse</th><th>Groupe lié</th><th>Par défaut</th><th>Activé</th><th>Test</th><th style="width:180px">Actions</th></tr></thead>
    <tbody>${proxiesCache.map(n => `<tr>
      <td style="font-weight:700">${esc(n.name || '-')}</td>
      <td>${esc(n.type)}</td>
      <td class="mono">${esc(n.host)}:${n.port}${n.username ? ' · ' + esc(n.username) : ''}</td>
      <td>${n.group_name ? n.group_name.split(',').map(g => `<span class="pill-group" style="margin:1px">${esc(g.trim())}</span>`).join('') : '-'}</td>
      <td>${n.is_default ? '⭐' : '-'}</td>
      <td>${n.enabled ? '<span class="badge badge-success">Oui</span>' : '<span class="badge badge-secondary">Non</span>'}</td>
      <td style="font-size:12px">${n.check_status === 'ok' ? `✅ ${esc(n.check_ip)} ${n.check_latency}ms` : n.check_status === 'fail' ? `❌ ${esc(n.check_msg || '')}` : '-'}
        ${n.check_at ? `<div style="font-size:10.5px;color:var(--c-text-lighter)">${esc(n.check_at)}</div>` : ''}</td>
      <td class="actions-cell">
        <button class="btn btn-sm btn-secondary" onclick="testProxy(${n.id})">Tester</button>
        <button class="btn btn-sm btn-secondary" onclick="showProxyModal(${n.id})">Modifier</button>
        <button class="btn btn-sm btn-danger" onclick="deleteProxy(${n.id})">Supprimer</button>
      </td>
    </tr>`).join('')}</tbody></table></div>`;
}

function showProxyModal(id) {
  const n = proxiesCache.find(x => x.id === id) || { type: 'socks5', enabled: true };
  openModal(`<h3>${id ? 'Modifier le nœud proxy' : 'Ajouter un nœud proxy'}</h3>
    <div class="form-group"><label>Nom</label><input type="text" id="pxName" value="${esc(n.name || '')}" placeholder="ex. : Proxy résidentiel USA"></div>
    <div class="form-group"><label>Type</label><select id="pxType">
      <option value="socks5" ${n.type === 'socks5' ? 'selected' : ''}>SOCKS5</option>
      <option value="http" ${n.type === 'http' ? 'selected' : ''}>HTTP(S)</option></select></div>
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:10px">
      <div class="form-group"><label>Hôte</label><input type="text" id="pxHost" value="${esc(n.host || '')}" placeholder="127.0.0.1"></div>
      <div class="form-group"><label>Port</label><input type="number" id="pxPort" value="${n.port || ''}" placeholder="7897"></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div class="form-group"><label>Nom d’utilisateur (optionnel)</label><input type="text" id="pxUser" value="${esc(n.username || '')}"></div>
      <div class="form-group"><label>Mot de passe (optionnel)</label><input type="password" id="pxPass" placeholder="${id ? 'Laisser vide pour conserver' : ''}"></div>
    </div>
    <div class="form-group"><label>Groupes liés (séparés par virgules, vide = non lié)</label><input type="text" id="pxGroup" value="${esc(n.group_name || '')}" placeholder="default,work"></div>
    <div class="form-group"><label>
      <input type="checkbox" id="pxDefault" ${n.is_default ? 'checked' : ''} style="width:auto;margin-right:6px">Nœud par défaut (les comptes sans groupe passent par ici)
      <input type="checkbox" id="pxEnabled" ${n.enabled !== false ? 'checked' : ''} style="width:auto;margin:0 6px 0 16px">Activer</label></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="saveProxy(${id || 0})">Enregistrer</button></div>`);
}

async function saveProxy(id) {
  const body = {
    name: document.getElementById('pxName').value.trim(),
    type: document.getElementById('pxType').value,
    host: document.getElementById('pxHost').value.trim(),
    port: Number(document.getElementById('pxPort').value || 0),
    username: document.getElementById('pxUser').value.trim(),
    password: document.getElementById('pxPass').value,
    group_name: document.getElementById('pxGroup').value.trim(),
    is_default: document.getElementById('pxDefault').checked,
    enabled: document.getElementById('pxEnabled').checked,
  };
  try {
    if (id) await api('/api/proxies/' + id, { method: 'PUT', body });
    else await api('/api/proxies', { method: 'POST', body });
    closeModal(); toast('Enregistré'); loadProxies(); loadGroups();
  } catch (e) { toast(e.message, 'error'); }
}

async function deleteProxy(id) {
  if (!confirm('Supprimer ce nœud proxy ?')) return;
  try { await api('/api/proxies/' + id, { method: 'DELETE' }); toast('Supprimé'); loadProxies(); }
  catch (e) { toast(e.message, 'error'); }
}

async function testProxy(id) {
  toast('Test en cours…', 'info');
  try {
    const r = await api(`/api/proxies/${id}/test`, { method: 'POST' });
    if (r.ok) toast(`IP de sortie : ${r.exit_ip} (${r.elapsed_ms}ms)`);
    else toast('Échec du test : ' + (r.message || ''), 'error');
    loadProxies();
  } catch (e) { toast('Échec du test : ' + e.message, 'error'); }
}

async function probeProxyPorts() {
  try {
    const d = await api('/api/proxies/probe-ports');
    const ports = d.ports || [];
    if (!ports.length) return toast('Aucun port proxy local ouvert détecté', 'error');
    openModal(`<h3>Détection des ports proxy locaux</h3>
      ${ports.map(p => `<div style="display:flex;justify-content:space-between;align-items:center;padding:9px 4px;border-bottom:1px solid var(--c-border-light)">
        <div><b class="mono">${esc(p.url)}</b><div style="font-size:11.5px;color:var(--c-text-light)">${esc(p.label)}</div></div>
        <button class="btn btn-sm btn-primary" data-url="${esc(p.url)}" onclick="useProbedPort(this.dataset.url)">Utiliser</button></div>`).join('')}
      <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Fermer</button></div>`);
  } catch (e) { toast(e.message, 'error'); }
}

function useProbedPort(url) {
  closeModal();
  document.getElementById('setGlobalProxy').value = url;
  saveGlobalProxy();
}

async function detectSystemProxy() {
  try {
    const d = await api('/api/proxies/system');
    if (d.enabled && d.url) {
      document.getElementById('setGlobalProxy').value = d.url;
      toast('Proxy système renseigné : ' + d.url, 'info');
    } else toast('Aucun proxy système activé', 'error');
  } catch (e) { toast(e.message, 'error'); }
}

async function saveGlobalProxy() {
  try {
    await api('/api/settings', { method: 'PUT', body: { upstream_proxy: document.getElementById('setGlobalProxy').value.trim() } });
    toast('Proxy global enregistré');
  } catch (e) { toast(e.message, 'error'); }
}

async function testGlobalProxy() {
  const url = document.getElementById('setGlobalProxy').value.trim();
  const el = document.getElementById('globalProxyTest');
  el.textContent = 'Test en cours…';
  try {
    const r = await api('/api/proxies/test-url', { method: 'POST', body: { url } });
    el.innerHTML = r.ok
      ? `✅ IP de sortie : <b>${esc(r.exit_ip)}</b> (${r.elapsed_ms}ms)`
      : `❌ ${esc(r.message || 'Indisponible')}`;
  } catch (e) { el.textContent = '❌ ' + e.message; }
}

// ---- Migration par paquet de comptes chiffré ----

function showExportBundleModal() {
  openModal(`<h3>Exporter le paquet de comptes chiffré</h3>
    <p style="font-size:13px;color:var(--c-text-light);margin-bottom:12px">Exporte les identifiants de tous les comptes (JWT / clé API / empreinte appareil / snapshot local), chiffrés en PBKDF2+AES-256-GCM, transférables entre machines.</p>
    <div class="form-group"><label>Mot de passe de chiffrement</label><input type="password" id="expPass" placeholder="Le même mot de passe sera requis à l'import"></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="doExportBundle()">Générer le paquet</button></div>`);
}

async function doExportBundle() {
  const pass = document.getElementById('expPass').value;
  if (!pass) return toast('Veuillez définir un mot de passe', 'error');
  try {
    const r = await api('/api/accounts/export', { method: 'POST', body: { password: pass } });
    openModal(`<h3>Paquet de comptes généré</h3>
      <div class="form-group"><textarea id="bundleText" style="min-height:160px">${esc(r.bundle)}</textarea></div>
      <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Fermer</button>
      <button class="btn btn-primary" onclick="navigator.clipboard.writeText(document.getElementById('bundleText').value).then(()=>toast('Copié'))">Copier</button></div>`);
  } catch (e) { toast(e.message, 'error'); }
}

function showImportBundleModal() {
  openModal(`<h3>Importer un paquet de comptes chiffré</h3>
    <div class="form-group"><label>Mot de passe de déchiffrement</label><input type="password" id="impPass"></div>
    <div class="form-group"><label>Contenu du paquet (commence par zcb1:)</label><textarea id="impBundle" placeholder="zcb1:..."></textarea></div>
    <div class="actions"><button class="btn btn-secondary" onclick="closeModal()">Annuler</button>
    <button class="btn btn-primary" onclick="doImportBundle()">Importer</button></div>`);
}

async function doImportBundle() {
  try {
    const r = await api('/api/accounts/import/bundle', { method: 'POST', body: {
      password: document.getElementById('impPass').value,
      bundle: document.getElementById('impBundle').value.trim(),
    }});
    closeModal(); toast(`Import réussi : ${r.imported} compte(s)`); switchSection('accounts');
  } catch (e) { toast(e.message, 'error'); }
}

// ---- Test LLM ----

let llmHistory = [];

async function loadLlmKey() {
  try {
    const d = await api('/api/settings/api-key');
    const el = document.getElementById('llmKey');
    if (el) el.value = d.api_key || '';
  } catch (e) { /* ignore */ }
}

// Extraire le texte incrémental d'une ligne SSE (selon le protocole)
function llmDeltaText(proto, data) {
  try {
    const j = JSON.parse(data);
    if (proto === 'messages') {
      if (j.type === 'content_block_delta' && j.delta && j.delta.type === 'text_delta') return j.delta.text || '';
      return '';
    }
    if (proto === 'chat') {
      const c = (j.choices || [])[0];
      return (c && c.delta && c.delta.content) || '';
    }
    if (proto === 'responses') {
      if (j.type === 'response.output_text.delta') return j.delta || '';
      return '';
    }
  } catch (e) { /* ignore */ }
  return '';
}

// Extraire la réflexion incrémentale d'une ligne SSE
function llmDeltaThink(proto, data) {
  try {
    const j = JSON.parse(data);
    if (proto === 'messages') {
      if (j.type === 'content_block_delta' && j.delta && j.delta.type === 'thinking_delta') return j.delta.thinking || '';
      return '';
    }
    if (proto === 'chat') {
      const c = (j.choices || [])[0];
      return (c && c.delta && c.delta.reasoning_content) || '';
    }
    if (proto === 'responses') {
      if (j.type === 'response.reasoning_summary_text.delta') return j.delta || '';
      return '';
    }
  } catch (e) { /* ignore */ }
  return '';
}

function llmUsageFrom(json, proto) {
  const u = json && json.usage;
  if (!u) return null;
  if (proto === 'chat') return { in: u.prompt_tokens, out: u.completion_tokens };
  if (proto === 'responses') return { in: u.input_tokens, out: u.output_tokens };
  return { in: u.input_tokens, out: u.output_tokens };
}

async function runLlmTest() {
  const proto = document.getElementById('llmProto').value;
  const model = document.getElementById('llmModel').value.trim() || 'GLM-4.5-Flash';
  const maxTokens = Number(document.getElementById('llmMaxTokens').value || 256);
  const stream = document.getElementById('llmStream').checked;
  const prompt = document.getElementById('llmPrompt').value || 'Bonjour';
  const key = document.getElementById('llmKey').value;
  const btn = document.getElementById('llmRunBtn');
  const resultEl = document.getElementById('llmResult');
  const contentEl = document.getElementById('llmContent');
  if (!key) { toast('Clé passerelle manquante, cliquez sur « Actualiser la clé »', 'error'); return; }

  const path = proto === 'messages' ? '/v1/messages' : proto === 'chat' ? '/v1/chat/completions' : '/v1/responses';
  let body;
  if (proto === 'messages') body = { model, max_tokens: maxTokens, stream, messages: [{ role: 'user', content: prompt }] };
  else if (proto === 'chat') body = { model, max_tokens: maxTokens, stream, messages: [{ role: 'user', content: prompt }] };
  else body = { model, max_output_tokens: maxTokens, stream, input: prompt };
  const headers = { 'Content-Type': 'application/json' };
  if (proto === 'messages') headers['x-api-key'] = key; else headers['Authorization'] = 'Bearer ' + key;

  btn.disabled = true;
  resultEl.innerHTML = '<div class="kv-item"><div class="k">Statut</div><div class="v">En cours…</div></div>';
  contentEl.textContent = '';
  const t0 = performance.now();
  let ttft = 0, text = '', think = '', events = 0, usage = null, status = 0;
  try {
    const resp = await fetch(path, { method: 'POST', headers, body: JSON.stringify(body) });
    status = resp.status;
    if (stream && resp.body) {
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!ttft) ttft = Math.round(performance.now() - t0);
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
          const dl = frame.split('\n').find(l => l.startsWith('data:'));
          if (!dl) continue;
          const data = dl.slice(5).trim();
          if (!data || data === '[DONE]') continue;
          events++;
          text += llmDeltaText(proto, data);
          think += llmDeltaThink(proto, data);
          try { const j = JSON.parse(data); const u = llmUsageFrom(j, proto); if (u && (u.in || u.out)) usage = u; } catch (e) { }
        }
      }
    } else {
      const j = await resp.json();
      if (!ttft) ttft = Math.round(performance.now() - t0);
      if (resp.ok) {
        if (proto === 'messages') {
          text = (j.content || []).filter(c => c.type === 'text').map(c => c.text).join('');
          think = (j.content || []).filter(c => c.type === 'thinking').map(c => c.thinking).join('');
        } else if (proto === 'chat') {
          const m = ((j.choices || [])[0] || {}).message || {};
          text = m.content || '';
          think = m.reasoning_content || '';
        } else {
          text = j.output_text || '';
          think = (j.output || []).filter(o => o.type === 'reasoning').map(o => (o.summary || []).map(s => s.text).join('')).join('');
        }
        usage = llmUsageFrom(j, proto);
      } else {
        text = JSON.stringify(j).slice(0, 500);
      }
    }
  } catch (e) {
    status = 0; text = 'Échec de la requête : ' + e.message;
  }
  const latency = Math.round(performance.now() - t0);
  btn.disabled = false;
  const ok = status >= 200 && status < 300;
  resultEl.innerHTML = `
    <div class="kv-item"><div class="k">Statut HTTP</div><div class="v" style="color:${ok ? 'var(--c-success-dark)' : 'var(--c-danger)'}">${status || 'Erreur réseau'}</div></div>
    <div class="kv-item"><div class="k">Latence totale</div><div class="v">${latency}ms</div></div>
    <div class="kv-item"><div class="k">Premier token TTFT</div><div class="v">${stream ? ttft + 'ms' : '-'}</div></div>
    <div class="kv-item"><div class="k">Tokens in/out</div><div class="v">${usage ? usage.in + ' / ' + usage.out : '-'}</div></div>
    <div class="kv-item"><div class="k">Événements SSE</div><div class="v">${stream ? events : '-'}</div></div>
    <div class="kv-item"><div class="k">Protocole</div><div class="v">${proto}${stream ? ' (stream)' : ''}</div></div>`;
  contentEl.textContent = text
    ? text
    : (think ? '[Le modèle a uniquement renvoyé la réflexion]\n' + think : '(Réponse vide)');
  llmHistory.unshift({ t: new Date().toLocaleTimeString(), proto, model, status, latency, ttft, ok });
  document.getElementById('llmHistory').innerHTML = llmHistory.slice(0, 10).map(h =>
    `<div>${esc(h.t)} · ${esc(h.proto)} · ${esc(h.model)} · <span style="color:${h.ok ? 'var(--c-success-dark)' : 'var(--c-danger)'}">${h.status}</span> · ${h.latency}ms${h.ttft ? ' / ttft ' + h.ttft + 'ms' : ''}</div>`).join('');
  if (ok) toast('Test terminé'); else toast('Le test a renvoyé ' + status, 'error');
}

function clearLlmHistory() {
  llmHistory = [];
  document.getElementById('llmHistory').innerHTML = '(Aucun)';
  document.getElementById('llmResult').innerHTML = '';
  document.getElementById('llmContent').textContent = '(Pas encore exécuté)';
}

// setLlmPrompt insertion rapide de prompt
function setLlmPrompt(text) {
  const el = document.getElementById('llmPrompt');
  el.value = text;
  el.focus();
}

// ---- Démarrage ----

function loadAll() {
  loadDashboard();
  loadGroups().then(loadAccounts);
}

setInterval(() => {
  if (document.getElementById('mainApp').style.display !== 'none') {
    if (document.getElementById('section-dashboard').classList.contains('active')) loadDashboard();
    if (document.getElementById('section-activity').classList.contains('active')) { pollRunning(); }
  }
}, 5000);

checkAuth();
