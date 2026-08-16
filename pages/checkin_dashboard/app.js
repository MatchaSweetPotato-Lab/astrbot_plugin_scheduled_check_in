/**
 * AstrBot Scheduled Check-In Plugin - Dashboard Logic (Vanilla JS - 0 External Dependencies)
 */

let sites = [];
let settings = {
  enabled: true,
  random_enabled: true,
  start_time: '08:00',
  end_time: '10:30',
  checkin_time: '08:30'
};
let logs = [];
let isEdit = false;
let editIndex = -1;

// Helper: Toast Notifications
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3000);
}

// Helper: Custom Confirm Dialog (Avoids iframe sandbox confirm() restrictions)
function showConfirm(message, onConfirm) {
  const msgEl = document.getElementById('confirm-message');
  const okBtn = document.getElementById('confirm-ok-btn');
  if (msgEl) msgEl.textContent = message;
  if (okBtn) {
    okBtn.onclick = () => {
      closeModal('confirm-modal');
      onConfirm();
    };
  }
  openModal('confirm-modal');
}

// Helper: Mask credentials
function maskToken(val) {
  if (!val) return '未配置';
  if (val.length <= 10) return '******';
  return val.substring(0, 4) + '***' + val.substring(val.length - 4);
}

// Helper: Open URL
function openUrl(url) {
  if (!url) return;
  let target = url;
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    target = 'https://' + target;
  }
  window.open(target, '_blank');
}

// Helper: Escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// API Bridge Wrappers
async function apiGet(endpoint, params = {}) {
  if (window.AstrBotPluginPage) {
    try {
      return await window.AstrBotPluginPage.apiGet(endpoint, params);
    } catch (e) {
      console.error('AstrBotPluginPage apiGet error:', e);
    }
  }
  const query = new URLSearchParams(params).toString();
  const url = query ? `${endpoint}?${query}` : endpoint;
  const res = await fetch(url);
  return await res.json();
}

async function apiPost(endpoint, body = {}) {
  if (window.AstrBotPluginPage) {
    try {
      return await window.AstrBotPluginPage.apiPost(endpoint, body);
    } catch (e) {
      console.error('AstrBotPluginPage apiPost error:', e);
    }
  }
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return await res.json();
}

// Modal Controls
function openModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
}

function handleOverlayClick(event, id) {
  if (event.target.id === id) {
    closeModal(id);
  }
}

// Data Loaders & Renderers
async function loadSites() {
  const tbody = document.getElementById('sites-tbody');
  try {
    const data = await apiGet('/api/sites');
    sites = Array.isArray(data) ? data : [];
    renderSitesTable();
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-text">读取站点列表失败</td></tr>`;
    showToast('读取站点列表失败', 'error');
  }
}

function getTodayStr() {
  const d = new Date();
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function renderCheckInStatus(site) {
  const todayStr = getTodayStr();
  if (site.last_checkin_date === todayStr && site.last_checkin_success) {
    const timeStr = site.last_checkin_time ? site.last_checkin_time.substring(0, 5) : '';
    return `<span class="badge badge-success">已签到${timeStr ? ' (' + timeStr + ')' : ''}</span>`;
  }
  if (site.last_checkin_date === todayStr && site.last_checkin_success === false) {
    const timeStr = site.last_checkin_time ? site.last_checkin_time.substring(0, 5) : '';
    return `<span class="badge" style="background:#fee2e2;color:#991b1b;">失败${timeStr ? ' (' + timeStr + ')' : ''}</span>`;
  }
  return `<span class="badge badge-warning">未签到</span>`;
}

function renderSitesTable() {
  const tbody = document.getElementById('sites-tbody');
  if (!tbody) return;

  if (sites.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-text">暂无中转站，请点击右上角添加</td></tr>`;
    return;
  }

  tbody.innerHTML = sites.map((site, index) => `
    <tr>
      <td><strong>${escapeHtml(site.name)}</strong></td>
      <td>
        <span class="badge ${site.type === 'new-api' ? 'badge-success' : 'badge-info'}">
          ${escapeHtml(site.type || 'new-api')}
        </span>
      </td>
      <td>
        <a class="link" onclick="openUrl('${escapeHtml(site.base_url)}')">${escapeHtml(site.base_url)}</a>
      </td>
      <td>
        ${renderCheckInStatus(site)}
      </td>
      <td>
        <span class="token-mask">${maskToken(site.auth_value)}</span>
      </td>
      <td>
        <label class="switch">
          <input type="checkbox" ${site.enabled !== false ? 'checked' : ''} onchange="toggleSiteEnabled(${index}, this.checked)" />
          <span class="slider"></span>
        </label>
      </td>
      <td style="text-align: right; padding-right: 24px;">
        <button class="btn btn-sm btn-success-plain" style="margin-right: 6px;" onclick="recheckInSite(${index})">重新签到</button>
        <button class="btn btn-sm btn-primary-plain" style="margin-right: 6px;" onclick="testSingleSite(${index})">测试</button>
        <button class="btn btn-sm" style="margin-right: 6px;" onclick="openEditSiteModal(${index})">编辑</button>
        <button class="btn btn-sm btn-danger-plain" onclick="deleteSite(${index})">删除</button>
      </td>
    </tr>
  `).join('');
}

async function toggleSiteEnabled(index, enabled) {
  if (sites[index]) {
    sites[index].enabled = enabled;
    await saveSites();
  }
}

async function saveSites() {
  try {
    await apiPost('/api/sites', sites);
    showToast('配置更新成功', 'success');
  } catch (e) {
    showToast('保存配置失败', 'error');
  }
}

// Header Dynamic Key-Value Editor Helpers
function addHeaderRow(key = '', value = '') {
  const container = document.getElementById('headers-list-container');
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'kv-row';
  row.innerHTML = `
    <input type="text" class="form-control kv-key" placeholder="" value="${escapeHtml(key)}" />
    <input type="text" class="form-control kv-value" placeholder="" value="${escapeHtml(value)}" />
    <button type="button" class="btn-icon-danger" onclick="this.parentElement.remove()" title="删除此 Header">&times;</button>
  `;
  container.appendChild(row);
}

function clearHeaderRows() {
  const container = document.getElementById('headers-list-container');
  if (container) container.innerHTML = '';
}

function setHeadersFromText(text) {
  clearHeaderRows();
  if (!text) return;
  const lines = String(text).split('\n');
  lines.forEach(line => {
    line = line.trim();
    if (!line) return;
    const idx = line.indexOf(':');
    if (idx > -1) {
      const k = line.substring(0, idx).trim();
      const v = line.substring(idx + 1).trim();
      addHeaderRow(k, v);
    }
  });
}

function getHeaderPairsText() {
  const container = document.getElementById('headers-list-container');
  if (!container) return '';
  const rows = container.querySelectorAll('.kv-row');
  const pairs = [];
  rows.forEach(row => {
    const key = row.querySelector('.kv-key')?.value.trim();
    const val = row.querySelector('.kv-value')?.value.trim();
    if (key) {
      pairs.push(`${key}: ${val}`);
    }
  });
  return pairs.join('\n');
}

// Site Form Actions
function openAddSiteModal() {
  isEdit = false;
  editIndex = -1;
  document.getElementById('site-modal-title').textContent = '新增中转站';
  document.getElementById('site-name').value = '';
  document.getElementById('site-type').value = 'new-api';
  document.getElementById('site-url').value = '';
  document.querySelector('input[name="auth_type"][value="bearer_token"]').checked = true;
  document.getElementById('site-auth-value').value = '';
  document.getElementById('site-endpoint').value = '';
  document.getElementById('site-proxy').value = '';
  clearHeaderRows();
  document.getElementById('site-enabled').checked = true;
  openModal('site-modal');
}

function openEditSiteModal(index) {
  const site = sites[index];
  if (!site) return;
  isEdit = true;
  editIndex = index;
  document.getElementById('site-modal-title').textContent = '编辑中转站';
  document.getElementById('site-name').value = site.name || '';
  document.getElementById('site-type').value = site.type || 'new-api';
  document.getElementById('site-url').value = site.base_url || '';
  const authType = site.auth_type === 'cookie' ? 'cookie' : 'bearer_token';
  document.querySelector(`input[name="auth_type"][value="${authType}"]`).checked = true;
  document.getElementById('site-auth-value').value = site.auth_value || '';
  document.getElementById('site-endpoint').value = site.checkin_endpoint || '';
  document.getElementById('site-proxy').value = site.proxy || '';
  setHeadersFromText(site.custom_headers || '');
  document.getElementById('site-enabled').checked = site.enabled !== false;
  openModal('site-modal');
}

async function submitSiteForm() {
  const name = document.getElementById('site-name').value.trim();
  const type = document.getElementById('site-type').value;
  const base_url = document.getElementById('site-url').value.trim();
  const auth_type = document.querySelector('input[name="auth_type"]:checked').value;
  const auth_value = document.getElementById('site-auth-value').value.trim();
  const checkin_endpoint = document.getElementById('site-endpoint').value.trim();
  const proxy = document.getElementById('site-proxy').value.trim();
  const custom_headers = getHeaderPairsText();
  const enabled = document.getElementById('site-enabled').checked;

  if (!name || !base_url || !auth_value) {
    showToast('请补全必要信息', 'warning');
    return;
  }

  const siteData = {
    id: isEdit ? (sites[editIndex].id || 'site_' + Date.now()) : 'site_' + Date.now(),
    name,
    type,
    base_url,
    auth_type,
    auth_value,
    checkin_endpoint,
    proxy,
    custom_headers,
    enabled
  };

  if (isEdit && editIndex >= 0) {
    sites[editIndex] = siteData;
  } else {
    sites.push(siteData);
  }

  renderSitesTable();
  await saveSites();
  closeModal('site-modal');
}

function deleteSite(index) {
  const site = sites[index];
  const name = site ? site.name : '该中转站';
  showConfirm(`确定要删除“${name}”吗？`, async () => {
    sites.splice(index, 1);
    renderSitesTable();
    await saveSites();
  });
}

function recheckInSite(index) {
  const site = sites[index];
  if (!site) return;

  showConfirm(`确定要重新签到“${site.name}”吗？这会再次请求签到接口。`, async () => {
    try {
      const data = await apiPost('/api/sites/recheckin', { site_id: site.id });
      const result = data?.result;
      if (result?.success) {
        showToast(`${site.name}: ${result.message || '重新签到成功'}`, 'success');
      } else {
        showToast(`${site.name}: ${result?.message || data?.message || '重新签到失败'}`, 'error');
      }
      await loadSites();
      await loadLogs();
    } catch (e) {
      showToast('重新签到请求失败', 'error');
    }
  });
}

async function testSingleSite(index) {
  const site = sites[index];
  if (!site) return;
  try {
    const data = await apiPost('/api/sites/test', site);
    if (data && data.success) {
      showToast(`${site.name}: ${data.message} (余额: $${data.total_quota})`, 'success');
    } else {
      showToast(`${site.name}: ${data.message || '测试失败'}`, 'error');
    }
    loadLogs();
  } catch (e) {
    showToast('测试请求失败', 'error');
  }
}

async function runCheckInAll() {
  const btn = document.getElementById('btn-run-all');
  if (btn) {
    btn.disabled = true;
    btn.textContent = '签到中...';
  }
  try {
    await apiPost('/api/checkin/run', {});
    showToast('一键打卡完成！', 'success');
    loadSites();
    loadLogs();
  } catch (e) {
    showToast('打卡请求异常', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '立即全部签到';
    }
  }
}

// Global Settings Actions
async function loadSettings() {
  try {
    const data = await apiGet('/api/settings');
    if (data && typeof data === 'object') {
      settings = { ...settings, ...data };
      renderSettingsForm();
      const badge = document.getElementById('target-time-badge');
      if (badge && data.today_target_time) {
        badge.textContent = data.today_target_time;
      }
    }
  } catch (e) {
    console.error('loadSettings error:', e);
  }
}

function renderSettingsForm() {
  document.getElementById('setting-enabled').checked = settings.enabled !== false;
  const isRandom = settings.random_enabled !== false;
  document.getElementById('setting-random').checked = isRandom;
  document.getElementById('setting-start-time').value = settings.start_time || '08:00';
  document.getElementById('setting-end-time').value = settings.end_time || '10:30';
  document.getElementById('setting-fixed-time').value = settings.checkin_time || '08:30';
  toggleRandomMode();
}

function toggleRandomMode() {
  const isRandom = document.getElementById('setting-random').checked;
  document.getElementById('random-time-fields').style.display = isRandom ? 'block' : 'none';
  document.getElementById('fixed-time-field').style.display = isRandom ? 'none' : 'block';
}

function openSettingsModal() {
  openModal('settings-modal');
  loadSettings();
}

async function saveSettings() {
  const enabled = document.getElementById('setting-enabled').checked;
  const random_enabled = document.getElementById('setting-random').checked;
  const start_time = document.getElementById('setting-start-time').value;
  const end_time = document.getElementById('setting-end-time').value;
  const checkin_time = document.getElementById('setting-fixed-time').value;

  settings = {
    enabled,
    random_enabled,
    start_time,
    end_time,
    checkin_time
  };

  try {
    await apiPost('/api/settings', settings);
    showToast('定时设置更新成功', 'success');
    closeModal('settings-modal');
    loadSettings();
  } catch (e) {
    showToast('保存设置失败', 'error');
  }
}

// Custom Target Time Modal Actions
function openTargetTimeModal() {
  let initialTime = settings.manual_target_time || '';
  if (!initialTime && settings.target_info && settings.target_info.target_time) {
    initialTime = settings.target_info.target_time;
  }
  const input = document.getElementById('custom-target-time-input');
  if (input) {
    input.value = initialTime !== '--:--' ? initialTime : '';
  }
  openModal('target-time-modal');
}

async function saveCustomTargetTime() {
  const targetTime = document.getElementById('custom-target-time-input').value;
  if (!targetTime) {
    showToast('请选择有效的时刻', 'warning');
    return;
  }
  try {
    await apiPost('/api/settings/target_time', { target_time: targetTime });
    showToast(`下次签到时间已设定为: ${targetTime}`, 'success');
    closeModal('target-time-modal');
    loadSettings();
  } catch (e) {
    showToast('更新签到时间失败', 'error');
  }
}

async function resetCustomTargetTime() {
  try {
    await apiPost('/api/settings/target_time', { target_time: '' });
    showToast('已恢复全局自动计算', 'success');
    closeModal('target-time-modal');
    loadSettings();
  } catch (e) {
    showToast('恢复配置失败', 'error');
  }
}

// History Logs Actions
async function loadLogs() {
  const container = document.getElementById('logs-body');
  try {
    const data = await apiGet('/api/logs');
    logs = Array.isArray(data) ? data : [];
    renderLogs();
  } catch (e) {
    if (container) container.innerHTML = `<div class="empty-text">读取日志失败</div>`;
  }
}

function getLogTitle(log) {
  if (log.type === 'test') return '单站连通性测试';
  if (log.type === 'manual' || (log.manual && log.type !== 'test')) return '手动一键签到';
  return '自动定时签到';
}

function renderLogs() {
  const container = document.getElementById('logs-body');
  if (!container) return;

  if (logs.length === 0) {
    container.innerHTML = `<div class="empty-text">暂无签到历史记录</div>`;
    return;
  }

  container.innerHTML = `
    <div class="timeline">
      ${logs.map(log => `
        <div class="timeline-item">
          <div class="timeline-header">
            <span class="timeline-title">${getLogTitle(log)}</span>
            <span class="timeline-time">${escapeHtml(log.timestamp)}</span>
          </div>
          <div class="timeline-content">${escapeHtml(log.report)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function openLogsDrawer() {
  openModal('logs-drawer');
  loadLogs();
}

function clearLogs() {
  showConfirm('确定要清空所有历史签到日志吗？此操作无法撤销。', async () => {
    try {
      await apiPost('/api/logs/clear', {});
      logs = [];
      renderLogs();
      showToast('历史日志已成功清空', 'success');
    } catch (e) {
      showToast('清空日志失败', 'error');
    }
  });
}

// Initial Loading
document.addEventListener('DOMContentLoaded', () => {
  loadSites();
  loadSettings();
  loadLogs();
});
