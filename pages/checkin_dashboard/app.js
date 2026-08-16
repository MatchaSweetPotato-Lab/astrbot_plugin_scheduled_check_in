/**
 * AstrBot Scheduled Check-In Plugin - Dashboard Logic (Vanilla JS - 0 External Dependencies)
 */

let sites = [];
let settings = {
  enabled: true,
  random_enabled: true,
  start_time: '08:00',
  end_time: '10:30',
  checkin_time: '08:30',
  http_ssl_verify: true,
  http_timeout_seconds: 15,
  http_impersonate: '',
  http_impersonate_options: []
};
let logs = [];
let isEdit = false;
let editIndex = -1;
let activeConfirmResolver = null;

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
  if (activeConfirmResolver) {
    activeConfirmResolver(false);
    activeConfirmResolver = null;
  }
  if (msgEl) msgEl.textContent = message;
  return new Promise(resolve => {
    activeConfirmResolver = resolve;
    if (okBtn) {
      okBtn.onclick = async () => {
        activeConfirmResolver = null;
        closeModal('confirm-modal');
        if (onConfirm) await onConfirm();
        resolve(true);
      };
    }
    openModal('confirm-modal');
  });
}

function cancelConfirm() {
  if (activeConfirmResolver) {
    const resolve = activeConfirmResolver;
    activeConfirmResolver = null;
    closeModal('confirm-modal');
    resolve(false);
    return;
  }
  closeModal('confirm-modal');
}

// Helper: Mask credentials
function maskToken(val) {
  if (!val) return '未配置';
  const token = String(val);
  if (token.length <= 10) return '******';
  return token.substring(0, 4) + '***' + token.substring(token.length - 4);
}

function getSiteId(site) {
  // Site IDs are transported as trimmed strings, matching the scheduler API.
  if (!site || site.id === undefined || site.id === null) return '';
  return String(site.id).trim();
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
    if (id === 'confirm-modal') {
      cancelConfirm();
    } else {
      closeModal(id);
    }
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
    renderTableMessage(tbody, '读取站点列表失败');
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
  const badge = document.createElement('span');
  const timeStr = site.last_checkin_time ? String(site.last_checkin_time).substring(0, 5) : '';

  if (site.last_checkin_date === todayStr && site.last_checkin_success) {
    badge.className = 'badge badge-success';
    badge.textContent = `已签到${timeStr ? ' (' + timeStr + ')' : ''}`;
    return badge;
  }
  if (site.last_checkin_date === todayStr && site.last_checkin_success === false) {
    badge.className = 'badge badge-failure';
    badge.textContent = `失败${timeStr ? ' (' + timeStr + ')' : ''}`;
    return badge;
  }
  badge.className = 'badge badge-warning';
  badge.textContent = '未签到';
  return badge;
}

function renderTableMessage(tbody, message) {
  if (!tbody) return;
  tbody.replaceChildren();
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = 7;
  cell.className = 'empty-text';
  cell.textContent = message;
  row.appendChild(cell);
  tbody.appendChild(row);
}

function createActionButton(label, className, handler, addMargin = true) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `btn btn-sm${className ? ` ${className}` : ''}`;
  button.textContent = label;
  if (addMargin) button.style.marginRight = '6px';
  button.addEventListener('click', handler);
  return button;
}

function renderSitesTable() {
  const tbody = document.getElementById('sites-tbody');
  if (!tbody) return;

  if (sites.length === 0) {
    renderTableMessage(tbody, '暂无中转站，请点击右上角添加');
    return;
  }

  tbody.replaceChildren();
  sites.forEach((site, index) => {
    const row = document.createElement('tr');

    const nameCell = document.createElement('td');
    const name = document.createElement('strong');
    name.textContent = site.name || '';
    nameCell.appendChild(name);
    row.appendChild(nameCell);

    const typeCell = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.className = `badge ${site.type === 'new-api' ? 'badge-success' : 'badge-info'}`;
    typeBadge.textContent = site.type || 'new-api';
    typeCell.appendChild(typeBadge);
    row.appendChild(typeCell);

    const urlCell = document.createElement('td');
    const urlButton = document.createElement('button');
    urlButton.type = 'button';
    urlButton.className = 'link link-button';
    urlButton.textContent = site.base_url || '';
    urlButton.addEventListener('click', () => openUrl(site.base_url));
    urlCell.appendChild(urlButton);
    row.appendChild(urlCell);

    const statusCell = document.createElement('td');
    statusCell.appendChild(renderCheckInStatus(site));
    row.appendChild(statusCell);

    const tokenCell = document.createElement('td');
    const token = document.createElement('span');
    token.className = 'token-mask';
    token.textContent = maskToken(site.auth_value);
    tokenCell.appendChild(token);
    row.appendChild(tokenCell);

    const enabledCell = document.createElement('td');
    const switchLabel = document.createElement('label');
    switchLabel.className = 'switch';
    const enabledInput = document.createElement('input');
    enabledInput.type = 'checkbox';
    enabledInput.checked = site.enabled !== false;
    enabledInput.addEventListener('change', event => {
      toggleSiteEnabled(index, event.currentTarget.checked);
    });
    const slider = document.createElement('span');
    slider.className = 'slider';
    switchLabel.append(enabledInput, slider);
    enabledCell.appendChild(switchLabel);
    row.appendChild(enabledCell);

    const actionsCell = document.createElement('td');
    actionsCell.style.textAlign = 'right';
    actionsCell.style.paddingRight = '24px';
    const actionButtons = [];
    const siteId = getSiteId(site);
    const recheckButton = createActionButton(
      '重新签到',
      'btn-success-plain',
      async () => {
        if (!siteId || recheckButton.dataset.rechecking === 'true') return;
        recheckButton.disabled = true;
        recheckButton.dataset.rechecking = 'true';
        try {
          await recheckInSite(index);
        } finally {
          if (getSiteId(sites[index]) === siteId) {
            recheckButton.disabled = false;
          }
          delete recheckButton.dataset.rechecking;
        }
      }
    );
    if (!siteId) {
      recheckButton.disabled = true;
      recheckButton.title = '站点 ID 不可用，请先保存站点';
    }
    actionButtons.push(
      recheckButton,
      createActionButton('测试', 'btn-primary-plain', () => testSingleSite(index)),
      createActionButton('编辑', '', () => openEditSiteModal(index)),
      createActionButton('删除', 'btn-danger-plain', () => deleteSite(index), false)
    );
    actionsCell.append(...actionButtons);
    row.appendChild(actionsCell);
    tbody.appendChild(row);
  });
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
  const keyInput = document.createElement('input');
  keyInput.type = 'text';
  keyInput.className = 'form-control kv-key';
  keyInput.value = key;
  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.className = 'form-control kv-value';
  valueInput.value = value;
  const removeButton = document.createElement('button');
  removeButton.type = 'button';
  removeButton.className = 'btn-icon-danger';
  removeButton.title = '删除此 Header';
  removeButton.textContent = '×';
  removeButton.addEventListener('click', () => row.remove());
  row.append(keyInput, valueInput, removeButton);
  container.appendChild(row);
}

function clearHeaderRows() {
  const container = document.getElementById('headers-list-container');
  if (container) container.replaceChildren();
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
  document.getElementById('site-solve-acw-sc-v2').checked = false;
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
  document.getElementById('site-solve-acw-sc-v2').checked = site.solve_acw_sc_v2 === true;
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
  const solve_acw_sc_v2 = document.getElementById('site-solve-acw-sc-v2').checked;
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
    solve_acw_sc_v2,
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

async function recheckInSite(index) {
  const site = sites[index];
  if (!site) return false;
  const siteId = getSiteId(site);
  if (!siteId) {
    showToast('站点 ID 不可用，请先保存站点', 'warning');
    return false;
  }

  const confirmed = await showConfirm(`确定要重新签到“${site.name}”吗？这会再次请求签到接口。`);
  if (!confirmed) return false;

  try {
    const data = await apiPost('/api/sites/recheckin', { site_id: siteId });
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
  return true;
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
  document.getElementById('setting-http-ssl-verify').checked = settings.http_ssl_verify === true;
  document.getElementById('setting-http-timeout').value = settings.http_timeout_seconds || 15;
  renderImpersonateOptions();
  toggleRandomMode();
}

function renderImpersonateOptions() {
  const select = document.getElementById('setting-http-impersonate');
  if (!select) return;

  const maxOptions = 128;
  const values = Array.isArray(settings.http_impersonate_options)
    ? settings.http_impersonate_options.filter(value => typeof value === 'string' && value.trim())
    : [];
  const options = [...new Set(values)].slice(0, maxOptions);

  select.replaceChildren();
  if (options.length === 0) {
    const emptyOption = document.createElement('option');
    emptyOption.value = '';
    emptyOption.textContent = '当前版本未提供可用指纹';
    emptyOption.disabled = true;
    emptyOption.selected = true;
    select.appendChild(emptyOption);
    return;
  }

  options.forEach(value => {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
  if (options.includes(settings.http_impersonate)) {
    select.value = settings.http_impersonate;
  } else {
    select.value = options[0];
  }
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
  const http_ssl_verify = document.getElementById('setting-http-ssl-verify').checked;
  const timeoutInputElement = document.getElementById('setting-http-timeout');
  const timeoutInput = Number(timeoutInputElement.value);
  const http_timeout_seconds = Number.isFinite(timeoutInput)
    ? Math.min(300, Math.max(1, Math.round(timeoutInput)))
    : 15;
  timeoutInputElement.value = String(http_timeout_seconds);
  const httpImpersonateSelect = document.getElementById('setting-http-impersonate');
  const http_impersonate = httpImpersonateSelect?.value || settings.http_impersonate || '';

  settings = {
    enabled,
    random_enabled,
    start_time,
    end_time,
    checkin_time,
    http_ssl_verify,
    http_timeout_seconds,
    http_impersonate
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
    renderLogMessage(container, '读取日志失败');
  }
}

function getLogTitle(log) {
  if (log.type === 'test') return '单站连通性测试';
  if (log.type === 'manual' || (log.manual && log.type !== 'test')) return '手动一键签到';
  return '自动定时签到';
}

function renderLogMessage(container, message) {
  if (!container) return;
  container.replaceChildren();
  const empty = document.createElement('div');
  empty.className = 'empty-text';
  empty.textContent = message;
  container.appendChild(empty);
}

function renderLogs() {
  const container = document.getElementById('logs-body');
  if (!container) return;

  if (logs.length === 0) {
    renderLogMessage(container, '暂无签到历史记录');
    return;
  }

  container.replaceChildren();
  const timeline = document.createElement('div');
  timeline.className = 'timeline';

  logs.forEach(log => {
    const item = document.createElement('div');
    item.className = 'timeline-item';

    const header = document.createElement('div');
    header.className = 'timeline-header';
    const title = document.createElement('span');
    title.className = 'timeline-title';
    title.textContent = getLogTitle(log);
    const time = document.createElement('span');
    time.className = 'timeline-time';
    time.textContent = log.timestamp || '';
    header.append(title, time);

    const content = document.createElement('div');
    content.className = 'timeline-content';
    content.textContent = log.report || '';
    item.append(header, content);
    timeline.appendChild(item);
  });

  container.appendChild(timeline);
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
