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
  http_impersonate_options: [],
  max_history_records: 0
};
let logItems = [];
let logsNextBeforeId = null;
let logsHasMore = true;
let logsLoading = false;
let logsTotal = 0;
let logsStartDate = '';
let logsEndDate = '';
let isEdit = false;
let editIndex = -1;
let activeConfirmResolver = null;
let vaultState = { enabled: false, unlocked: false, locked: false };
let keySlots = [];
let activeAnalyticsSite = null;
let analyticsMonth = '';
const PLUGIN_ID = 'astrbot_plugin_scheduled_check_in';

const SLOT_TYPE_LABELS = {
  user_key: '用户密钥',
  webauthn_prf: '通行密钥'
};
// Credentials being edited in the site modal, kept out of `sites` until saved.
let credentialDraft = [];
let credentialSeq = 0;

const CREDENTIAL_LABELS = {
  token: 'Authorization Token',
  cookie: 'Cookie',
  github_oauth: 'Github OAuth',
  linuxdo_oauth: 'LinuxDO OAuth'
};

const OAUTH_TYPES = ['github_oauth', 'linuxdo_oauth'];

const OAUTH_COOKIE_HINTS = {
  github_oauth: '填入 github.com 的 user_session Cookie',
  linuxdo_oauth: '填入 linux.do 的 _t Cookie'
};

// Endpoints each framework already knows, shown as placeholder hints.
const FRAMEWORK_DEFAULTS = {
  'new-api': {
    checkin: '留空自动使用 /api/user/checkin 或 /api/user/pay/checkin',
    balance: '留空自动使用 /api/user/self',
    newApiUser: '跟随框架时会自动探测 new-api-user 并回写到此处'
  },
  generic_rest: {
    checkin: '留空将直接 GET 访问 Base URL（该框架未适配签到接口）',
    balance: '留空则不查询余额（该框架未适配余额接口）',
    newApiUser: ''
  }
};

// Helper: Toast Notifications
function showToast(message, type = 'success', duration = 3500) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const rawText = String(message || '').trim();
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.title = rawText; // Hover to view full text when truncated
  toast.textContent = rawText.length > 500 ? rawText.substring(0, 500) + '...' : rawText;
  toast.addEventListener('click', () => toast.remove());
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, duration);
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

function isVaultLocked() {
  return vaultState.locked === true;
}

function getSiteId(site) {
  // Site IDs are transported as trimmed strings, matching the scheduler API.
  return String(site?.id ?? '').trim();
}

function normalizeImpersonateValue(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
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

function getCurrentMonthStr() {
  return getTodayStr().substring(0, 7);
}

function renderCheckInStatus(site) {
  const todayStr = getTodayStr();
  const statusButton = document.createElement('button');
  statusButton.type = 'button';
  statusButton.className = 'status-chip';
  statusButton.title = '点击查看签到日历和余额变化';
  statusButton.addEventListener('click', () => openSiteAnalytics(site));
  const timeStr = site.last_checkin_time ? String(site.last_checkin_time).substring(0, 5) : '';

  if (site.last_checkin_date === todayStr && site.last_checkin_success) {
    statusButton.classList.add('status-chip-success');
    statusButton.textContent = `已签到${timeStr ? ' (' + timeStr + ')' : ''}`;
    return statusButton;
  }
  if (site.last_checkin_date === todayStr && site.last_checkin_success === false) {
    statusButton.classList.add('status-chip-failure');
    statusButton.textContent = `失败${timeStr ? ' (' + timeStr + ')' : ''}`;
    return statusButton;
  }
  statusButton.classList.add('status-chip-warning');
  statusButton.textContent = '未签到';
  return statusButton;
}

function renderTableMessage(tbody, message) {
  if (!tbody) return;
  tbody.replaceChildren();
  const row = document.createElement('tr');
  const cell = document.createElement('td');
  cell.colSpan = 6;
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
    const locked = site.locked === true;
    if (locked) row.classList.add('row-locked');

    const nameCell = document.createElement('td');
    const name = document.createElement('strong');
    name.textContent = site.name;
    nameCell.appendChild(name);
    if (locked) {
      const lockTag = document.createElement('span');
      lockTag.className = 'badge badge-warning';
      lockTag.style.marginLeft = '8px';
      lockTag.textContent = '锁定';
      lockTag.title = '配置已加密，请先输入密钥解锁';
      nameCell.appendChild(lockTag);
    }
    row.appendChild(nameCell);

    const typeCell = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.className = `badge ${site.type === 'new-api' ? 'badge-success' : 'badge-info'}`;
    typeBadge.textContent = site.type;
    typeCell.appendChild(typeBadge);
    row.appendChild(typeCell);

    const urlCell = document.createElement('td');
    const urlButton = document.createElement('button');
    urlButton.type = 'button';
    urlButton.className = 'link link-button';
    urlButton.textContent = site.base_url;
    urlButton.addEventListener('click', () => openUrl(site.base_url));
    urlCell.appendChild(urlButton);
    row.appendChild(urlCell);

    const statusCell = document.createElement('td');
    statusCell.appendChild(renderCheckInStatus(site));
    row.appendChild(statusCell);

    const enabledCell = document.createElement('td');
    const switchLabel = document.createElement('label');
    switchLabel.className = 'switch';
    const enabledInput = document.createElement('input');
    enabledInput.type = 'checkbox';
    enabledInput.checked = site.enabled === true;
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
        if (recheckButton.dataset.rechecking === 'true') return;
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
    const testButton = createActionButton('测试', 'btn-primary-plain', () => testSingleSite(index));
    const editButton = createActionButton('编辑', '', () => openEditSiteModal(index));
    if (locked) {
      // Editing or running a locked site would overwrite unreadable secrets.
      [recheckButton, testButton, editButton].forEach(button => {
        button.disabled = true;
        button.title = '配置已加密，请先输入密钥解锁';
      });
    }
    actionButtons.push(
      recheckButton,
      testButton,
      editButton,
      createActionButton('删除', 'btn-danger-plain', () => deleteSite(index), false)
    );
    actionsCell.append(...actionButtons);
    row.appendChild(actionsCell);
    tbody.appendChild(row);
  });
}

function formatBalanceNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  return Number(number.toFixed(3)).toString();
}

function formatBalance(value) {
  if (value === null || value === undefined || value === '') return '暂无数据';
  const formatted = formatBalanceNumber(value);
  return formatted === null ? '暂无数据' : `$${formatted}`;
}

function formatBalanceChange(value) {
  if (value === null || value === undefined || value === '') return '首次记录';
  const number = Number(value);
  if (!Number.isFinite(number)) return '首次记录';
  return `${number > 0 ? '+' : ''}$${formatBalanceNumber(number)}`;
}

function formatSignedBalance(value) {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `${number >= 0 ? '+' : '-'}$${formatBalanceNumber(Math.abs(number))}`;
}

function getAnalyticsTypeLabel(type) {
  if (type === 'test') return '测试连接';
  if (type === 'manual') return '手动签到';
  return '自动签到';
}

function formatAnalyticsMonth(month) {
  const match = /^(\d{4})-(\d{2})$/.exec(month || '');
  return match ? `${match[1]} 年 ${Number(match[2])} 月` : month || '签到日历';
}

function changeAnalyticsMonth(delta) {
  if (!analyticsMonth) analyticsMonth = getCurrentMonthStr();
  const [year, month] = analyticsMonth.split('-').map(Number);
  const next = new Date(year, month - 1 + delta, 1);
  analyticsMonth = `${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}`;
  loadSiteAnalytics();
}

function openSiteAnalytics(site) {
  if (!site) return;
  activeAnalyticsSite = site;
  analyticsMonth = getCurrentMonthStr();
  const title = document.getElementById('site-analytics-title');
  if (title) title.textContent = `${site.name || '站点'} · 签到日历`;
  openModal('site-analytics-modal');
  loadSiteAnalytics();
}

async function loadSiteAnalytics() {
  if (!activeAnalyticsSite) return;
  const siteId = getSiteId(activeAnalyticsSite);
  const requestedMonth = analyticsMonth || getCurrentMonthStr();
  analyticsMonth = requestedMonth;
  const calendar = document.getElementById('site-checkin-calendar');
  const chart = document.getElementById('site-balance-chart');
  const notice = document.getElementById('site-analytics-notice');
  if (calendar) calendar.innerHTML = '<div class="analytics-loading">正在读取签到记录...</div>';
  if (chart) chart.innerHTML = '<div class="analytics-loading">正在读取余额变化...</div>';
  if (notice) {
    notice.hidden = true;
    notice.textContent = '';
  }

  try {
    const data = await apiGet('/api/sites/activity', {
      site_id: siteId,
      month: requestedMonth
    });
    if (!data || data.error || data.status === 'error') {
      throw new Error(data?.message || data?.error || '读取站点活动记录失败');
    }
    if (
      !activeAnalyticsSite
      || getSiteId(activeAnalyticsSite) !== siteId
      || analyticsMonth !== requestedMonth
    ) {
      return;
    }
    renderSiteAnalytics(data);
  } catch (e) {
    console.error('loadSiteAnalytics error:', e);
    if (calendar) calendar.innerHTML = '<div class="analytics-empty">暂时无法读取签到记录</div>';
    if (chart) chart.innerHTML = '<div class="analytics-empty">暂时无法读取余额变化</div>';
    showToast(e.message || '读取站点活动记录失败', 'error');
  }
}

function renderSiteAnalytics(data) {
  const monthLabel = document.getElementById('site-analytics-month');
  if (monthLabel) monthLabel.textContent = formatAnalyticsMonth(data.month || analyticsMonth);

  const supportsBalance = data.supports_balance === true
    || ['new-api', 'one-api'].includes(String(data.site?.type || '').trim().toLowerCase());
  const balanceSection = document.getElementById('site-balance-section');
  if (balanceSection) balanceSection.hidden = !supportsBalance;

  const notice = document.getElementById('site-analytics-notice');
  if (notice) {
    const truncated = data.history_truncated === true;
    const limit = Number(data.history_record_limit || 0);
    notice.hidden = !truncated;
    notice.textContent = truncated
      ? `本月日志超过 ${limit.toLocaleString()} 条，仅展示最近记录，统计可能不完整`
      : '';
  }

  const summary = document.getElementById('site-analytics-summary');
  if (summary) {
    summary.replaceChildren();
    const summaryItems = [
      ['本月签到', `${Number(data.success_days || 0)} 天`, 'success'],
      ['失败记录', `${Number(data.failure_days || 0)} 天`, 'failure'],
    ];
    if (supportsBalance) {
      summaryItems.push([
        '签到余额(总余额)',
        formatBalance(data.current_balance !== undefined ? data.current_balance : data.latest_balance),
        'balance'
      ]);
    }
    summaryItems.forEach(([label, value, className]) => {
      const item = document.createElement('div');
      item.className = `analytics-stat ${className}`;
      const labelElement = document.createElement('span');
      labelElement.textContent = label;
      const valueElement = document.createElement('strong');
      valueElement.textContent = value;
      item.append(labelElement, valueElement);
      summary.appendChild(item);
    });
  }

  renderSiteCalendar(
    Array.isArray(data.days) ? data.days : [],
    data.month || analyticsMonth,
    supportsBalance ? data.current_balance : null,
    supportsBalance
  );
  renderBalanceHistory(supportsBalance && Array.isArray(data.balance_history) ? data.balance_history : []);
}

function renderSiteCalendar(days, month, currentBalance = null, showBalance = true) {
  const container = document.getElementById('site-checkin-calendar');
  if (!container) return;
  container.replaceChildren();

  const match = /^(\d{4})-(\d{2})$/.exec(month || '');
  if (!match) {
    container.textContent = '月份格式无效';
    return;
  }
  const year = Number(match[1]);
  const monthNumber = Number(match[2]);
  const firstDay = (new Date(year, monthNumber - 1, 1).getDay() + 6) % 7;
  const daysInMonth = new Date(year, monthNumber, 0).getDate();
  const dayMap = new Map(days.map(day => [day.date, day]));

  const grid = document.createElement('div');
  grid.className = 'analytics-calendar-grid';
  ['一', '二', '三', '四', '五', '六', '日'].forEach(label => {
    const weekday = document.createElement('div');
    weekday.className = 'analytics-calendar-weekday';
    weekday.textContent = label;
    grid.appendChild(weekday);
  });

  for (let index = 0; index < firstDay; index += 1) {
    const emptyCell = document.createElement('div');
    emptyCell.className = 'analytics-calendar-cell is-empty';
    grid.appendChild(emptyCell);
  }

  for (let dayNumber = 1; dayNumber <= daysInMonth; dayNumber += 1) {
    const date = `${year}-${String(monthNumber).padStart(2, '0')}-${String(dayNumber).padStart(2, '0')}`;
    const record = dayMap.get(date);
    const cell = document.createElement('div');
    cell.className = 'analytics-calendar-cell';
    if (date === getTodayStr()) cell.classList.add('is-today');
    if (record) cell.classList.add(record.status === 'success' ? 'is-success' : 'is-failure');
    cell.title = record?.message || (
      record ? (record.status === 'success' ? '签到成功' : '签到失败') : '当天没有签到记录'
    );

    const number = document.createElement('span');
    number.className = 'analytics-calendar-date';
    number.textContent = String(dayNumber);
    const marker = document.createElement('span');
    marker.className = 'analytics-calendar-marker';
    marker.textContent = record ? (record.status === 'success' ? '✓' : '×') : '·';
    cell.append(number, marker);

    if (showBalance && record?.balance !== null && record?.balance !== undefined) {
      const balanceRow = document.createElement('div');
      balanceRow.className = 'analytics-calendar-balance-row';
      balanceRow.title = '左侧为本次签到增量，括号内为记录总余额';
      const gained = document.createElement('small');
      gained.className = 'analytics-calendar-gain';
      gained.textContent = formatSignedBalance(record.gained_quota);
      const displayBalance = date === getTodayStr() && currentBalance !== null && currentBalance !== undefined
        ? currentBalance
        : record.balance;
      const total = document.createElement('small');
      total.className = 'analytics-calendar-total';
      total.textContent = `(${formatBalance(displayBalance)})`;
      balanceRow.append(gained, total);
      cell.appendChild(balanceRow);
    }
    grid.appendChild(cell);
  }
  container.appendChild(grid);
}

function renderBalanceHistory(history) {
  const chartContainer = document.getElementById('site-balance-chart');
  const listContainer = document.getElementById('site-balance-list');
  if (!chartContainer || !listContainer) return;
  chartContainer.replaceChildren();
  listContainer.replaceChildren();

  if (history.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'analytics-empty';
    empty.textContent = '本月没有可用的余额记录';
    chartContainer.appendChild(empty);
    return;
  }

  const chartPoints = history
    .slice(-60)
    .filter(item => Number.isFinite(Number(item.balance)));
  if (chartPoints.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'analytics-empty';
    empty.textContent = '本月没有可用的数值余额记录';
    chartContainer.appendChild(empty);
  } else {
    const values = chartPoints.map(item => Number(item.balance));
    const min = Math.min(...values);
    const max = Math.max(...values);
    const span = max - min;
    const chart = document.createElement('div');
    chart.className = 'analytics-balance-chart';
    chartPoints.forEach(item => {
      const value = Number(item.balance);
      const column = document.createElement('div');
      column.className = 'analytics-balance-column';
      column.title = `${item.timestamp || ''} · ${formatBalance(value)}`;
      const barTrack = document.createElement('div');
      barTrack.className = 'analytics-balance-bar-track';
      const bar = document.createElement('div');
      bar.className = 'analytics-balance-bar';
      bar.style.height = `${span === 0 ? 52 : 18 + ((value - min) / span) * 82}%`;
      barTrack.appendChild(bar);
      const date = document.createElement('small');
      date.textContent = String(item.date || '').substring(5);
      const valueLabel = document.createElement('span');
      valueLabel.textContent = formatBalance(value);
      column.append(barTrack, valueLabel, date);
      chart.appendChild(column);
    });
    chartContainer.appendChild(chart);
  }

  const list = document.createElement('div');
  list.className = 'analytics-balance-list';
  history.slice().reverse().forEach(item => {
    const row = document.createElement('div');
    row.className = 'analytics-balance-row';
    const info = document.createElement('div');
    info.className = 'analytics-balance-info';
    const timestamp = document.createElement('strong');
    timestamp.textContent = item.timestamp || '未记录时间';
    const type = document.createElement('span');
    type.textContent = getAnalyticsTypeLabel(item.type);
    info.append(timestamp, type);
    const value = document.createElement('div');
    value.className = 'analytics-balance-value';
    const balance = document.createElement('strong');
    balance.textContent = formatBalance(item.balance);
    const change = document.createElement('span');
    const changeNumber = Number(item.change);
    change.className = Number.isFinite(changeNumber)
      ? (changeNumber > 0 ? 'is-increase' : changeNumber < 0 ? 'is-decrease' : 'is-flat')
      : 'is-first';
    change.textContent = formatBalanceChange(item.change);
    value.append(balance, change);
    row.append(info, value);
    list.appendChild(row);
  });
  listContainer.appendChild(list);
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

// Header Dynamic Key-Value Editor Helpers (one editor per action)
function getHeadersContainer(action) {
  return document.getElementById(`${action}-headers-container`);
}

function addHeaderRow(action, key = '', value = '') {
  const container = getHeadersContainer(action);
  if (!container) return;

  const row = document.createElement('div');
  row.className = 'kv-row';
  const keyInput = document.createElement('input');
  keyInput.type = 'text';
  keyInput.className = 'form-control kv-key';
  keyInput.placeholder = 'Header 名称';
  keyInput.value = key;
  const valueInput = document.createElement('input');
  valueInput.type = 'text';
  valueInput.className = 'form-control kv-value';
  valueInput.placeholder = 'Header 值';
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

function setHeaderRows(action, pairs) {
  const container = getHeadersContainer(action);
  if (!container) return;
  container.replaceChildren();
  (Array.isArray(pairs) ? pairs : []).forEach(pair => {
    if (pair && pair.key) addHeaderRow(action, pair.key, pair.value ?? '');
  });
}

function getHeaderPairs(action) {
  const container = getHeadersContainer(action);
  if (!container) return [];
  const pairs = [];
  container.querySelectorAll('.kv-row').forEach(row => {
    const key = row.querySelector('.kv-key')?.value.trim();
    const value = row.querySelector('.kv-value')?.value.trim();
    if (key) pairs.push({ key, value: value || '' });
  });
  return pairs;
}

// Site Modal Tabs
function switchSiteTab(tab) {
  document.querySelectorAll('#site-tab-bar .tab-btn').forEach(button => {
    button.classList.toggle('active', button.dataset.tab === tab);
  });
  document.querySelectorAll('#site-modal .tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.dataset.panel === tab);
  });
}

// Credential Editor
function nextCredentialId() {
  credentialSeq += 1;
  return `cred_${Date.now()}_${credentialSeq}`;
}

function addCredential(type) {
  credentialDraft.push({
    id: nextCredentialId(),
    type,
    label: '',
    value: '',
    auto_bearer: type === 'token' ? true : undefined,
    has_session: false
  });
  renderCredentials();
  renderActionCredentialOptions('checkin');
  renderActionCredentialOptions('balance');
}

function removeCredential(credentialId) {
  credentialDraft = credentialDraft.filter(item => item.id !== credentialId);
  renderCredentials();
  renderActionCredentialOptions('checkin');
  renderActionCredentialOptions('balance');
}

function readCredentialDraftFromDom() {
  const list = document.getElementById('credentials-list');
  if (!list) return;
  list.querySelectorAll('.cred-card').forEach(card => {
    const credential = credentialDraft.find(item => item.id === card.dataset.credId);
    if (!credential) return;
    credential.label = card.querySelector('.cred-label')?.value.trim() || '';
    credential.value = card.querySelector('.cred-value')?.value.trim() || '';
    const autoBearer = card.querySelector('.cred-auto-bearer');
    if (autoBearer) credential.auto_bearer = autoBearer.checked;
  });
}

function buildCredentialCard(credential) {
  const isOauth = OAUTH_TYPES.includes(credential.type);
  const card = document.createElement('div');
  card.className = 'cred-card';
  card.dataset.credId = credential.id;

  const header = document.createElement('div');
  header.className = 'cred-card-header';
  const title = document.createElement('div');
  title.className = 'cred-title';
  const tag = document.createElement('span');
  tag.className = `cred-type-tag${isOauth ? ' oauth' : ''}`;
  tag.textContent = CREDENTIAL_LABELS[credential.type] || credential.type;
  title.appendChild(tag);
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn-icon-danger';
  remove.title = '删除此凭据';
  remove.textContent = '×';
  remove.addEventListener('click', () => {
    readCredentialDraftFromDom();
    removeCredential(credential.id);
  });
  header.append(title, remove);
  card.appendChild(header);

  const labelGroup = document.createElement('div');
  labelGroup.className = 'form-group';
  const labelText = document.createElement('label');
  labelText.textContent = '备注名称 (可选)';
  const labelInput = document.createElement('input');
  labelInput.type = 'text';
  labelInput.className = 'form-control cred-label';
  labelInput.placeholder = '用于在签到/余额页中区分同类凭据';
  labelInput.value = credential.label || '';
  labelInput.addEventListener('input', () => {
    credential.label = labelInput.value.trim();
    renderActionCredentialOptions('checkin');
    renderActionCredentialOptions('balance');
  });
  labelGroup.append(labelText, labelInput);
  card.appendChild(labelGroup);

  const valueGroup = document.createElement('div');
  valueGroup.className = 'form-group';
  const valueLabel = document.createElement('label');
  valueLabel.textContent = isOauth ? '第三方会话 Cookie *' : `${CREDENTIAL_LABELS[credential.type]} *`;
  const valueInput = document.createElement('textarea');
  valueInput.className = 'form-control cred-value';
  valueInput.rows = isOauth ? 2 : 3;
  valueInput.placeholder = isOauth
    ? OAUTH_COOKIE_HINTS[credential.type] || ''
    : (credential.type === 'token' ? '粘贴 Access Token' : '例如 session=xxxx; other=yyyy');
  valueInput.value = credential.value || '';
  valueGroup.append(valueLabel, valueInput);
  if (isOauth) {
    const hint = document.createElement('div');
    hint.className = 'form-hint';
    hint.textContent = '插件会用它自动登录，并把站点会话 Cookie 存在此凭据内。';
    valueGroup.appendChild(hint);
  }
  card.appendChild(valueGroup);

  if (credential.type === 'token') {
    const inlineGroup = document.createElement('div');
    inlineGroup.className = 'form-group cred-inline-row';
    const autoLabel = document.createElement('label');
    autoLabel.className = 'checkbox-label';
    autoLabel.title = '发送请求时自动加上 Bearer 前缀';
    const autoInput = document.createElement('input');
    autoInput.type = 'checkbox';
    autoInput.className = 'cred-auto-bearer';
    autoInput.checked = credential.auto_bearer !== false;
    const autoText = document.createElement('span');
    autoText.textContent = '自动补全 Bearer';
    autoLabel.append(autoInput, autoText);
    inlineGroup.appendChild(autoLabel);
    card.appendChild(inlineGroup);
  }

  if (isOauth) {
    const state = document.createElement('div');
    const hasSession = credential.has_session === true || Boolean(credential.session_cookie);
    state.className = `cred-session-state${hasSession ? ' has-session' : ''}`;
    state.textContent = hasSession
      ? `站点会话已保存${credential.session_updated_at ? ` (${credential.session_updated_at})` : ''}`
      : '尚未登录，首次签到时会自动完成 OAuth';
    card.appendChild(state);
  }

  return card;
}

function renderCredentials() {
  const list = document.getElementById('credentials-list');
  const count = document.getElementById('credentials-count');
  if (count) count.textContent = String(credentialDraft.length);
  if (!list) return;
  list.replaceChildren();
  if (credentialDraft.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-text';
    empty.textContent = '暂无凭据，请从上方按钮添加';
    list.appendChild(empty);
    return;
  }
  credentialDraft.forEach(credential => list.appendChild(buildCredentialCard(credential)));
}

// Action credential pickers reflect the credentials currently drafted.
function renderActionCredentialOptions(action) {
  const select = document.getElementById(`${action}-credential`);
  const hint = document.getElementById(`${action}-credential-hint`);
  if (!select) return;

  const protocol = document.getElementById(`${action}-protocol`)?.value || 'auto';
  const wantsOauth = action === 'checkin' && protocol === 'oauth';
  const previous = select.value;

  select.replaceChildren();
  const auto = document.createElement('option');
  auto.value = '';
  auto.textContent = wantsOauth ? '自动（优先 Github，其次 LinuxDO）' : '自动（优先 Token，其次 Cookie）';
  select.appendChild(auto);

  const usable = credentialDraft.filter(credential =>
    wantsOauth ? OAUTH_TYPES.includes(credential.type) : true
  );
  usable.forEach(credential => {
    const option = document.createElement('option');
    option.value = credential.id;
    const name = CREDENTIAL_LABELS[credential.type] || credential.type;
    option.textContent = credential.label ? `${name} — ${credential.label}` : name;
    select.appendChild(option);
  });
  select.value = usable.some(item => item.id === previous) ? previous : '';

  if (hint) {
    if (credentialDraft.length === 0) {
      hint.textContent = '请先在「凭据」页添加至少一个凭据。';
    } else if (wantsOauth && usable.length === 0) {
      hint.textContent = 'OAuth 协议需要一个 Github 或 LinuxDO OAuth 凭据。';
    } else {
      hint.textContent = '';
    }
  }

  const protocolHint = document.getElementById(`${action}-protocol-hint`);
  if (protocolHint) {
    protocolHint.textContent = wantsOauth
      ? '适用于二次开发后关闭了通用签到端点、只能靠重新登录自动签到的站点：每次签到都会重新走一次 OAuth 登录，而不是复用已保存的会话。'
      : '';
  }
  if (action === 'checkin') renderFrameworkHints();
}

function renderFrameworkHints() {
  const type = document.getElementById('site-type')?.value || 'new-api';
  const defaults = FRAMEWORK_DEFAULTS[type] || FRAMEWORK_DEFAULTS['new-api'];
  const checkinHint = document.getElementById('checkin-path-hint');
  const balanceHint = document.getElementById('balance-path-hint');
  const isOauth = document.getElementById('checkin-protocol')?.value === 'oauth';
  if (checkinHint) {
    checkinHint.textContent = isOauth
      ? '通常留空。若站点仍保留签到端点，登录成功后会继续请求它。'
      : defaults.checkin;
  }
  if (balanceHint) balanceHint.textContent = defaults.balance;
  ['checkin', 'balance'].forEach(name => {
    const headerHint = document.getElementById(`${name}-headers-hint`);
    if (headerHint) headerHint.textContent = defaults.newApiUser;
  });
}

function fillActionForm(action, config) {
  const source = config && typeof config === 'object' ? config : {};
  const path = document.getElementById(`${action}-path`);
  const protocol = document.getElementById(`${action}-protocol`);
  const solve = document.getElementById(`${action}-solve-acw`);
  if (path) path.value = source.path || '';
  if (protocol) protocol.value = source.protocol || 'auto';
  if (solve) solve.checked = source.solve_acw_sc_v2 === true;
  setHeaderRows(action, source.headers);
  renderActionCredentialOptions(action);
  const credential = document.getElementById(`${action}-credential`);
  if (credential) {
    const wanted = source.credential_id || '';
    credential.value = credentialDraft.some(item => item.id === wanted) ? wanted : '';
  }
}

function readActionForm(action) {
  return {
    path: document.getElementById(`${action}-path`)?.value.trim() || '',
    protocol: document.getElementById(`${action}-protocol`)?.value || 'auto',
    credential_id: document.getElementById(`${action}-credential`)?.value || '',
    headers: getHeaderPairs(action),
    solve_acw_sc_v2: document.getElementById(`${action}-solve-acw`)?.checked === true
  };
}

// Site Form Actions
function openAddSiteModal() {
  isEdit = false;
  editIndex = -1;
  document.getElementById('site-modal-title').textContent = '新增中转站';
  document.getElementById('site-name').value = '';
  document.getElementById('site-type').value = 'new-api';
  document.getElementById('site-url').value = '';
  document.getElementById('site-proxy').value = '';
  document.getElementById('site-enabled').checked = true;
  credentialDraft = [];
  renderCredentials();
  fillActionForm('checkin', {});
  fillActionForm('balance', {});
  renderFrameworkHints();
  switchSiteTab('basic');
  openModal('site-modal');
}

function openEditSiteModal(index) {
  const site = sites[index];
  if (!site) return;
  if (site.locked) {
    showToast('该站点配置已加密，请先输入密钥解锁', 'warning');
    return;
  }
  isEdit = true;
  editIndex = index;
  document.getElementById('site-modal-title').textContent = '编辑中转站';
  document.getElementById('site-name').value = site.name || '';
  document.getElementById('site-type').value = site.type || 'new-api';
  document.getElementById('site-url').value = site.base_url || '';
  document.getElementById('site-proxy').value = site.proxy || '';
  document.getElementById('site-enabled').checked = site.enabled === true;

  credentialDraft = (Array.isArray(site.credentials) ? site.credentials : []).map(credential => ({
    ...credential,
    id: credential.id || nextCredentialId()
  }));
  renderCredentials();
  fillActionForm('checkin', site.checkin);
  fillActionForm('balance', site.balance);
  renderFrameworkHints();
  switchSiteTab('basic');
  openModal('site-modal');
}

async function submitSiteForm() {
  const name = document.getElementById('site-name').value.trim();
  const type = document.getElementById('site-type').value;
  const base_url = document.getElementById('site-url').value.trim();
  const proxy = document.getElementById('site-proxy').value.trim();
  const enabled = document.getElementById('site-enabled').checked;

  if (!name || !base_url) {
    showToast('请填写站点名称与 Base URL', 'warning');
    switchSiteTab('basic');
    return;
  }

  readCredentialDraftFromDom();
  if (credentialDraft.length === 0) {
    showToast('请至少添加一个凭据', 'warning');
    switchSiteTab('credentials');
    return;
  }
  const blank = credentialDraft.find(credential => !credential.value);
  if (blank) {
    const label = CREDENTIAL_LABELS[blank.type] || '凭据';
    showToast(`凭据「${blank.label || label}」尚未填写内容`, 'warning');
    switchSiteTab('credentials');
    return;
  }

  const checkin = readActionForm('checkin');
  if (checkin.protocol === 'oauth' && !credentialDraft.some(c => OAUTH_TYPES.includes(c.type))) {
    showToast('签到协议为 OAuth，请先添加一个 OAuth 凭据', 'warning');
    switchSiteTab('checkin');
    return;
  }

  const previous = isEdit && editIndex >= 0 ? sites[editIndex] : null;
  const siteData = {
    id: previous ? previous.id : 'site_' + Date.now(),
    name,
    type,
    base_url,
    proxy,
    credentials: credentialDraft.map(credential => {
      const entry = {
        id: credential.id,
        type: credential.type,
        label: credential.label || '',
        value: credential.value || ''
      };
      if (credential.type === 'token') entry.auto_bearer = credential.auto_bearer !== false;
      return entry;
    }),
    checkin,
    balance: readActionForm('balance'),
    enabled
  };
  if (previous) {
    // Preserve state the dashboard never edits.
    ['last_checkin_date', 'last_checkin_time', 'last_checkin_success', 'last_quota'].forEach(key => {
      if (previous[key] !== undefined) siteData[key] = previous[key];
    });
  }

  if (isEdit && editIndex >= 0) {
    sites[editIndex] = siteData;
  } else {
    sites.push(siteData);
  }

  renderSitesTable();
  await saveSites();
  closeModal('site-modal');
  await loadSites();
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
  if (site.locked || isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return false;
  }
  const siteId = getSiteId(site);

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
  if (site.locked || isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return;
  }
  try {
    const data = await apiPost('/api/sites/test', site);
    if (data && data.success) {
      showToast(`${site.name}: ${data.message} (余额: $${data.total_quota})`, 'success');
    } else {
      showToast(`${site.name}: ${data.message || '测试失败'}`, 'error');
    }
    await loadSites();
    loadLogs();
  } catch (e) {
    showToast('测试请求失败', 'error');
  }
}

async function runCheckInAll() {
  if (isVaultLocked()) {
    showToast('配置已加密未解锁，请先输入密钥', 'warning');
    return;
  }
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

// Vault (AES-256-GCM Encryption) Actions
function applyVaultState(state) {
  if (state && typeof state === 'object') {
    vaultState = {
      enabled: state.enabled === true,
      unlocked: state.unlocked === true,
      locked: state.locked === true
    };
  }
  renderVaultUi();
}

function renderVaultUi() {
  const banner = document.getElementById('lock-banner');
  if (banner) banner.style.display = vaultState.locked ? 'flex' : 'none';

  const badge = document.getElementById('vault-badge');
  if (badge) {
    badge.style.display = vaultState.enabled ? 'inline-block' : 'none';
    badge.className = `badge ${vaultState.locked ? 'badge-warning' : 'badge-success'}`;
    badge.textContent = vaultState.locked ? '已加密 · 锁定' : '已加密 · 已解锁';
  }

  const toggle = document.getElementById('setting-vault-enabled');
  if (toggle) toggle.checked = vaultState.enabled;

  const controls = document.getElementById('vault-controls');
  if (controls) controls.style.display = vaultState.enabled ? 'flex' : 'none';

  const hint = document.getElementById('vault-state-hint');
  if (hint) {
    if (!vaultState.enabled) {
      hint.textContent = '加密凭据、请求头与代理。启用后生成一个仅显示一次的密钥。';
    } else if (vaultState.locked) {
      hint.textContent = '已锁定：敏感字段不可读，定时签到会跳过所有站点。';
    } else {
      hint.textContent = '已解锁：插件重载后需重新解锁。';
    }
  }

  renderKeySlots();
}

async function loadVaultState() {
  try {
    const data = await apiGet('/api/vault');
    applyVaultState(data);
  } catch (e) {
    console.error('loadVaultState error:', e);
  }
  await loadKeySlots();
}

// Key Slot Actions
async function loadKeySlots() {
  try {
    const data = await apiGet('/api/vault/slots');
    keySlots = Array.isArray(data?.slots) ? data.slots : [];
  } catch (e) {
    console.error('loadKeySlots error:', e);
    keySlots = [];
  }
  renderKeySlots();
}

function renderKeySlots() {
  const block = document.getElementById('slots-block');
  if (block) block.style.display = vaultState.enabled ? 'block' : 'none';

  const list = document.getElementById('slots-list');
  if (!list) return;
  list.replaceChildren();
  if (keySlots.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-text';
    empty.textContent = '暂无槽位';
    list.appendChild(empty);
    return;
  }

  keySlots.forEach(slot => {
    const card = document.createElement('div');
    card.className = 'cred-card';

    const header = document.createElement('div');
    header.className = 'cred-card-header';
    const title = document.createElement('div');
    title.className = 'cred-title';
    const tag = document.createElement('span');
    tag.className = `cred-type-tag${slot.type === 'webauthn_prf' ? ' oauth' : ''}`;
    tag.textContent = SLOT_TYPE_LABELS[slot.type] || slot.type;
    const name = document.createElement('span');
    name.textContent = slot.label || '未命名';
    title.append(tag, name);
    header.appendChild(title);

    if (slot.removable) {
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'btn-icon-danger';
      remove.title = '删除此槽位';
      remove.textContent = '×';
      remove.addEventListener('click', () => removeKeySlot(slot));
      header.appendChild(remove);
    } else {
      const badge = document.createElement('span');
      badge.className = 'badge badge-info';
      badge.textContent = '恢复槽位';
      badge.title = '不可删除，确保丢失通行密钥后仍能解锁';
      header.appendChild(badge);
    }
    card.appendChild(header);

    const meta = document.createElement('div');
    meta.className = 'cred-session-state';
    const bits = [];
    if (slot.rp_id) bits.push(`域名 ${slot.rp_id}`);
    if (slot.created_at) bits.push(`创建于 ${slot.created_at}`);
    bits.push(slot.last_used_at ? `最近使用 ${slot.last_used_at}` : '尚未使用');
    meta.textContent = bits.join(' · ');
    card.appendChild(meta);

    list.appendChild(card);
  });
}

function removeKeySlot(slot) {
  const name = slot.label || '该槽位';
  showConfirm(`确定要删除「${name}」吗？该设备将无法再解锁配置。`, async () => {
    try {
      const data = await apiPost('/api/vault/slots/remove', { slot_id: slot.id });
      if (!data || data.status !== 'ok') {
        showToast(data?.message || '删除槽位失败', 'error');
        return;
      }
      applyVaultState(data.vault);
      showToast(data.message || '槽位已删除', 'success');
      await loadKeySlots();
    } catch (e) {
      showToast('删除槽位请求失败', 'error');
    }
  });
}

function getPasskeyPageUrl() {
  // This iframe has an opaque origin, so location.origin reads "null" and
  // parent.location is unreachable. The document can still read its own
  // protocol and host, which are the dashboard's — that is enough to build an
  // absolute URL the user can paste into a new tab.
  const path = `/api/v1/plugins/extensions/${PLUGIN_ID}/passkey`;
  const { protocol, host } = window.location;
  if (host && protocol && protocol !== 'null:') {
    return `${protocol}//${host}${path}`;
  }
  return path;
}

function openPasskeyModal() {
  const box = document.getElementById('passkey-url');
  if (box) box.textContent = getPasskeyPageUrl();
  clearCopyStatus('passkey-url', 'passkey-url-status');
  openModal('passkey-modal');
}

async function copyPasskeyUrl() {
  await runCopy({
    boxId: 'passkey-url',
    statusId: 'passkey-url-status',
    successText: '地址已复制，请在新标签页中打开',
    failureTitle: '复制失败，请手动复制下面的地址',
    noun: '地址'
  });
}

/**
 * Copy a one-shot value and report the outcome inline, next to the value.
 *
 * A corner toast is the wrong place for either outcome here: the vault key is
 * shown exactly once, so a user who misses a failed copy — or who treats a
 * successful copy as "saved" and closes the dialog before pasting anywhere —
 * has to reset the vault. Both messages therefore land directly above the
 * value and stay there until the dialog is reopened.
 */
async function runCopy({ boxId, statusId, successText, successNotice, failureTitle, noun }) {
  const box = document.getElementById(boxId);
  const value = box?.textContent || '';
  if (!value) return false;

  const copied = await copyText(value);
  if (copied) {
    if (box) box.classList.remove('copy-failed');
    if (successNotice) {
      renderCopyStatus(statusId, 'notice', '✓', successNotice.title, successNotice.detail);
    } else {
      clearCopyStatus(boxId, statusId);
    }
    showToast(successText, 'success');
    return true;
  }

  // Select the text so the only remaining step is one keystroke.
  const selected = selectElementText(box);
  if (box) box.classList.add('copy-failed');
  renderCopyStatus(
    statusId,
    'error',
    '!',
    failureTitle,
    selected
      ? `${noun}已选中，按 Ctrl/⌘+C 复制。`
      : `请选中下面的${noun}并按 Ctrl/⌘+C 复制。`
  );
  return false;
}

/** Render an inline copy status block above a value box. */
function renderCopyStatus(statusId, variant, iconText, title, detail) {
  const status = document.getElementById(statusId);
  if (!status) return;
  status.replaceChildren();
  status.className = `copy-status copy-status-${variant}`;

  const icon = document.createElement('span');
  icon.className = 'copy-status-icon';
  icon.textContent = iconText;

  const text = document.createElement('div');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const body = document.createElement('span');
  body.textContent = detail;
  text.append(heading, body);

  status.append(icon, text);
  status.style.display = 'flex';
  status.scrollIntoView({ block: 'nearest' });
}

/** Reset the copy status state for one value box. */
function clearCopyStatus(boxId, statusId) {
  const box = document.getElementById(boxId);
  const status = document.getElementById(statusId);
  if (box) box.classList.remove('copy-failed');
  if (status) {
    status.className = 'copy-status';
    status.style.display = 'none';
    status.replaceChildren();
  }
}

/**
 * Select an element's text so the user only needs to press Ctrl+C.
 *
 * Returns whether the selection took, so the failure message can tell the
 * truth instead of promising a selection that never happened. The check uses
 * rangeCount/isCollapsed rather than the selection's string value: after the
 * copy fallback moves focus, the stringified selection can lag by a frame and
 * would make a successful selection look like a failure.
 */
function selectElementText(element) {
  if (!element) return false;
  try {
    const range = document.createRange();
    range.selectNodeContents(element);
    const selection = document.getSelection();
    if (!selection) return false;
    selection.removeAllRanges();
    selection.addRange(range);
    return selection.rangeCount > 0 && !selection.isCollapsed;
  } catch (e) {
    return false;
  }
}

/**
 * Copy text to the clipboard, falling back to the legacy command.
 *
 * navigator.clipboard is unusable in this page: the dashboard sandboxes plugin
 * iframes without allow-same-origin, giving them an opaque origin that the
 * clipboard-write permissions policy (default allowlist "self") can never
 * match, so writeText always rejects with NotAllowedError. execCommand is
 * governed by user-gesture rules instead and still works, so it is the one
 * that actually succeeds here.
 */
async function copyText(text) {
  const value = String(text || '');
  if (!value) return false;

  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (e) {
      // Expected inside the sandbox; fall through to execCommand.
    }
  }

  let textarea = null;
  try {
    textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    // Keep it off-screen without using display:none, which would make it
    // unselectable and defeat the copy.
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.width = '1px';
    textarea.style.height = '1px';
    textarea.style.padding = '0';
    textarea.style.border = 'none';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);

    const selection = document.getSelection();
    const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, value.length);
    const copied = document.execCommand('copy');

    // Leave the selection in a clean state. Without this it still points into
    // the textarea we are about to remove, and a later selectElementText()
    // would silently produce an empty selection.
    if (selection) {
      selection.removeAllRanges();
      if (previousRange) selection.addRange(previousRange);
    }
    textarea.blur();
    return copied;
  } catch (e) {
    return false;
  } finally {
    if (textarea) textarea.remove();
  }
}

function toggleVaultEncryption(input) {
  const wantsEnabled = input.checked;
  // The switch only reflects server state; revert it until the call succeeds.
  input.checked = vaultState.enabled;
  if (wantsEnabled === vaultState.enabled) return;
  if (wantsEnabled) {
    showConfirm(
      '启用后将使用 AES-256-GCM 加密凭据、自定义请求头与代理地址。密钥只显示一次，丢失后只能重置。是否继续？',
      enableVault
    );
  } else {
    showConfirm('关闭加密会把所有敏感字段还原为明文保存。是否继续？', disableVault);
  }
}

async function enableVault() {
  try {
    const data = await apiPost('/api/vault/enable', {});
    if (!data || data.status !== 'ok' || !data.key) {
      showToast(data?.message || '启用加密失败', 'error');
      await loadVaultState();
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    const keyBox = document.getElementById('vault-key-text');
    if (keyBox) keyBox.textContent = data.key;
    clearCopyStatus('vault-key-text', 'vault-key-status');
    openModal('vault-key-modal');
    await loadSites();
  } catch (e) {
    showToast('启用加密请求失败', 'error');
  }
}

async function disableVault() {
  try {
    const data = await apiPost('/api/vault/disable', {});
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '关闭加密失败', 'error');
      await loadVaultState();
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    showToast(data.message || '加密已关闭', 'success');
    await loadSites();
  } catch (e) {
    showToast('关闭加密请求失败', 'error');
  }
}

async function copyVaultKey() {
  await runCopy({
    boxId: 'vault-key-text',
    statusId: 'vault-key-status',
    successText: '密钥已复制到剪贴板',
    // Copying is not saving: the clipboard can be overwritten at any moment,
    // and this key is never shown again.
    successNotice: {
      title: '先粘贴保存，再关闭',
      detail: '密钥不会再次显示，剪贴板随时可能被覆盖。'
    },
    failureTitle: '复制失败，请手动复制',
    noun: '密钥'
  });
}

function openUnlockModal() {
  const input = document.getElementById('vault-unlock-key');
  if (input) input.value = '';
  openModal('vault-unlock-modal');
  if (input) input.focus();
}

async function submitUnlockVault() {
  const input = document.getElementById('vault-unlock-key');
  const key = input ? input.value.trim() : '';
  if (!key) {
    showToast('请粘贴密钥', 'warning');
    return;
  }
  try {
    const data = await apiPost('/api/vault/unlock', { key });
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '解锁失败', 'error');
      return;
    }
    applyVaultState(data.vault);
    if (input) input.value = '';
    closeModal('vault-unlock-modal');
    showToast('解锁成功', 'success');
    await loadSites();
  } catch (e) {
    showToast('解锁请求失败', 'error');
  }
}

function lockVault() {
  showConfirm('锁定后需要重新输入密钥才能查看和使用敏感配置，定时签到将暂时跳过所有站点。是否继续？', async () => {
    try {
      const data = await apiPost('/api/vault/lock', {});
      applyVaultState(data?.vault);
      showToast(data?.message || '已锁定', 'success');
      await loadSites();
    } catch (e) {
      showToast('锁定请求失败', 'error');
    }
  });
}

function openResetVaultModal() {
  const input = document.getElementById('vault-reset-confirm');
  if (input) input.value = '';
  openModal('vault-reset-modal');
  if (input) input.focus();
}

async function submitResetVault() {
  const input = document.getElementById('vault-reset-confirm');
  if ((input ? input.value.trim().toUpperCase() : '') !== 'RESET') {
    showToast('请输入 RESET 以确认重置', 'warning');
    return;
  }
  const confirmed = await showConfirm('最后确认：所有站点的凭据、自定义请求头与代理地址都会被清空，且无法恢复。');
  if (!confirmed) return;
  try {
    const data = await apiPost('/api/vault/reset', { confirm: 'reset' });
    if (!data || data.status !== 'ok') {
      showToast(data?.message || '重置失败', 'error');
      return;
    }
    applyVaultState(data.vault);
    await loadKeySlots();
    closeModal('vault-reset-modal');
    showToast(data.message || '已重置加密', 'success');
    await loadSites();
  } catch (e) {
    showToast('重置请求失败', 'error');
  }
}

// Global Settings Actions
async function loadSettings() {
  try {
    const data = await apiGet('/api/settings');
    if (data && typeof data === 'object') {
      settings = { ...settings, ...data };
      renderSettingsForm();
      applyVaultState(data.vault);
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
  document.getElementById('setting-enabled').checked = settings.enabled === true;
  const isRandom = settings.random_enabled === true;
  document.getElementById('setting-random').checked = isRandom;
  document.getElementById('setting-start-time').value = settings.start_time;
  document.getElementById('setting-end-time').value = settings.end_time;
  document.getElementById('setting-fixed-time').value = settings.checkin_time;
  document.getElementById('setting-http-ssl-verify').checked = settings.http_ssl_verify === true;
  document.getElementById('setting-http-timeout').value = settings.http_timeout_seconds;
  const maxRecordsInput = document.getElementById('setting-max-history-records');
  if (maxRecordsInput) {
    maxRecordsInput.value = settings.max_history_records ?? 0;
  }
  renderImpersonateOptions();
  toggleRandomMode();
  renderVaultUi();
}

function renderImpersonateOptions() {
  const select = document.getElementById('setting-http-impersonate');
  if (!select) return;

  const values = Array.isArray(settings.http_impersonate_options)
    ? settings.http_impersonate_options.map(normalizeImpersonateValue).filter(Boolean)
    : [];
  const normalizedCurrent = normalizeImpersonateValue(settings.http_impersonate);
  const options = [...new Set(values)];

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
  select.value = options.includes(normalizedCurrent) ? normalizedCurrent : options[0];
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
  const http_impersonate = httpImpersonateSelect.value;
  const maxRecordsInput = document.getElementById('setting-max-history-records');
  const max_history_records = Math.max(0, parseInt(maxRecordsInput ? maxRecordsInput.value : 0, 10) || 0);
  if (maxRecordsInput) maxRecordsInput.value = String(max_history_records);

  settings = {
    enabled,
    random_enabled,
    start_time,
    end_time,
    checkin_time,
    http_ssl_verify,
    http_timeout_seconds,
    http_impersonate,
    max_history_records
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

// History Logs Actions & Infinite Scroll Pagination
function getLogTitle(log) {
  if (log.type === 'test') return '单站连通性测试';
  if (log.type === 'manual' || (log.manual && log.type !== 'test')) return '手动一键签到';
  return '自动定时签到';
}

/**
 * Collapse a value to a single short line.
 * Response bodies can be whole HTML pages or JSON documents, so the overview
 * flattens every run of whitespace before truncating.
 */
function abridge(text, limit = 120) {
  const flat = String(text ?? '').replace(/\s+/g, ' ').trim();
  return flat.length > limit ? `${flat.slice(0, limit)}…` : flat;
}

/** Derive overview counters from a log's per-site results. */
function summarizeLog(log) {
  const details = Array.isArray(log?.details) ? log.details : [];
  let okCount = 0;
  let totalQuota = 0;
  let hasQuota = false;
  const parts = [];

  details.forEach(item => {
    if (item?.success) okCount += 1;
    const quota = Number(item?.total_quota);
    if (Number.isFinite(quota) && quota > 0) {
      totalQuota += quota;
      hasQuota = true;
    }
    const name = item?.site_name || item?.site_id || '未命名站点';
    const message = abridge(item?.message, 40);
    parts.push(message ? `${name}: ${message}` : name);
  });

  return {
    okCount,
    total: details.length,
    totalQuota: hasQuota ? totalQuota : null,
    // Built from structured fields rather than log.report, which embeds the
    // raw station messages verbatim.
    preview: parts.length ? abridge(parts.join(' · '), 160) : abridge(log?.report, 160)
  };
}

function createLogTimelineItem(log) {
  const item = document.createElement('div');
  item.className = 'timeline-item';

  const details = Array.isArray(log?.details) ? log.details : [];
  const single = details.length === 1 ? details[0] : null;

  const header = document.createElement('div');
  header.className = 'timeline-header';
  const title = document.createElement('span');
  title.className = 'timeline-title';
  // One entry is one site, so lead with its name; the run type is secondary.
  title.textContent = single
    ? `${single.site_name || single.site_id || '未命名站点'} · ${getLogTitle(log)}`
    : getLogTitle(log);
  const time = document.createElement('span');
  time.className = 'timeline-time';
  time.textContent = log.timestamp || '';
  header.append(title, time);

  const stats = summarizeLog(log);
  const summary = document.createElement('div');
  summary.className = 'timeline-summary';
  if (single) {
    const status = document.createElement('span');
    if (single.success) {
      status.className = 'badge badge-success';
      status.textContent = '成功';
    } else if (single.expired) {
      status.className = 'badge badge-failure';
      status.textContent = 'Token 失效';
    } else {
      status.className = 'badge badge-failure';
      status.textContent = '失败';
    }
    summary.appendChild(status);
    const gained = Number(single.gained_quota);
    if (Number.isFinite(gained) && gained > 0) {
      const gain = document.createElement('span');
      gain.className = 'badge badge-success';
      gain.textContent = `+${formatBalance(gained)}`;
      summary.appendChild(gain);
    }
  } else if (stats.total > 0) {
    const counts = document.createElement('span');
    const allOk = stats.okCount === stats.total;
    counts.className = `badge ${allOk ? 'badge-success' : 'badge-warning'}`;
    counts.textContent = `成功 ${stats.okCount}/${stats.total}`;
    summary.appendChild(counts);
  } else {
    const empty = document.createElement('span');
    empty.className = 'badge badge-info';
    empty.textContent = log.success ? '已完成' : '无站点结果';
    summary.appendChild(empty);
  }
  if (stats.totalQuota !== null) {
    const balance = document.createElement('span');
    balance.className = 'badge badge-info';
    balance.textContent = single
      ? `余额 ${formatBalance(stats.totalQuota)}`
      : `总余额 ${formatBalance(stats.totalQuota)}`;
    summary.appendChild(balance);
  }

  const preview = document.createElement('div');
  preview.className = 'timeline-preview';
  // Abridged on purpose: a station message can be a whole HTML page or JSON
  // document, which belongs in the detail view, not the overview.
  preview.textContent = single
    ? (abridge(single.message, 160) || '无更多信息')
    : (stats.preview || '无更多信息');
  preview.title = '点击「查看详情」查看完整报文';

  const actions = document.createElement('div');
  actions.className = 'timeline-actions';
  actions.appendChild(
    createActionButton('查看详情', 'btn-primary-plain', () => openLogDetail(log), false)
  );

  item.append(header, summary, preview, actions);
  return item;
}

function createLogDetailBlock(labelText, value, className = '') {
  const block = document.createElement('div');
  block.className = `log-detail-block${className ? ` ${className}` : ''}`;
  const label = document.createElement('div');
  label.className = 'log-detail-label';
  label.textContent = labelText;
  const pre = document.createElement('pre');
  pre.className = 'log-detail-pre';
  if (className.includes('log-detail-report') || className.includes('summary')) {
    pre.classList.add('log-detail-summary');
  }
  pre.textContent = value || '';
  block.append(label, pre);
  return block;
}

function createLogAttemptElement(attempt, index) {
  const item = attempt || {};
  const attemptElement = document.createElement('div');
  attemptElement.className = `log-attempt ${item.success === true ? 'success' : 'failed'}`;

  const header = document.createElement('div');
  header.className = 'log-attempt-header';
  const step = document.createElement('span');
  step.className = 'log-attempt-step';
  step.textContent = item.step || `请求 ${index + 1}`;
  const status = document.createElement('span');
  status.className = 'log-attempt-status';
  status.textContent = item.status !== null && item.status !== undefined
    ? `HTTP ${item.status}`
    : '未收到 HTTP 响应';
  header.append(step, status);

  const url = document.createElement('div');
  url.className = 'log-attempt-url';
  url.textContent = `${item.method || ''} ${item.url || ''}`.trim();
  attemptElement.append(header, url);

  if (item.message) {
    const message = document.createElement('div');
    message.className = 'log-detail-message';
    message.textContent = item.message;
    attemptElement.appendChild(message);
  }
  if (item.error) {
    const error = document.createElement('div');
    error.className = 'log-detail-error';
    error.textContent = `异常：${item.error}`;
    attemptElement.appendChild(error);
  }
  if (item.response) {
    const responseLength = item.response_length ? `（${item.response_length} 字符）` : '';
    attemptElement.appendChild(
      createLogDetailBlock(`响应内容${responseLength}`, item.response)
    );
  }
  return attemptElement;
}

function createLogResultElement(result, index) {
  const item = result || {};
  const resultElement = document.createElement('section');
  resultElement.className = 'log-detail-result';

  const resultHeader = document.createElement('div');
  resultHeader.className = 'log-detail-result-header';
  const siteInfo = document.createElement('div');
  const site = document.createElement('div');
  site.className = 'log-detail-site';
  site.textContent = item.site_name || `站点 ${index + 1}`;
  const siteId = document.createElement('div');
  siteId.className = 'log-detail-site-id';
  siteId.textContent = `ID：${item.site_id || '未记录'}`;
  siteInfo.append(site, siteId);
  const resultStatus = document.createElement('div');
  resultStatus.className = `log-detail-status ${item.success ? 'success' : 'failed'}`;
  resultStatus.textContent = item.success ? '成功' : (item.expired ? '鉴权失败' : '失败');
  resultHeader.append(siteInfo, resultStatus);
  resultElement.appendChild(resultHeader);

  const message = document.createElement('div');
  message.className = 'log-detail-message';
  message.textContent = item.message || '未记录结果消息';
  resultElement.appendChild(message);

  const quota = Number(item.total_quota);
  if (Number.isFinite(quota) && quota > 0) {
    const balance = document.createElement('div');
    balance.className = 'log-detail-balance';
    balance.textContent = `余额：${formatBalance(quota)}`;
    resultElement.appendChild(balance);
  }

  if (item.error_detail) {
    resultElement.appendChild(
      createLogDetailBlock('请求摘要', item.error_detail, 'log-detail-summary-block')
    );
  }

  const attempts = Array.isArray(item.attempts) ? item.attempts : [];
  const attemptsLabel = document.createElement('div');
  attemptsLabel.className = 'log-detail-label log-detail-attempts-label';
  attemptsLabel.textContent = `请求链路（${attempts.length} 次）`;
  resultElement.appendChild(attemptsLabel);

  const attemptList = document.createElement('div');
  attemptList.className = 'log-attempt-list';
  if (attempts.length > 0) {
    attempts.forEach((attempt, attemptIndex) => {
      attemptList.appendChild(createLogAttemptElement(attempt, attemptIndex));
    });
  } else {
    const empty = document.createElement('div');
    empty.className = 'log-detail-empty';
    empty.textContent = '该条历史记录没有保存请求级详情（旧版本日志）。';
    attemptList.appendChild(empty);
  }
  resultElement.appendChild(attemptList);
  return resultElement;
}

function openLogDetail(log) {
  if (!log) return;
  const title = document.getElementById('log-detail-title');
  const body = document.getElementById('log-detail-body');
  if (!body) return;

  const details = Array.isArray(log.details) ? log.details : [];
  // One entry is normally one site, so name it in the title rather than making
  // the user hunt for it. Pre-split entries fall back to a neutral heading.
  const single = details.length === 1 ? details[0] : null;
  const siteName = single ? (single.site_name || single.site_id || '未命名站点') : '';
  if (title) {
    title.textContent = siteName
      ? `${siteName} · ${log.timestamp || ''}`
      : `签到日志详情 · ${log.timestamp || ''}`;
  }
  body.replaceChildren();

  const overview = document.createElement('div');
  overview.className = 'log-detail-overview';
  const fields = [['类型', getLogTitle(log)], ['时间', log.timestamp || '未记录']];
  if (!single && details.length > 1) {
    fields.push(['站点数', String(details.length)]);
  }
  fields.forEach(([labelText, value]) => {
    const field = document.createElement('div');
    const label = document.createElement('span');
    label.textContent = labelText;
    const strong = document.createElement('strong');
    strong.textContent = value;
    field.append(label, strong);
    overview.appendChild(field);
  });
  body.appendChild(overview);

  // No aggregate report block: an entry covers one site's task, and its status,
  // message and balance already appear in the section below. Older databases
  // may still hold pre-split entries with several sites, so the loop stays.
  if (details.length > 0) {
    details.forEach((result, resultIndex) => {
      body.appendChild(createLogResultElement(result, resultIndex));
    });
  } else {
    const empty = document.createElement('div');
    empty.className = 'log-detail-empty';
    empty.textContent = '这条日志没有站点详情。';
    body.appendChild(empty);
  }
  openModal('log-detail-modal');
}

function renderLogMessage(container, message) {
  if (!container) return;
  container.replaceChildren();
  const empty = document.createElement('div');
  empty.className = 'empty-text';
  empty.textContent = message;
  container.appendChild(empty);
}

function updateLogsFooter(isLoadingMore) {
  const container = document.getElementById('logs-body');
  if (!container) return;

  const existingLoading = container.querySelector('.logs-loading-more');
  if (existingLoading) existingLoading.remove();
  const existingEnd = container.querySelector('.logs-end-line');
  if (existingEnd) existingEnd.remove();

  if (logItems.length === 0) return;

  if (isLoadingMore) {
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'logs-loading-more';
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    const text = document.createElement('span');
    text.textContent = '正在加载更多历史记录...';
    loadingDiv.append(spinner, text);
    container.appendChild(loadingDiv);
  } else if (!logsHasMore) {
    const endDiv = document.createElement('div');
    endDiv.className = 'logs-end-line';
    const total = logsTotal || logItems.length;
    endDiv.textContent = logsStartDate || logsEndDate
      ? `筛选结果：共 ${total} 条日志`
      : `已加载全部日志 (共 ${total} 条)`;
    container.appendChild(endDiv);
  }
}

function syncLogTimeFilterFields() {
  const startInput = document.getElementById('logs-start-date');
  const endInput = document.getElementById('logs-end-date');
  if (startInput) startInput.value = logsStartDate;
  if (endInput) endInput.value = logsEndDate;
}

function applyLogTimeFilter() {
  const startInput = document.getElementById('logs-start-date');
  const endInput = document.getElementById('logs-end-date');
  const startDate = startInput?.value || '';
  const endDate = endInput?.value || '';

  if (startDate && endDate && startDate > endDate) {
    showToast('开始日期不能晚于结束日期', 'warning');
    return;
  }

  logsStartDate = startDate;
  logsEndDate = endDate;
  fetchLogsPage(true);
}

function resetLogTimeFilter() {
  logsStartDate = '';
  logsEndDate = '';
  syncLogTimeFilterFields();
  fetchLogsPage(true);
}

async function fetchLogsPage(isInitial = false) {
  const container = document.getElementById('logs-body');
  if (!container) return;
  if (logsLoading || (!isInitial && !logsHasMore)) return;

  logsLoading = true;

  if (isInitial) {
    logItems = [];
    logsNextBeforeId = null;
    logsHasMore = true;
    logsTotal = 0;
    renderLogMessage(container, '正在加载历史日志...');
  } else {
    updateLogsFooter(true);
  }

  try {
    const params = { limit: 20 };
    if (logsNextBeforeId !== null && logsNextBeforeId !== undefined) {
      params.before_id = logsNextBeforeId;
    }
    if (logsStartDate) params.start_date = logsStartDate;
    if (logsEndDate) params.end_date = logsEndDate;

    const data = await apiGet('/api/logs', params);
    let newItems = [];

    if (data && typeof data === 'object' && !Array.isArray(data)) {
      newItems = Array.isArray(data.items) ? data.items : [];
      logsHasMore = Boolean(data.has_more);
      logsTotal = typeof data.total === 'number' ? data.total : (logItems.length + newItems.length);
      logsNextBeforeId = data.next_before_id ?? (newItems.length > 0 ? newItems[newItems.length - 1].id : null);
    } else if (Array.isArray(data)) {
      newItems = data;
      logsHasMore = newItems.length === 20;
      logsNextBeforeId = newItems.length > 0 ? newItems[newItems.length - 1].id : null;
      logsTotal = logItems.length + newItems.length;
    }

    if (isInitial) {
      container.replaceChildren();
      if (newItems.length === 0) {
        renderLogMessage(
          container,
          logsStartDate || logsEndDate
            ? '该时间范围内没有签到记录'
            : '暂无签到历史记录'
        );
        logsLoading = false;
        return;
      }
      const timeline = document.createElement('div');
      timeline.className = 'timeline';
      timeline.id = 'logs-timeline';
      container.appendChild(timeline);
    }

    const timeline = document.getElementById('logs-timeline');
    if (timeline) {
      newItems.forEach(log => {
        logItems.push(log);
        timeline.appendChild(createLogTimelineItem(log));
      });
    }

    updateLogsFooter(false);
  } catch (e) {
    console.error('fetchLogsPage error:', e);
    if (isInitial) {
      renderLogMessage(container, '读取日志失败');
    }
  } finally {
    logsLoading = false;
  }
}

function handleLogsScroll() {
  const body = document.getElementById('logs-body');
  if (!body || logsLoading || !logsHasMore) return;
  if (body.scrollTop + body.clientHeight >= body.scrollHeight - 80) {
    fetchLogsPage(false);
  }
}

function openLogsDrawer() {
  openModal('logs-drawer');
  syncLogTimeFilterFields();
  fetchLogsPage(true);
}

async function loadLogs() {
  const drawer = document.getElementById('logs-drawer');
  if (drawer && drawer.classList.contains('active')) {
    await fetchLogsPage(true);
  }
}

function clearLogs() {
  showConfirm('确定要清空所有历史签到日志吗？此操作无法撤销。', async () => {
    try {
      await apiPost('/api/logs/clear', {});
      logItems = [];
      logsNextBeforeId = null;
      logsHasMore = false;
      logsTotal = 0;
      // Nothing is left to filter, so drop the range too.
      logsStartDate = '';
      logsEndDate = '';
      syncLogTimeFilterFields();
      const container = document.getElementById('logs-body');
      renderLogMessage(container, '暂无签到历史记录');
      showToast('历史日志已成功清空', 'success');
    } catch (e) {
      showToast('清空日志失败', 'error');
    }
  });
}

// Initial Loading
document.addEventListener('DOMContentLoaded', () => {
  loadVaultState();
  loadSites();
  loadSettings();
  const logsBody = document.getElementById('logs-body');
  if (logsBody) {
    logsBody.addEventListener('scroll', handleLogsScroll);
  }
  const unlockInput = document.getElementById('vault-unlock-key');
  if (unlockInput) {
    unlockInput.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        submitUnlockVault();
      }
    });
  }
});
