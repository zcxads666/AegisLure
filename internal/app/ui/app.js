import {
  html,
  render,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from './htm-preact.module.js'

const ADMIN_BASE = document.body.dataset.adminBase || '/'
const BASE = ADMIN_BASE.endsWith('/') ? ADMIN_BASE : `${ADMIN_BASE}/`
const jsonHeaders = { 'Content-Type': 'application/json', Accept: 'application/json' }

const NAV_ITEMS = [
  { id: 'dashboard', label: '总览', caption: 'Dashboard', icon: 'grid' },
  { id: 'observations', label: '观测记录', caption: 'Observations', icon: 'activity' },
  { id: 'invocations', label: '调用分析', caption: 'Invocations', icon: 'spark' },
  { id: 'chains', label: '交互链路', caption: 'Chains', icon: 'route' },
  { id: 'indicators', label: 'IP 情报', caption: 'Indicators', icon: 'shield' },
  { id: 'instances', label: '蜜罐实例', caption: 'Instances', icon: 'server' },
  { id: 'packs', label: '规则与策略', caption: 'Packs', icon: 'layers' },
]

const PROFILE_LABELS = {
  'new-api': 'New API',
  vllm: 'vLLM',
  ollama: 'Ollama',
  sglang: 'SGLang',
  localai: 'LocalAI',
}

const ICON_PATHS = {
  activity: ['M4 12h4l2-8 4 16 2-8h4', 'M3 12h18'],
  arrow: ['M5 12h14', 'm13 6 6 6-6 6'],
  bell: ['M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9', 'M10 21h4'],
  check: ['m5 12 4 4L19 6'],
  chevron: ['m9 18 6-6-6-6'],
  clock: ['M12 7v5l3 2', 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z'],
  close: ['m6 6 12 12', 'm18 6-12 12'],
  copy: ['M9 9h10v10H9z', 'M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M5 21h14'],
  eye: ['M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z'],
  grid: ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  key: ['M15.5 7.5a4.5 4.5 0 1 1-8.2 2.5L3 14.3V18h3v-2h2v-2h2.3', 'm17 5 2 2'],
  layers: ['m12 3 9 5-9 5-9-5 9-5Z', 'm3 12 9 5 9-5', 'm3 16 9 5 9-5'],
  lock: ['M6 10V7a6 6 0 0 1 12 0v3', 'M5 10h14v10H5z', 'M12 14v2'],
  logout: ['M10 17l5-5-5-5', 'M15 12H3', 'M21 19V5a2 2 0 0 0-2-2h-5'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  pause: ['M7 5v14', 'M17 5v14'],
  play: ['m8 5 11 7-11 7V5Z'],
  plus: ['M12 5v14', 'M5 12h14'],
  refresh: ['M20 11a8 8 0 1 0 1 5', 'M20 5v6h-6'],
  route: ['M5 4a2 2 0 1 0 0 4 2 2 0 0 0-4 0Z', 'M19 16a2 2 0 1 0 0 4 2 2 0 0 0-4 2Z', 'M7 6h5a4 4 0 0 1 4 4v6', 'm13 16 3 3 3-3'],
  search: ['m21 21-4.3-4.3', 'M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z'],
  server: ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M7 7h.01', 'M7 17h.01', 'M11 7h6', 'M11 17h6'],
  shield: ['M12 3 20 6v5c0 5.2-3.4 8.8-8 10-4.6-1.2-8-4.8-8-10V6l8-3Z', 'm8.5 12 2.2 2.2 4.8-5'],
  spark: ['m12 3-1.5 6.5L4 11l6.5 1.5L12 19l1.5-6.5L20 11l-6.5-1.5L12 3Z'],
  user: ['M20 21a8 8 0 0 0-16 0', 'M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z'],
  warning: ['M12 3 2 21h20L12 3Z', 'M12 9v4', 'M12 17h.01'],
}

const LEVEL_LABELS = {
  L0_no_invocation: 'L0 · 发现',
  L1_rejected_attempt: 'L1 · 被拒绝',
  L2_synthetic_accepted: 'L2 · 已接受',
  L3_response_consumed: 'L3 · 已消费',
  L4_post_call_verified: 'L4 · 已验证',
}

class APIError extends Error {
  constructor(message, status, data) {
    super(message)
    this.status = status
    this.data = data
  }
}

function icon(name, size = 18) {
  const paths = ICON_PATHS[name] || ICON_PATHS.spark
  return html`<svg class="icon" width=${size} height=${size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    ${paths.map((path) => html`<path d=${path}></path>`)}
  </svg>`
}

function formatNumber(value) {
  return new Intl.NumberFormat('zh-CN').format(Number(value || 0))
}

function formatTime(value, withSeconds = false) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat('zh-CN', {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined, hour12: false,
  }).format(date)
}

function shortValue(value, size = 18) {
  if (!value) return '—'
  const text = String(value)
  return text.length > size ? `${text.slice(0, size)}…` : text
}

function profileLabel(value) { return PROFILE_LABELS[value] || value || '未知' }
function levelLabel(value) { return LEVEL_LABELS[value] || value || '未分级' }
function apiPath(path) { return `${BASE}admin/api/v1/${path}` }

async function request(path, options = {}) {
  const response = await fetch(path.startsWith('setup/') ? `${BASE}${path}` : apiPath(path), {
    credentials: 'same-origin',
    ...options,
    headers: { Accept: 'application/json', ...(options.body ? jsonHeaders : {}), ...(options.headers || {}) },
  })
  const type = response.headers.get('content-type') || ''
  const data = type.includes('json') ? await response.json().catch(() => ({})) : await response.text()
  if (!response.ok) {
    const message = typeof data === 'string' ? data : data.error || data.message || `请求失败（${response.status}）`
    throw new APIError(message, response.status, data)
  }
  return data
}

function navigateTo(route, replace = false) {
  const next = route === 'dashboard' ? BASE : `${BASE}${route}`
  if (window.location.pathname !== next) window.history[replace ? 'replaceState' : 'pushState']({}, '', next)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

function routeFromLocation() {
  const current = window.location.pathname
  if (!current.startsWith(BASE)) return 'login'
  const route = current.slice(BASE.length).replace(/^\/+|\/+$/g, '')
  return route || 'dashboard'
}

function cn(...values) { return values.filter(Boolean).join(' ') }

function Button({ variant = 'secondary', size = 'md', icon: iconName, children, className, ...props }) {
  return html`<button class=${cn('button', `button-${variant}`, `button-${size}`, className)} ...${props}>
    ${iconName ? icon(iconName, size === 'sm' ? 15 : 17) : null}<span>${children}</span>
  </button>`
}

function Badge({ children, tone = 'neutral', dot = false }) {
  return html`<span class=${cn('badge', `badge-${tone}`)}>${dot ? html`<i class="badge-dot"></i>` : null}${children}</span>`
}

function Panel({ title, eyebrow, action, className, children, flush = false }) {
  return html`<section class=${cn('panel', flush && 'panel-flush', className)}>
    ${(title || eyebrow || action) ? html`<header class="panel-header"><div>${eyebrow ? html`<p class="eyebrow">${eyebrow}</p>` : null}${title ? html`<h2>${title}</h2>` : null}</div>${action || null}</header>` : null}
    ${children}
  </section>`
}

function PageHeader({ eyebrow = 'Control plane', title, description, actions }) {
  return html`<header class="page-header"><div><p class="eyebrow">${eyebrow}</p><h1>${title}</h1>${description ? html`<p class="page-description">${description}</p>` : null}</div>${actions ? html`<div class="page-actions">${actions}</div>` : null}</header>`
}

function MetricCard({ label, value, detail, tone = 'cyan', icon: iconName }) {
  return html`<article class=${cn('metric-card', `metric-${tone}`)}><div class="metric-top"><span>${label}</span>${iconName ? html`<span class="metric-icon">${icon(iconName, 17)}</span>` : null}</div><strong>${value}</strong>${detail ? html`<small>${detail}</small>` : null}</article>`
}

function EmptyState({ icon: iconName = 'activity', title = '暂无数据', description = '新的观测出现后会显示在这里。' }) {
  return html`<div class="empty-state">${icon(iconName, 26)}<strong>${title}</strong><p>${description}</p></div>`
}

function LoadingState({ label = '读取中…' }) { return html`<div class="loading-state"><span class="spinner"></span><span>${label}</span></div>` }

function RiskBadge({ score }) {
  const value = Number(score || 0)
  const tone = value >= 60 ? 'danger' : value >= 30 ? 'warning' : 'success'
  const label = value >= 60 ? '高风险' : value >= 30 ? '中风险' : '低风险'
  return html`<span class="risk-score"><b class=${`risk-${tone}`}>${value}</b><span>${label}</span></span>`
}

function StatusBadge({ state }) {
  const running = state === 'running'
  return html`<${Badge} tone=${running ? 'success' : 'neutral'} dot=${true}>${running ? '运行中' : '已停止'}<//>`
}

function Modal({ title, eyebrow, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (event) => event.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  return html`<div class="modal-backdrop" onClick=${(event) => event.target === event.currentTarget && onClose()}><section class=${cn('modal', wide && 'modal-wide')} role="dialog" aria-modal="true" aria-label=${title}><header class="modal-header">${eyebrow ? html`<p class="eyebrow">${eyebrow}</p>` : null}<h2>${title}</h2><button class="icon-button" type="button" onClick=${onClose} aria-label="关闭">${icon('close', 19)}</button></header><div class="modal-body">${children}</div></section></div>`
}

function DataTable({ columns, rows, onRowClick, emptyTitle, emptyDescription }) {
  if (!rows || rows.length === 0) return html`<${EmptyState} title=${emptyTitle} description=${emptyDescription} />`
  const headerCells = columns.map((column) => html`<th class=${column.className || ''}>${column.label}</th>`)
  const tableRows = rows.map((row, index) => {
    const cells = columns.map((column) => html`<td class=${column.className || ''}>${column.render ? column.render(row) : row[column.key] || '—'}</td>`)
    const click = onRowClick ? () => onRowClick(row) : undefined
    return html`<tr key=${row.event_id || row.id || row.session_id || index} onClick=${click} class=${onRowClick ? 'is-clickable' : ''}>${cells}</tr>`
  })
  return html`<div class="table-scroll"><table class="data-table"><thead><tr>${headerCells}</tr></thead><tbody>${tableRows}</tbody></table></div>`
}

function FilterBar({ children, onReset }) { return html`<div class="filter-bar">${children}${onReset ? html`<button class="text-button" type="button" onClick=${onReset}>重置筛选</button>` : null}</div>` }

function Select({ label, value, onChange, options, className }) {
  return html`<label class=${cn('select-field', className)}>${label ? html`<span>${label}</span>` : null}<select value=${value} onChange=${(event) => onChange(event.target.value)}>${options.map((option) => html`<option value=${option.value}>${option.label}</option>`)}</select></label>`
}

function TextInput({ label, placeholder, value, onInput, type = 'text', className, ...props }) {
  return html`<label class=${cn('text-field', className)}>${label ? html`<span>${label}</span>` : null}<input type=${type} value=${value} placeholder=${placeholder} onInput=${(event) => onInput(event.target.value)} ...${props} /></label>`
}

function Toggle({ checked, onChange, label, disabled = false }) {
  return html`<button type="button" class=${cn('toggle', checked && 'is-on')} onClick=${() => onChange(!checked)} disabled=${disabled} role="switch" aria-checked=${checked} aria-label=${label || '切换状态'}><span></span></button>`
}

function ActivityChart({ items = [] }) {
  const max = Math.max(1, ...items.map((item) => Number(item.count || 0)))
  return html`<div class="activity-chart" aria-label="近 24 小时事件量">${items.map((item) => html`<div class="activity-bar-wrap"><div class="activity-value">${item.count || ''}</div><div class="activity-bar" style=${{ height: `${Math.max(5, (Number(item.count || 0) / max) * 100)}%` }}></div><small>${item.label}</small></div>`)}</div>`
}

function RiskDonut({ distribution = {} }) {
  const low = Number(distribution.low || 0); const medium = Number(distribution.medium || 0); const high = Number(distribution.high || 0); const total = low + medium + high
  const highPct = total ? Math.round((high / total) * 100) : 0; const mediumPct = total ? Math.round((medium / total) * 100) : 0
  const gradient = total ? `conic-gradient(#ef7185 0 ${highPct}%, #edb968 ${highPct}% ${highPct + mediumPct}%, #56d6bd ${highPct + mediumPct}% 100%)` : 'conic-gradient(#22334d 0 100%)'
  return html`<div class="risk-donut-wrap"><div class="risk-donut" style=${{ background: gradient }}><div><strong>${formatNumber(total)}</strong><small>IP 指标</small></div></div><div class="legend-list"><div><i class="legend-dot dot-danger"></i><span>高风险</span><b>${high}</b></div><div><i class="legend-dot dot-warning"></i><span>中风险</span><b>${medium}</b></div><div><i class="legend-dot dot-success"></i><span>低风险</span><b>${low}</b></div></div></div>`
}

function RiskActivityChart({ series = {} }) {
  const [period, setPeriod] = useState('day')
  const periods = [{ key: 'day', label: '近24小时', detail: '每 2 小时' }, { key: 'week', label: '近 7 天', detail: '每日' }, { key: 'month', label: '近 30 天', detail: '每日' }]
  const selected = series[period] || {}
  const points = Array.isArray(selected.points) ? selected.points : []
  const width = 760; const height = 238; const padding = { top: 18, right: 14, bottom: 32, left: 14 }
  const plotWidth = width - padding.left - padding.right; const plotHeight = height - padding.top - padding.bottom
  const max = Math.max(1, ...points.map((point) => Math.max(Number(point.count || 0), Number(point.risk_count || 0))))
  const x = (index) => points.length <= 1 ? width / 2 : padding.left + (index * plotWidth) / (points.length - 1)
  const y = (value) => padding.top + plotHeight * (1 - Number(value || 0) / max)
  const linePath = (key) => points.map((point, index) => `${index === 0 ? 'M' : 'L'} ${x(index)} ${y(point[key])}`).join(' ')
  const totalPath = linePath('count'); const riskPath = linePath('risk_count')
  const baseline = height - padding.bottom
  const areaPath = points.length ? `M ${x(0)} ${baseline} L ${points.map((point, index) => `${x(index)} ${y(point.count)}`).join(' L ')} L ${x(points.length - 1)} ${baseline} Z` : ''
  const labelStep = Math.max(1, Math.ceil(points.length / 6))
  return html`<div class="risk-activity"><div class="chart-switcher" role="tablist" aria-label="趋势时间范围">${periods.map((item) => html`<button key=${item.key} type="button" class=${cn(period === item.key && 'is-active')} onClick=${() => setPeriod(item.key)} role="tab" aria-selected=${period === item.key}><b>${item.label}</b><small>${item.detail}</small></button>`)}</div>${points.length ? html`<div class="risk-chart-canvas"><svg viewBox=${`0 0 ${width} ${height}`} role="img" aria-label=${`${periods.find((item) => item.key === period)?.label || ''}风险触发趋势`}><defs><linearGradient id="risk-area-gradient" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#6edfeb" stop-opacity=".28"></stop><stop offset="100%" stop-color="#6edfeb" stop-opacity="0"></stop></linearGradient></defs>${[0, .25, .5, .75, 1].map((ratio) => html`<line key=${ratio} class="chart-grid-line" x1=${padding.left} x2=${width - padding.right} y1=${y(ratio * max)} y2=${y(ratio * max)}></line>`)}<path class="chart-area" d=${areaPath}></path><path class="chart-line chart-line-total" d=${totalPath}></path><path class="chart-line chart-line-risk" d=${riskPath}></path>${points.map((point, index) => html`<g key=${`${point.label}-${index}`}><circle class="chart-dot chart-dot-total" cx=${x(index)} cy=${y(point.count)} r="3.5"><title>${point.label} · 总事件 ${formatNumber(point.count)} · 风险 ${formatNumber(point.risk_count)}</title></circle><circle class="chart-dot chart-dot-risk" cx=${x(index)} cy=${y(point.risk_count)} r="3"><title>${point.label} · 风险触发 ${formatNumber(point.risk_count)}</title></circle>${(index === 0 || index === points.length - 1 || index % labelStep === 0) ? html`<text class="chart-label" x=${x(index)} y=${height - 8} text-anchor="middle">${point.label}</text>` : null}</g>`)}</svg></div>` : html`<${EmptyState} title="暂无趋势数据" description="新的观测事件出现后，这里会显示风险波动。" />`}<div class="chart-summary"><span><i class="chart-key key-total"></i><b>${formatNumber(selected.total)}</b> 总事件</span><span><i class="chart-key key-risk"></i><b>${formatNumber(selected.risk_total)}</b> 风险触发</span><span class="chart-threshold">阈值 ≥ ${selected.risk_threshold || 30}</span></div></div>`
}

function DistributionDonut({ items = [], centerLabel = '事件总量' }) {
  const colors = { high: '#ef7185', medium: '#edb968', low: '#56d6bd' }
  const palette = ['#6edfeb', '#9c8cf4', '#ef9b73', '#76a7ff']
  const total = items.reduce((sum, item) => sum + Number(item.count || 0), 0)
  let cursor = 0
  const stops = items.map((item, index) => {
    const start = cursor; cursor += total ? (Number(item.count || 0) / total) * 100 : 0
    return `${colors[item.key] || palette[index % palette.length]} ${start}% ${cursor}%`
  })
  const gradient = total ? `conic-gradient(${stops.join(', ')})` : 'conic-gradient(#22334d 0 100%)'
  return html`<div class="risk-donut-wrap"><div class="risk-donut" style=${{ background: gradient }}><div><strong>${formatNumber(total)}</strong><small>${centerLabel}</small></div></div><div class="legend-list">${items.map((item, index) => html`<div key=${item.key || index}><i class="legend-dot" style=${{ background: colors[item.key] || palette[index % palette.length] }}></i><span>${item.name || item.key}</span><b>${formatNumber(item.count)} <small>${item.percentage || 0}%</small></b></div>`)}</div></div>`
}

function CountryDistribution({ items = [] }) {
  const visible = items.slice(0, 7); const max = Math.max(1, ...visible.map((item) => Number(item.count || 0)))
  if (!visible.length) return html`<${EmptyState} icon="globe" title="暂无来源区域" description="聚合来源 IP 后会显示离线可识别的地址类别。" />`
  return html`<div class="country-list">${visible.map((item) => html`<div class="country-row" key=${item.key || item.name}><div class="country-row-head"><span><i class="country-bullet"></i>${item.name || '未知'}</span><b>${formatNumber(item.count)} <small>${item.percentage || 0}%</small></b></div><div class="share-progress"><i style=${{ width: `${Math.max(3, (Number(item.count || 0) / max) * 100)}%` }}></i></div></div>`)}</div><div class="panel-footnote">离线标签：本地/保留、文档地址可确定；未配置 GeoIP 数据的公网 IP 显示为“未知”。</div>`
}

function HoneypotDistribution({ items = [] }) {
  const visible = items.slice(0, 7); const max = Math.max(1, ...visible.map((item) => Number(item.count || 0)))
  if (!visible.length) return html`<${EmptyState} icon="layers" title="暂无蜜罐触发" description="访问公开端点后会按协议统计触发占比。" />`
  return html`<div class="honeypot-list">${visible.map((item, index) => html`<div class="honeypot-row" key=${item.key || item.name}><div class="honeypot-row-head"><span class="honeypot-rank">${String(index + 1).padStart(2, '0')}</span><div><b>${profileLabel(item.name)}</b><small>${formatNumber(item.count)} 次 · 风险 ${formatNumber(item.risk_count)} 次</small></div><strong>${item.percentage || 0}%</strong></div><div class="share-progress"><i style=${{ width: `${Math.max(3, (Number(item.count || 0) / max) * 100)}%` }}></i></div></div>`)}</div><div class="panel-footnote">占比按事件次数计算；“风险”表示该类型中风险分 ≥ 30 的事件。</div>`
}

function ActorDetailModal({ actor, onClose, onOpenEvent }) {
  if (!actor) return null
  if (actor.loading) return html`<${Modal} title="IP 动作详情" eyebrow="IP intelligence" onClose=${onClose}><${LoadingState} label=${`正在读取 ${actor.ip || 'IP'} 的全部动作…`} /><//>`
  const indicator = actor.indicator || {}; const events = Array.isArray(actor.events) ? actor.events : []; const riskEvents = events.filter((event) => Number(event.score || 0) >= 30).length
  const firstSeen = indicator.first_seen || events[events.length - 1]?.observed_at; const lastSeen = indicator.last_seen || events[0]?.observed_at
  return html`<${Modal} title="IP 动作详情" eyebrow=${`IP intelligence · ${actor.ip || 'unknown'}`} onClose=${onClose} wide=${true}><div class="actor-hero"><div><p class="actor-kicker">来源 IP</p><code class="actor-ip">${actor.ip || '—'}</code><div class="actor-subline"><span class="country-pill">${actor.country || '未知'}</span><span>全部事件已加载 · 按时间倒序</span></div></div><${RiskBadge} score=${indicator.score} /></div><div class="actor-summary-grid"><div><span>来源区域</span><strong>${actor.country || '未知'}</strong></div><div><span>证据次数</span><strong>${formatNumber(indicator.evidence_count || events.length)}</strong></div><div><span>风险事件</span><strong>${formatNumber(riskEvents)}</strong></div><div><span>置信度</span><strong>${indicator.confidence || 'low'}</strong></div><div><span>首次出现</span><strong>${formatTime(firstSeen)}</strong></div><div><span>最近出现</span><strong>${formatTime(lastSeen)}</strong></div></div><div class="actor-meta-row"><div><span>命中蜜罐</span><div class="chip-list compact">${(indicator.products || []).map((product) => html`<${Badge} tone="neutral" key=${product}>${profileLabel(product)}<//>`)}</div></div><div><span>建议处置</span><b class=${cn('action-label', indicator.score >= 60 && 'action-risk')}>${indicator.recommended_action || 'observe'}</b></div></div><div class="detail-section actor-actions-section"><div class="actor-actions-head"><div><p class="eyebrow">Evidence timeline</p><h3>全部动作</h3></div><span class="panel-meta">${formatNumber(events.length)} 条脱敏动作</span></div>${events.length ? html`<div class="actor-timeline">${events.map((event, index) => html`<button class="actor-action-row" type="button" key=${event.event_id || index} onClick=${() => onOpenEvent(event)}><span class=${cn('actor-action-marker', Number(event.score || 0) >= 60 && 'is-high', Number(event.score || 0) >= 30 && Number(event.score || 0) < 60 && 'is-medium')}></span><span class="actor-action-main"><b>${event.event_type || event.route_template || 'event'}</b><small>${profileLabel(event.product)} · ${event.method || 'HTTP'} ${event.route_template || 'unknown.route'}</small><em>${event.execution_outcome || event.auth_outcome || event.effect_outcome || '已记录'} · ${levelLabel(event.invocation_level)}</em></span><span class="actor-action-side"><${RiskBadge} score=${event.score} /><time>${formatTime(event.observed_at, true)}</time></span>${icon('chevron', 15)}</button>`)}</div>` : html`<${EmptyState} title="该 IP 暂无动作" description="指标仍存在，但当前没有可展示的事件记录。" />`}</div><div class="panel-footnote">点击任意动作可查看已脱敏的事件字段与命中原因；系统不会保留原始凭据。</div></${Modal}>`
}

function EventDetails({ event }) {
  if (!event) return null
  const fields = [['事件 ID', event.event_id], ['观测时间', formatTime(event.observed_at, true)], ['产品', profileLabel(event.product)], ['来源 IP', event.source_ip], ['请求路由', event.route_template], ['请求方法', event.method], ['状态码', event.status], ['风险分', event.score], ['意图分类', event.intent_class], ['调用等级', levelLabel(event.invocation_level)], ['鉴权结果', event.auth_outcome], ['执行结果', event.execution_outcome], ['效果结果', event.effect_outcome], ['模型', event.model_id], ['会话 ID', event.session_id]]
  return html`<${Modal} title="观测详情" eyebrow=${event.event_type || 'event'} onClose=${event.onClose} wide=${true}><div class="detail-grid">${fields.filter((item) => item[1] !== undefined && item[1] !== '').map((item) => html`<div class="detail-item"><span>${item[0]}</span><strong>${String(item[1])}</strong></div>`)}</div>${event.reason_codes?.length ? html`<div class="detail-section"><h3>命中原因</h3><div class="chip-list">${event.reason_codes.map((reason) => html`<${Badge} tone="warning">${reason}<//>`)}</div></div>` : null}<div class="detail-section"><h3>原始事件（已脱敏）</h3><pre class="json-view">${JSON.stringify({ ...event, onClose: undefined }, null, 2)}</pre></div><//>`
}

function LoginPage({ onLogin, onRecovery, onForgot }) {
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [modal, setModal] = useState(null)
  const submit = async (event) => { event.preventDefault(); setBusy(true); setMessage(''); try { await onLogin(username, password) } catch (error) { setMessage(error.message || '登录失败，请检查账号和密码。') } finally { setBusy(false) } }
  return html`<div class="auth-layout"><div class="auth-art"><div class="auth-orbit orbit-one"></div><div class="auth-orbit orbit-two"></div><div class="auth-glow"></div><div class="auth-brand"><span class="brand-mark">A</span><div><strong>AegisLure</strong><small>AI security sensor</small></div></div><div class="auth-copy"><p class="eyebrow">Private control plane</p><h1>看见每一次<br /><em>可疑调用。</em></h1><p>把模型服务蜜罐里的发现、调用与风险证据，收拢成一条清晰的操作链路。</p><div class="auth-facts"><span>${icon('shield', 16)}本地存储</span><span>${icon('lock', 16)}同源会话</span><span>${icon('spark', 16)}合成响应</span></div></div><div class="auth-art-foot">AegisLure / Standalone node</div></div><main class="auth-main"><div class="auth-card"><div class="mobile-brand"><span class="brand-mark">A</span><strong>AegisLure</strong></div><p class="eyebrow">Control plane</p><h2>欢迎回来</h2><p class="auth-subtitle">登录以继续查看传感器状态和观测证据。</p><form onSubmit=${submit} class="auth-form"><${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" maxLength="128" required=${true} /><${TextInput} label="密码" placeholder="输入密码" type="password" value=${password} onInput=${setPassword} autoComplete="current-password" required=${true} /><button class="button button-primary button-lg auth-submit" type="submit" disabled=${busy}>${busy ? html`<span class="spinner spinner-dark"></span>登录中…` : html`登录控制台 ${icon('arrow', 17)}`}</button></form>${message ? html`<div class="form-message error">${message}</div>` : null}<button class="link-button" type="button" onClick=${() => setModal('forgot')}>忘记密码？使用恢复码</button><div class="auth-note">${icon('shield', 15)}管理端建议仅通过可信网络或 VPN 访问。</div></div><p class="auth-footer">Synthetic-only telemetry · no real model or URL access</p></main></div>${modal === 'forgot' ? html`<${RecoveryModal} mode="forgot" onClose=${() => setModal(null)} onForgot=${onForgot} onRecovery=${onRecovery} />` : null}`
}

function RecoveryModal({ onClose, onForgot, onRecovery }) {
  const [username, setUsername] = useState(''); const [code, setCode] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [sent, setSent] = useState(false)
  const submitForgot = async (event) => { event.preventDefault(); setBusy(true); setMessage(''); try { await onForgot(username); setSent(true) } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  const submitReset = async (event) => { event.preventDefault(); if (password !== confirm) { setMessage('两次输入的新密码不一致。'); return } setBusy(true); setMessage(''); try { await onRecovery(username, code, password); onClose() } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  return html`<${Modal} title="恢复管理员访问" eyebrow="Account recovery" onClose=${onClose}>${!sent ? html`<form class="stack-form" onSubmit=${submitForgot}><p class="modal-copy">如果部署配置了恢复流程，系统会向对应渠道发送说明。账号是否存在不会通过响应泄露。</p><${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" required=${true} /><button class="button button-primary button-full" type="submit" disabled=${busy}>${busy ? '提交中…' : '发送恢复说明'}</button></form>` : html`<form class="stack-form" onSubmit=${submitReset}><div class="notice notice-info">请输入一次性恢复码。恢复码成功使用后会立即失效。</div><${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" required=${true} /><${TextInput} label="恢复码" placeholder="输入离线保存的恢复码" value=${code} onInput=${setCode} autoComplete="one-time-code" required=${true} /><${TextInput} label="新密码" placeholder="至少 8 个字符" type="password" value=${password} onInput=${setPassword} minLength="8" maxLength="128" required=${true} /><${TextInput} label="确认新密码" placeholder="再次输入新密码" type="password" value=${confirm} onInput=${setConfirm} minLength="8" maxLength="128" required=${true} /><button class="button button-primary button-full" type="submit" disabled=${busy}>${busy ? '重置中…' : '重置密码'}</button></form>`}${message ? html`<div class="form-message error">${message}</div>` : null}<//>`
}

function SetupPage({ onSetup }) {
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [codes, setCodes] = useState([]); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [copied, setCopied] = useState(false)
  const submit = async (event) => { event.preventDefault(); if (password !== confirm) { setMessage('两次输入的密码不一致。'); return } setBusy(true); setMessage(''); try { const result = await onSetup(username, password); setCodes(result.recovery_codes || []) } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  const copyCodes = async () => { try { await navigator.clipboard.writeText(codes.join('\n')); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch (_) { setMessage('浏览器不允许自动复制，请手动保存恢复码。') } }
  return html`<div class="auth-layout setup-layout"><div class="auth-art"><div class="auth-orbit orbit-one"></div><div class="auth-orbit orbit-two"></div><div class="auth-glow"></div><div class="auth-brand"><span class="brand-mark">A</span><div><strong>AegisLure</strong><small>AI security sensor</small></div></div><div class="auth-copy"><p class="eyebrow">First-time setup</p><h1>建立你的<br /><em>观测中枢。</em></h1><p>初始化本地 owner 后，你就可以查看事件、控制蜜罐实例并管理风险证据。</p><div class="auth-facts"><span>${icon('lock', 16)}Argon2id 密码</span><span>${icon('key', 16)}一次性恢复码</span><span>${icon('shield', 16)}本地管理</span></div></div><div class="auth-art-foot">AegisLure / Standalone node</div></div><main class="auth-main"><div class="auth-card">${codes.length === 0 ? html`<p class="eyebrow">Initialize owner</p><h2>创建管理员</h2><p class="auth-subtitle">设置本地控制台的唯一 owner 账号。</p><form class="auth-form" onSubmit=${submit}><${TextInput} label="管理员账号" placeholder="例如 owner" value=${username} onInput=${setUsername} autoComplete="username" maxLength="128" required=${true} /><${TextInput} label="密码" placeholder="至少 8 个字符" type="password" value=${password} onInput=${setPassword} minLength="8" maxLength="128" required=${true} /><${TextInput} label="确认密码" placeholder="再次输入密码" type="password" value=${confirm} onInput=${setConfirm} minLength="8" maxLength="128" required=${true} /><button class="button button-primary button-lg button-full" type="submit" disabled=${busy}>${busy ? '创建中…' : '创建 owner 账号'} ${icon('arrow', 17)}</button></form>${message ? html`<div class="form-message error">${message}</div>` : null}<div class="auth-note">${icon('warning', 15)}恢复码只显示一次，请离线保存。</div>` : html`<p class="eyebrow">Owner ready</p><h2>保存恢复码</h2><p class="auth-subtitle">账号已经创建。请在继续登录前，把以下恢复码保存到安全位置。</p><div class="recovery-codes">${codes.map((code) => html`<code>${code}</code>`)}</div><div class="code-actions"><button class="button button-secondary button-full" type="button" onClick=${copyCodes}>${icon('copy', 16)}${copied ? '已复制' : '复制全部恢复码'}</button><button class="button button-primary button-full" type="button" onClick=${() => onSetup('continue')}>前往登录 ${icon('arrow', 16)}</button></div><div class="notice notice-warning">恢复码只会在本次初始化响应中返回。不要把它提交到仓库或聊天记录。</div>`}</div><p class="auth-footer">Synthetic-only telemetry · no real model or URL access</p></main></div>`
}

function AppShell({ route, onNavigate, onLogout, username, lastUpdated, children }) {
  const [mobileOpen, setMobileOpen] = useState(false); const current = NAV_ITEMS.some((item) => item.id === route) ? route : 'dashboard'
  const nav = html`<nav class="sidebar-nav"><p class="nav-heading">Workspace</p>${NAV_ITEMS.map((item) => html`<button class=${cn('nav-item', current === item.id && 'is-active')} type="button" onClick=${() => onNavigate(item.id)}>${icon(item.icon, 18)}<span><b>${item.label}</b><small>${item.caption}</small></span>${current === item.id ? html`<i class="nav-active-line"></i>` : null}</button>`)}</nav>`
  return html`<div class="app-shell"><aside class=${cn('sidebar', mobileOpen && 'is-open')}><div class="sidebar-brand"><span class="brand-mark">A</span><div><strong>AegisLure</strong><small>Control plane</small></div><button class="sidebar-close icon-button" type="button" onClick=${() => setMobileOpen(false)} aria-label="关闭菜单">${icon('close', 18)}</button></div>${nav}<div class="sidebar-boundary"><span class="boundary-icon">${icon('shield', 16)}</span><div><b>安全边界</b><p>仅合成遥测<br />不执行真实推理</p></div></div><div class="sidebar-footer"><span class="node-dot"></span><div><b>Standalone node</b><small>Local sensor online</small></div></div></aside>${mobileOpen ? html`<div class="sidebar-scrim" onClick=${() => setMobileOpen(false)}></div>` : null}<main class="app-main"><header class="topbar"><div class="topbar-left"><button class="mobile-menu icon-button" type="button" onClick=${() => setMobileOpen(true)} aria-label="打开菜单">${icon('menu', 20)}</button><div class="breadcrumb"><span>AegisLure</span><i>/</i><b>${NAV_ITEMS.find((item) => item.id === current)?.label || '总览'}</b></div></div><div class="topbar-right"><span class="online-indicator"><i></i>系统在线</span>${lastUpdated ? html`<span class="last-updated">更新于 ${formatTime(lastUpdated)}</span>` : null}<button class="topbar-icon icon-button" type="button" onClick=${() => onNavigate('settings')} aria-label="设置">${icon('user', 18)}</button><div class="user-chip"><span>${String(username || 'owner').slice(0, 1).toUpperCase()}</span><b>${username || 'owner'}</b></div><button class="topbar-icon icon-button" type="button" onClick=${onLogout} aria-label="退出登录">${icon('logout', 18)}</button></div></header><div class="content-wrap">${children}</div></main></div>`
}

function LegacyDashboardPage({ dashboard, instances, onNavigate, onRefresh, onOpenEvent }) {
  if (!dashboard) return html`<${LoadingState} label="加载控制台数据…" />`
  const counts = dashboard.counts || {}; const activity = dashboard.activity || []; const recent = dashboard.recent_events || []; const running = (instances || []).filter((item) => item.state === 'running').length
  return html`<div class="page-stack"><${PageHeader} eyebrow="Live overview / ${dashboard.service || 'AegisLure'}" title="观测总览" description="追踪蜜罐流量、合成调用和每一条风险信号。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新数据<//>`} /><section class="metrics-grid"><${MetricCard} label="观测事件" value=${formatNumber(counts.events)} detail="append-only 事件流" icon="activity" tone="cyan" /><${MetricCard} label="唯一 IP" value=${formatNumber(counts.unique_ips)} detail="聚合后的来源指标" icon="shield" tone="blue" /><${MetricCard} label="高风险指标" value=${formatNumber(counts.high_risk)} detail="风险分 ≥ 60" icon="warning" tone="pink" /><${MetricCard} label="虚拟调用" value=${formatNumber(counts.invocations)} detail="不会执行真实模型" icon="spark" tone="violet" /><${MetricCard} label="运行实例" value=${`${running}/${(instances || []).length || 0}`} detail="可从实例页控制" icon="server" tone="amber" /></section><div class="dashboard-grid"><${Panel} className="span-7" eyebrow="Traffic pulse" title="近 24 小时活动" action=${html`<span class="panel-meta">每 2 小时</span>`}><${ActivityChart} items=${activity} /><div class="chart-footer"><span><i class="legend-dot dot-cyan"></i>事件量</span><span>接受 ${formatNumber(counts.accepted)} · 拒绝 ${formatNumber(counts.rejected)}</span></div><//><${Panel} className="span-5" eyebrow="Risk posture" title="IP 风险分布"><${RiskDonut} distribution=${dashboard.risk_distribution} /><div class="panel-footnote">风险分只表示观测证据，不等同于真实身份。</div><//><${Panel} className="span-7" eyebrow="Latest evidence" title="最近观测" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('observations')}>查看全部 ${icon('arrow', 14)}</button>`} flush=${true}>${recent.length ? html`<div class="event-feed">${recent.map((event) => html`<button class="event-feed-row" type="button" onClick=${() => onOpenEvent(event)}><span class="feed-marker"></span><span class="feed-main"><b>${event.route_template || 'unknown.route'}</b><small>${profileLabel(event.product)} · ${event.source_ip || 'unknown'} · ${formatTime(event.observed_at)}</small></span><${RiskBadge} score=${event.score} /><${Badge} tone=${event.status >= 400 ? 'danger' : 'success'}>${event.status || '—'}<//></button>`)}</div>` : html`<${EmptyState} title="还没有观测" description="访问任一公开蜜罐端点后，事件会出现在这里。" />`}<//><${Panel} className="span-5" eyebrow="Honeypot fleet" title="实例状态" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('instances')}>管理实例 ${icon('arrow', 14)}</button>`}>${instances?.length ? html`<div class="fleet-list">${instances.slice(0, 5).map((instance) => html`<div class="fleet-row"><span class="fleet-mark">${profileLabel(instance.product).slice(0, 1)}</span><div><b>${profileLabel(instance.product)}</b><small>${instance.port ? `:${instance.port}` : '未配置端口'} · ${instance.scenario || 'default'}</small></div><${StatusBadge} state=${instance.state} /></div>`)}</div>` : html`<${EmptyState} title="实例数据不可用" />`}<//></div></div>`
}

function DashboardPage({ dashboard, instances, onNavigate, onRefresh, onOpenEvent }) {
  if (!dashboard) return html`<${LoadingState} label="加载控制台数据…" />`
  const counts = dashboard.counts || {}; const summary = dashboard.risk_summary || {}; const recent = dashboard.recent_events || []; const running = (instances || []).filter((item) => item.state === 'running').length
  const riskEvents = summary.event_count ?? counts.risk_events ?? 0; const riskRate = summary.event_rate ?? counts.risk_rate ?? 0
  return html`<div class="page-stack"><${PageHeader} eyebrow="Live overview / ${dashboard.service || 'AegisLure'}" title="观测总览" description="追踪蜜罐流量、风险触发与每一条可回溯的动作证据。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新数据<//>`} /><section class="metrics-grid"><${MetricCard} label="观测事件" value=${formatNumber(counts.events)} detail="append-only 事件流" icon="activity" tone="cyan" /><${MetricCard} label="风险触发" value=${formatNumber(riskEvents)} detail=${`中/高风险 · ${riskRate}%`} icon="warning" tone="pink" /><${MetricCard} label="唯一 IP" value=${formatNumber(counts.unique_ips)} detail="聚合后的来源指标" icon="shield" tone="blue" /><${MetricCard} label="高风险指标" value=${formatNumber(counts.high_risk)} detail="风险分 ≥ 60" icon="warning" tone="violet" /><${MetricCard} label="虚拟调用" value=${formatNumber(counts.invocations)} detail="不会执行真实模型" icon="spark" tone="amber" /><${MetricCard} label="运行实例" value=${`${running}/${(instances || []).length || 0}`} detail="可从实例页控制" icon="server" tone="cyan" /></section><div class="dashboard-hero-grid"><${Panel} className="dashboard-trend-panel" eyebrow="Risk pulse" title="风险触发趋势" action=${html`<span class="panel-meta">实时相对窗口</span>`}><${RiskActivityChart} series=${dashboard.risk_activity || {}} /><//><${Panel} className="dashboard-country-panel" eyebrow="Source intelligence" title="风险 IP 来源区域" action=${html`<${Badge} tone="blue">离线聚合<//>`}><${CountryDistribution} items=${dashboard.source_countries || []} /><//></div><div class="dashboard-analytics-grid"><${Panel} eyebrow="Surface mix" title="蜜罐触发占比"><${HoneypotDistribution} items=${dashboard.honeypot_distribution || []} /><//><${Panel} eyebrow="Risk mix" title="触发风险占比"><${DistributionDonut} items=${dashboard.risk_trigger_distribution || []} centerLabel="风险事件" /><div class="panel-footnote">按事件风险分分档；中风险起算阈值为 ≥ ${dashboard.risk_threshold || 30}。</div><//><${Panel} eyebrow="Indicator posture" title="IP 风险分布"><${RiskDonut} distribution=${dashboard.risk_distribution || {}} /><div class="panel-footnote">IP 维度聚合；风险分只表示观测证据，不等同于真实身份。</div><//></div><div class="dashboard-grid"><${Panel} className="span-7" eyebrow="Latest evidence" title="最近观测" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('observations')}>查看全部 ${icon('arrow', 14)}</button>`} flush=${true}>${recent.length ? html`<div class="event-feed">${recent.map((event) => html`<button class="event-feed-row" key=${event.event_id} type="button" onClick=${() => onOpenEvent(event)}><span class="feed-marker"></span><span class="feed-main"><b>${event.route_template || 'unknown.route'}</b><small>${profileLabel(event.product)} · ${event.source_ip || 'unknown'} · ${formatTime(event.observed_at)}</small></span><${RiskBadge} score=${event.score} /><${Badge} tone=${event.status >= 400 ? 'danger' : 'success'}>${event.status || '—'}<//></button>`)}</div>` : html`<${EmptyState} title="还没有观测" description="访问任一公开蜜罐端点后，事件会出现在这里。" />`}<//><${Panel} className="span-5" eyebrow="Honeypot fleet" title="实例状态" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('instances')}>管理实例 ${icon('arrow', 14)}</button>`}>${instances?.length ? html`<div class="fleet-list">${instances.slice(0, 5).map((instance) => html`<div class="fleet-row" key=${instance.product}><span class="fleet-mark">${profileLabel(instance.product).slice(0, 1)}</span><div><b>${profileLabel(instance.product)}</b><small>${instance.port ? `:${instance.port}` : '未配置端口'} · ${instance.scenario || 'default'}</small></div><${StatusBadge} state=${instance.state} /></div>`)}</div>` : html`<${EmptyState} title="实例数据不可用" />`}<//></div></div>`
}

function ObservationsPage({ events, onRefresh, onOpenEvent }) {
  const [product, setProduct] = useState(''); const [query, setQuery] = useState(''); const [minScore, setMinScore] = useState('')
  const filtered = useMemo(() => (events || []).filter((event) => { const matchesProduct = !product || event.product === product; const text = `${event.source_ip || ''} ${event.route_template || ''} ${event.event_type || ''} ${event.intent_class || ''}`.toLowerCase(); const matchesQuery = !query || text.includes(query.toLowerCase()); const matchesScore = !minScore || Number(event.score || 0) >= Number(minScore); return matchesProduct && matchesQuery && matchesScore }), [events, product, query, minScore])
  const columns = [{ label: '观测时间', render: (row) => html`<span class="table-time">${formatTime(row.observed_at)}</span>` }, { label: '来源 IP', render: (row) => html`<code class="mono">${row.source_ip || '—'}</code>` }, { label: '产品', render: (row) => html`<${Badge} tone="neutral">${profileLabel(row.product)}<//>` }, { label: '路由', render: (row) => html`<span class="route-cell">${row.route_template || '—'}</span>` }, { label: '状态', render: (row) => html`<${Badge} tone=${row.status >= 400 ? 'danger' : 'success'}>${row.status || '—'}<//>` }, { label: '调用等级', render: (row) => html`<span class="level-text">${levelLabel(row.invocation_level)}</span>` }, { label: '风险', className: 'align-right', render: (row) => html`<${RiskBadge} score=${row.score} />` }]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Evidence stream" title="观测记录" description="检索每一条请求的脱敏遥测、调用阶段与风险证据。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新记录<//>`} /><${Panel} className="table-panel" title="事件流" action=${html`<span class="panel-meta">显示 ${formatNumber(filtered.length)} / ${formatNumber(events?.length || 0)}</span>`}><${FilterBar} onReset=${() => { setProduct(''); setQuery(''); setMinScore('') }}><label class="search-field">${icon('search', 17)}<input value=${query} onInput=${(event) => setQuery(event.target.value)} placeholder="搜索 IP、路由或事件类型" /></label><${Select} value=${product} onChange=${setProduct} options=${[{ value: '', label: '全部产品' }, ...Object.entries(PROFILE_LABELS).map(([value, label]) => ({ value, label }))]} /><label class="score-filter"><span>最低风险</span><input type="number" min="0" max="100" value=${minScore} onInput=${(event) => setMinScore(event.target.value)} placeholder="0" /></label></${FilterBar}><${DataTable} columns=${columns} rows=${filtered} onRowClick=${onOpenEvent} emptyTitle="没有匹配的观测" emptyDescription="尝试清除筛选条件，或等待新的蜜罐请求。" /><//><p class="page-note">事件正文仅保留受限预览并自动脱敏；底层事件流为 append-only。</p></div>`
}

function InvocationsPage({ invocations, onRefresh, onOpenEvent }) {
  const [level, setLevel] = useState(''); const [auth, setAuth] = useState(''); const [execution, setExecution] = useState('')
  const filtered = useMemo(() => (invocations || []).filter((item) => (!level || item.invocation_level === level) && (!auth || item.auth_outcome === auth) && (!execution || item.execution_outcome === execution)), [invocations, level, auth, execution])
  const columns = [{ label: '时间', render: (row) => html`<span class="table-time">${formatTime(row.observed_at)}</span>` }, { label: '调用 ID', render: (row) => html`<code class="mono">${shortValue(row.invocation_id, 22)}</code>` }, { label: '模型', render: (row) => html`<span class="route-cell">${row.model_id || '未解析'}</span>` }, { label: '产品', render: (row) => html`<${Badge} tone="neutral">${profileLabel(row.product)}<//>` }, { label: '鉴权', render: (row) => html`<span class="outcome-text">${row.auth_outcome || '—'}</span>` }, { label: '执行', render: (row) => html`<span class=${cn('outcome-text', row.execution_outcome === 'rejected_before_dispatch' && 'text-danger')}>${row.execution_outcome || '—'}</span>` }, { label: '阶段', render: (row) => html`<${Badge} tone=${row.invocation_level?.startsWith('L4') ? 'success' : row.invocation_level?.startsWith('L1') ? 'danger' : 'blue'}>${levelLabel(row.invocation_level)}<//>` }, { label: '风险', className: 'align-right', render: (row) => html`<${RiskBadge} score=${row.score} />` }]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Synthetic execution trail" title="调用分析" description="查看模型调用尝试、鉴权结果与合成执行阶段。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新调用<//>`} /><div class="callout callout-blue">${icon('spark', 18)}<div><b>合成执行边界</b><p>所有“已接受”调用只返回确定性的兼容响应，不会加载模型、执行 prompt 工具或连接供应商。</p></div></div><${Panel} className="table-panel" title="调用事件" action=${html`<span class="panel-meta">${formatNumber(filtered.length)} 条结果</span>`}><${FilterBar} onReset=${() => { setLevel(''); setAuth(''); setExecution('') }}><${Select} value=${level} onChange=${setLevel} options=${[{ value: '', label: '全部阶段' }, ...Object.entries(LEVEL_LABELS).map(([value, label]) => ({ value, label }))]} /><${Select} value=${auth} onChange=${setAuth} options=${[{ value: '', label: '全部鉴权' }, { value: 'valid_honey_key', label: '有效 honey key' }, { value: 'bypass_simulated', label: '模拟绕过' }, { value: 'missing', label: '缺失' }, { value: 'invalid', label: '无效' }]} /><${Select} value=${execution} onChange=${setExecution} options=${[{ value: '', label: '全部执行结果' }, { value: 'synthetic_accepted', label: '合成已接受' }, { value: 'synthetic_stream_completed', label: '合成流完成' }, { value: 'rejected_before_dispatch', label: '派发前拒绝' }]} /></${FilterBar}><${DataTable} columns=${columns} rows=${filtered} onRowClick=${onOpenEvent} emptyTitle="还没有调用事件" emptyDescription="蜜罐记录到调用请求后，分析结果会显示在这里。" /><//></div>`
}

function ChainsPage({ chains, onRefresh, onOpenEvent }) {
  const [expanded, setExpanded] = useState(null)
  return html`<div class="page-stack"><${PageHeader} eyebrow="Session intelligence" title="交互链路" description="按最新观测时间展示链路；同一会话中的发现、调用和效果验证会按后端配置聚合。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新链路<//>`} />${chains?.length ? html`<div class="chain-grid">${chains.map((chain) => html`<article class="chain-card"><header class="chain-card-header"><div class="chain-id"><span class="chain-mark">${icon('route', 17)}</span><div><b>${shortValue(chain.id, 24)}</b><small>${profileLabel(chain.product)} · ${shortValue(chain.session_id || chain.aggregation_key, 24)}</small></div></div><${RiskBadge} score=${chain.score} /></header><div class="chain-meta"><span>${icon('clock', 14)}${chain.event_count || 0} 个事件</span><span>${icon('clock', 14)}最新 ${formatTime(chain.latest_observed_at, true)}</span><span>${icon('spark', 14)}${levelLabel(chain.invocation_level)}</span><${Badge} tone="blue">${chain.aggregation_mode || 'session'}<//><${Badge} tone="blue">${chain.stage || 'discovery'}<//></div>${chain.matched_rule_ids?.length ? html`<div class="chip-list chain-rules">${chain.matched_rule_ids.map((rule) => html`<${Badge} tone="warning">${rule}<//>`)}</div>` : null}<div class="chain-line">${(chain.events || []).slice(-5).map((event, index, visible) => html`<button type="button" class="chain-event" onClick=${() => onOpenEvent(event)}><i class=${cn('chain-dot', event.score >= 60 && 'is-risk')}></i><span><b>${event.event_type || event.route_template || 'event'}</b><small>${formatTime(event.observed_at)} · ${event.status || '—'} · ${event.route_template || 'unknown.route'}</small></span>${index === visible.length - 1 ? html`<em>latest</em>` : null}</button>`)}</div><button class="chain-expand" type="button" onClick=${() => setExpanded(expanded === chain.id ? null : chain.id)}>${expanded === chain.id ? '收起详情' : '查看完整链路'} ${icon('chevron', 14)}</button>${expanded === chain.id ? html`<div class="chain-expanded"><pre class="json-view">${JSON.stringify(chain, null, 2)}</pre></div>` : null}</article>`)}</div>` : html`<${Panel}><${EmptyState} icon="route" title="还没有交互链路" description="同一来源建立会话后，链路会自动聚合。" /><//>`}</div>`
}

function LegacyIndicatorsPage({ indicators, onRefresh }) {
  const [minScore, setMinScore] = useState(0); const filtered = (indicators || []).filter((item) => Number(item.score || 0) >= Number(minScore || 0))
  const exportIndicators = (format) => { const link = document.createElement('a'); link.href = `${apiPath('indicators')}?format=${format}&min_score=${encodeURIComponent(minScore)}`; link.download = `aegislure-indicators.${format}`; document.body.appendChild(link); link.click(); link.remove() }
  const columns = [{ label: '来源 IP', render: (row) => html`<code class="mono ip-cell">${row.ip}</code>` }, { label: '风险分', render: (row) => html`<${RiskBadge} score=${row.score} />` }, { label: '置信度', render: (row) => html`<span class="confidence">${row.confidence || 'low'}</span>` }, { label: '证据', render: (row) => html`<span>${formatNumber(row.evidence_count)} 次 · ${formatNumber(row.sensor_count)} 个传感器</span>` }, { label: '产品', render: (row) => html`<div class="chip-list compact">${(row.products || []).map((product) => html`<${Badge} tone="neutral">${profileLabel(product)}<//>`)}</div>` }, { label: '建议动作', render: (row) => html`<span class=${cn('action-label', row.score >= 60 && 'action-risk')}>${row.recommended_action || 'observe'}</span>` }, { label: '最近出现', className: 'align-right', render: (row) => html`<span class="table-time">${formatTime(row.last_seen)}</span>` }]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Risk intelligence" title="IP 情报" description="聚合来源 IP 的风险证据、命中产品和建议处置动作。" actions=${html`<div class="button-group"><${Button} icon="download" size="sm" onClick=${() => exportIndicators('csv')}>导出 CSV<//><${Button} icon="refresh" size="sm" onClick=${onRefresh}>刷新<//></div>`} /><${Panel} className="table-panel" title="指标列表" action=${html`<span class="panel-meta">${formatNumber(filtered.length)} 个指标</span>`}><div class="indicator-tools"><label class="range-field"><span>最低风险分</span><input type="range" min="0" max="100" step="10" value=${minScore} onInput=${(event) => setMinScore(event.target.value)} /><b>${minScore}</b></label><div class="button-group"><button class="outline-button" type="button" onClick=${() => exportIndicators('plain')}>导出纯文本</button><button class="outline-button" type="button" onClick=${() => exportIndicators('csv')}>下载 CSV</button></div></div><${DataTable} columns=${columns} rows=${filtered} emptyTitle="还没有 IP 指标" emptyDescription="当观测到公开蜜罐端点请求后，风险聚合会出现在这里。" /><//><p class="page-note">推荐动作仅供人工审核参考；当前 Lite 存储不会自动封禁来源。</p></div>`
}

function IndicatorsPage({ indicators, onRefresh, onOpenIndicator }) {
  const [minScore, setMinScore] = useState(0); const filtered = (indicators || []).filter((item) => Number(item.score || 0) >= Number(minScore || 0))
  const exportIndicators = (format) => { const link = document.createElement('a'); link.href = `${apiPath('indicators')}?format=${format}&min_score=${encodeURIComponent(minScore)}`; link.download = `aegislure-indicators.${format}`; document.body.appendChild(link); link.click(); link.remove() }
  const columns = [{ label: '来源 IP', render: (row) => html`<code class="mono ip-cell">${row.ip}</code>` }, { label: '风险分', render: (row) => html`<${RiskBadge} score=${row.score} />` }, { label: '置信度', render: (row) => html`<span class="confidence">${row.confidence || 'low'}</span>` }, { label: '证据', render: (row) => html`<span>${formatNumber(row.evidence_count)} 次 · ${formatNumber(row.sensor_count)} 个传感器</span>` }, { label: '产品', render: (row) => html`<div class="chip-list compact">${(row.products || []).map((product) => html`<${Badge} tone="neutral" key=${product}>${profileLabel(product)}<//>`)}</div>` }, { label: '建议动作', render: (row) => html`<span class=${cn('action-label', row.score >= 60 && 'action-risk')}>${row.recommended_action || 'observe'}</span>` }, { label: '最近出现', className: 'align-right', render: (row) => html`<span class="table-time">${formatTime(row.last_seen)}</span>` }]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Risk intelligence" title="IP 情报" description="聚合来源 IP 的风险证据、命中产品和建议处置动作；点击任意指标查看该 IP 的全部动作。" actions=${html`<div class="button-group"><${Button} icon="download" size="sm" onClick=${() => exportIndicators('csv')}>导出 CSV<//><${Button} icon="refresh" size="sm" onClick=${onRefresh}>刷新<//></div>`} /><${Panel} className="table-panel" title="指标列表" action=${html`<span class="panel-meta">${formatNumber(filtered.length)} 个指标 · 点击查看动作</span>`}><div class="indicator-tools"><label class="range-field"><span>最低风险分</span><input type="range" min="0" max="100" step="10" value=${minScore} onInput=${(event) => setMinScore(event.target.value)} /><b>${minScore}</b></label><div class="button-group"><button class="outline-button" type="button" onClick=${() => exportIndicators('plain')}>导出纯文本</button><button class="outline-button" type="button" onClick=${() => exportIndicators('csv')}>下载 CSV</button></div></div><${DataTable} columns=${columns} rows=${filtered} onRowClick=${onOpenIndicator} emptyTitle="还没有 IP 指标" emptyDescription="当观测到公开蜜罐端点请求后，风险聚合会出现在这里。" /><//><p class="page-note">推荐动作仅供人工审核参考；当前 Lite 存储不会自动封禁来源。点击列表行可查看该 IP 的完整脱敏动作时间线。</p></div>`
}

function InstanceCard({ instance, busy, onAction }) {
  const running = instance.state === 'running'
  return html`<article class=${cn('instance-card', running && 'is-running')}><div class="instance-card-head"><div class="instance-logo">${profileLabel(instance.product).slice(0, 1)}</div><div class="instance-title"><div><h3>${profileLabel(instance.product)}</h3><${StatusBadge} state=${instance.state} /></div><p>${instance.profile_id || 'profile'} · ${instance.version || 'version unknown'}</p></div><${Toggle} checked=${running} label=${`${profileLabel(instance.product)} 开关`} onChange=${(next) => onAction(instance, next ? 'start' : 'stop')} /></div><div class="instance-details"><div><span>监听端口</span><b>${instance.port || '—'}</b></div><div><span>场景</span><b>${instance.scenario || 'default'}</b></div><div><span>端点</span><code>${instance.endpoint || '—'}</code></div></div><div class="instance-card-foot"><span>${instance.synthetic_only ? html`<span class="instance-boundary"><i class="green-dot"></i>安全合成边界</span>` : '—'}</span><div class="button-group"><${Button} size="sm" variant="ghost" icon="refresh" onClick=${() => onAction(instance, 'restart')} disabled=${busy}>重启<//>${running ? html`<${Button} size="sm" variant="danger-ghost" icon="pause" onClick=${() => onAction(instance, 'stop')} disabled=${busy}>停止<//>` : html`<${Button} size="sm" variant="primary-soft" icon="play" onClick=${() => onAction(instance, 'start')} disabled=${busy}>启动<//>`}</div></div></article>`
}

function InstancesPage({ instances, onRefresh, onAction, busy }) {
  const running = (instances || []).filter((item) => item.state === 'running').length
  return html`<div class="page-stack"><${PageHeader} eyebrow="Honeypot fleet" title="蜜罐实例" description="按协议启停公开端点，所有实例都保持在安全的合成响应边界内。" actions=${html`<div class="button-group"><${Button} variant="secondary" icon="play" onClick=${() => onAction({ product: '__all__' }, 'start-all')} disabled=${busy}>启动全部<//><${Button} icon="refresh" onClick=${onRefresh}>刷新状态<//></div>`} /><div class="fleet-summary"><div><span class="summary-icon">${icon('server', 18)}</span><div><b>${running} / ${(instances || []).length}</b><small>当前运行实例</small></div></div><div><span class="summary-icon summary-blue">${icon('activity', 18)}</span><div><b>HTTP</b><small>公开协议表面</small></div></div><div><span class="summary-icon summary-pink">${icon('shield', 18)}</span><div><b>隔离</b><small>无真实上游出站</small></div></div></div><div class="instance-grid">${instances?.map((instance) => html`<${InstanceCard} instance=${instance} busy=${busy} onAction=${onAction} />`)}</div><p class="page-note">停止实例会关闭对应公开监听器并更新运行配置；管理端保持在线。</p></div>`
}

function conditionValue(value) {
  return typeof value === 'string' ? value : JSON.stringify(value)
}

function describeRuleCondition(condition) {
  if (!condition || typeof condition !== 'object') return []
  if (Array.isArray(condition.all)) return condition.all.flatMap(describeRuleCondition)
  if (Array.isArray(condition.any)) return condition.any.flatMap(describeRuleCondition)
  if (condition.not) return describeRuleCondition(condition.not).map((item) => `not (${item})`)
  if (condition.field && condition.op) return [`${condition.field} ${condition.op} ${conditionValue(condition.value)}`]
  return []
}

function ruleMatchSummary(rule) {
  const conditions = describeRuleCondition(rule.where)
  if (rule.url_classes?.length) conditions.push(`url_class in ${JSON.stringify(rule.url_classes)}`)
  if (rule.steps?.length) conditions.push(`${rule.sequence_mode || 'ordered'} steps: ${rule.steps.join(' → ')}`)
  return conditions.length ? conditions.join(' · ') : '事件类型/风险分匹配'
}

function strategyPackSummary(strategy) {
  return Object.entries(strategy?.packs || {}).map(([kind, pack]) => `${kind}: ${pack.revision || pack.id}${pack.bound ? ' · bound' : ''}`)
}

function ruleFormState(rule) {
  return {
    id: rule?.id || '',
    type: rule?.type || 'atomic',
    reason_code: rule?.reason_code || '',
    score: String(rule?.score ?? 0),
    confidence: rule?.confidence || 'medium',
    within: rule?.within || '',
    sequence_mode: rule?.sequence_mode || 'ordered',
    steps: (rule?.steps || []).join('\n'),
    url_classes: (rule?.url_classes || []).join('\n'),
    where: rule?.where ? JSON.stringify(rule.where, null, 2) : '',
  }
}

function ruleLines(value) {
  return String(value || '').split(/\r?\n/).map((item) => item.trim()).filter(Boolean)
}

function parseRuleForm(form) {
  const id = form.id.trim()
  const reasonCode = form.reason_code.trim()
  const score = Number(form.score)
  if (!id) throw new Error('规则 ID 不能为空。')
  if (!reasonCode) throw new Error('命中原因不能为空。')
  if (!Number.isInteger(score) || score < 0 || score > 100) throw new Error('风险分必须是 0 到 100 的整数。')
  const result = { id, type: form.type, reason_code: reasonCode, score, confidence: form.confidence }
  if (form.within.trim()) result.within = form.within.trim()
  if (form.type === 'sequence') {
    result.sequence_mode = form.sequence_mode || 'ordered'
    result.steps = ruleLines(form.steps)
  }
  const urlClasses = ruleLines(form.url_classes)
  if (urlClasses.length) result.url_classes = urlClasses
  if (form.where.trim()) {
    try { result.where = JSON.parse(form.where) } catch (_) { throw new Error('字段 / 正则配置必须是有效 JSON。') }
  }
  return result
}

function RuleEditorModal({ rule, editing, busy, onClose, onSave }) {
  const [form, setForm] = useState(() => ruleFormState(rule))
  const [message, setMessage] = useState('')
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }))
  const submit = async (event) => {
    event.preventDefault(); setMessage('')
    try { await onSave(parseRuleForm(form)) } catch (error) { setMessage(error.message || '规则保存失败。') }
  }
  return html`<${Modal} title=${editing ? '编辑规则' : '新增规则'} eyebrow="Detector rule CRUD" onClose=${onClose} wide=${true}><form class="stack-form" onSubmit=${submit}><div class="rule-form-grid"><${TextInput} label="规则 ID" placeholder="例如 CUSTOM_ROUTE_V1" value=${form.id} onInput=${(value) => update('id', value)} maxLength="128" disabled=${editing} required=${true} /><label class="select-field"><span>规则类型</span><select value=${form.type} onChange=${(event) => update('type', event.target.value)}><option value="atomic">atomic · 单事件</option><option value="sequence">sequence · 事件序列</option><option value="threshold">threshold · 阈值</option><option value="credential_reuse">credential_reuse · 凭据复用</option><option value="campaign">campaign · 活动关联</option></select></label><${TextInput} label="命中原因" placeholder="例如 suspicious_route_probe" value=${form.reason_code} onInput=${(value) => update('reason_code', value)} maxLength="128" required=${true} /><${TextInput} label="风险分" type="number" min="0" max="100" value=${form.score} onInput=${(value) => update('score', value)} required=${true} /><label class="select-field"><span>置信度</span><select value=${form.confidence} onChange=${(event) => update('confidence', event.target.value)}><option value="low">low · 低</option><option value="medium">medium · 中</option><option value="high">high · 高</option></select></label><${TextInput} label="时间窗口（可选）" placeholder="例如 10m 或 1h" value=${form.within} onInput=${(value) => update('within', value)} maxLength="32" /></div><div class="rule-form-grid"><label class="text-field rule-form-wide"><span>事件步骤（每行一个，仅 sequence 使用）</span><textarea rows="5" value=${form.steps} onInput=${(event) => update('steps', event.target.value)} placeholder="newapi.user.login.success\nllm.invoke.accepted"></textarea></label><label class="text-field rule-form-wide"><span>URL 分类（每行一个，可选）</span><textarea rows="5" value=${form.url_classes} onInput=${(event) => update('url_classes', event.target.value)} placeholder="loopback\nprivate"></textarea></label>${form.type === 'sequence' ? html`<label class="select-field"><span>序列匹配</span><select value=${form.sequence_mode} onChange=${(event) => update('sequence_mode', event.target.value)}><option value="ordered">ordered · 有序</option><option value="unordered">unordered · 无序</option></select></label>` : null}</div><label class="text-field"><span>字段 / 正则配置（JSON，可选）</span><textarea rows="8" value=${form.where} onInput=${(event) => update('where', event.target.value)} placeholder='{"field":"route_template","op":"eq","value":"ollama.home"}'></textarea></label><div class="button-group"><button class="button button-primary" type="submit" disabled=${busy}>${busy ? '保存中…' : editing ? '保存修改' : '新增规则'}</button><button class="button button-secondary" type="button" onClick=${onClose} disabled=${busy}>取消</button></div>${message ? html`<div class="form-message error">${message}</div>` : null}</form><p class="modal-copy">规则会先保存为 Draft revision；完成验证并点击“启用规则”后，才会替换当前运行中的规则。</p><//>`
}

function PacksPage({ packs, policies, onRefresh }) {
  const revisions = packs ? [['Fingerprint pack', packs.fingerprint_revision, '来源指纹与协议特征'], ['Model catalog', packs.model_catalog_revision, '安全模型目录与别名'], ['Scenario pack', packs.scenario_revision, '场景与响应契约'], ['Detector rules', packs.detector_revision, '风险检测规则']] : []
  const aggregation = packs?.chain_aggregation || { mode: 'session', window_seconds: 1800, max_events: 200 }
  const [mode, setMode] = useState(aggregation.mode || 'session')
  const [windowSeconds, setWindowSeconds] = useState(aggregation.window_seconds || 1800)
  const [maxEvents, setMaxEvents] = useState(aggregation.max_events || 200)
  const [selectedProduct, setSelectedProduct] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [editor, setEditor] = useState(null)
  const [ruleState, setRuleState] = useState(null)
  const [rulesLoading, setRulesLoading] = useState(false)
  const [ruleBusy, setRuleBusy] = useState(false)
  const [ruleMessage, setRuleMessage] = useState('')
  const [ruleMessageError, setRuleMessageError] = useState(false)
  const [policyBusy, setPolicyBusy] = useState('')
  const [policyMessage, setPolicyMessage] = useState('')
  const [policyMessageError, setPolicyMessageError] = useState(false)
  const strategies = packs?.strategies || []
  const selected = strategies.find((item) => item.product === selectedProduct) || strategies[0]
  const selectedPackID = selected?.rule_pack?.id || ''
  useEffect(() => {
    setMode(aggregation.mode || 'session')
    setWindowSeconds(aggregation.window_seconds || 1800)
    setMaxEvents(aggregation.max_events || 200)
  }, [aggregation.mode, aggregation.window_seconds, aggregation.max_events])
  useEffect(() => {
    if (selectedProduct === '' || !strategies.some((item) => item.product === selectedProduct)) setSelectedProduct(strategies[0]?.product || '')
  }, [selectedProduct, strategies])
  useEffect(() => {
    let active = true
    if (!selectedPackID) { setRuleState(null); setRulesLoading(false); return () => {} }
    setRulesLoading(true); setRuleMessage(''); setRuleMessageError(false)
    request(`rule-packs/${encodeURIComponent(selectedPackID)}/rules`).then((result) => {
      if (active) setRuleState(result)
    }).catch((error) => {
      if (active) { setRuleState(null); setRuleMessage(error.message || '规则读取失败。'); setRuleMessageError(true) }
    }).finally(() => { if (active) setRulesLoading(false) })
    return () => { active = false }
  }, [selectedPackID])
  const saveAggregation = async () => {
    setSaving(true); setMessage('')
    try {
      await request('chain-config', { method: 'PUT', body: JSON.stringify({ mode, window_seconds: Number(windowSeconds), max_events: Number(maxEvents) }) })
      setMessage('交互链路聚合配置已保存。'); await onRefresh()
    } catch (error) { setMessage(error.message || '配置保存失败。') } finally { setSaving(false) }
  }
  const refreshRules = async () => {
    if (!selectedPackID) return null
    const result = await request(`rule-packs/${encodeURIComponent(selectedPackID)}/rules`)
    setRuleState(result)
    return result
  }
  const saveRule = async (rule) => {
    if (!selectedPackID) throw new Error('当前蜜罐没有可编辑的规则包。')
    setRuleBusy(true); setRuleMessage(''); setRuleMessageError(false)
    try {
      const editing = editor?.mode === 'edit'
      const endpoint = `rule-packs/${encodeURIComponent(selectedPackID)}/rules${editing ? `/${encodeURIComponent(rule.id)}` : ''}`
      await request(endpoint, { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(rule) })
      await refreshRules(); setEditor(null); setRuleMessage(editing ? '规则已更新，当前为 Draft revision。' : '规则已新增，当前为 Draft revision。'); await onRefresh()
    } finally { setRuleBusy(false) }
  }
  const deleteRule = async (rule) => {
    if (!window.confirm(`确定删除规则“${rule.id}”吗？删除后会生成 Draft revision。`)) return
    setRuleBusy(true); setRuleMessage(''); setRuleMessageError(false)
    try {
      await request(`rule-packs/${encodeURIComponent(selectedPackID)}/rules/${encodeURIComponent(rule.id)}`, { method: 'DELETE' })
      await refreshRules(); await onRefresh(); setRuleMessage(`规则 ${rule.id} 已删除，当前为 Draft revision。`)
    } catch (error) { setRuleMessage(error.message || '规则删除失败。'); setRuleMessageError(true) } finally { setRuleBusy(false) }
  }
  const runRulePackAction = async (action) => {
    if (!selectedPackID) return
    setRuleBusy(true); setRuleMessage(''); setRuleMessageError(false)
    try {
      await request(`rule-packs/${encodeURIComponent(selectedPackID)}:${action}`, { method: 'POST' })
      await refreshRules(); await onRefresh(); setRuleMessage(action === 'validate' ? '规则包验证通过。' : '规则包已启用。')
    } catch (error) { setRuleMessage(error.message || `${action === 'validate' ? '规则验证' : '规则启用'}失败。`); setRuleMessageError(true) } finally { setRuleBusy(false) }
  }
  const togglePolicy = async (policy) => {
    setPolicyBusy(policy.provider); setPolicyMessage(''); setPolicyMessageError(false)
    try {
      await request(`identity-policies/${encodeURIComponent(policy.provider)}`, { method: 'PATCH', body: JSON.stringify({ enabled: !policy.enabled }) })
      setPolicyMessage(`${policy.provider} 注册页入口已${policy.enabled ? '关闭' : '开启'}。`)
      await onRefresh()
    } catch (error) {
      setPolicyMessage(error.message || '身份策略更新失败。'); setPolicyMessageError(true)
    } finally { setPolicyBusy('') }
  }
  const rules = ruleState?.pack_id === selectedPackID ? (ruleState.rules || []) : (selected?.rules || [])
  const ruleRevision = ruleState?.pack_id === selectedPackID ? ruleState.revision : selected?.rule_pack?.revision
  const ruleLifecycle = ruleState?.pack_id === selectedPackID ? ruleState.lifecycle : selected?.rule_pack?.lifecycle || 'Active'
  return html`<div class="page-stack"><${PageHeader} eyebrow="Configuration registry" title="规则与策略" description="查看每个蜜罐当前生效的策略、规则和请求匹配条件；规则支持新增、编辑、删除，修改会先进入 Draft revision。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新配置<//>`} /><div class="pack-grid">${revisions.map((revision) => html`<article class="pack-card"><div class="pack-icon">${icon('layers', 19)}</div><div><p>${revision[0]}</p><h3>${revision[1] || 'unknown'}</h3><small>${revision[2]}</small></div><${Badge} tone="success" dot=${true}>Active<//></article>`)}</div><${Panel} eyebrow="Interaction aggregation" title="交互链路聚合方式"><div class="config-form"><label class="select-field"><span>聚合键</span><select value=${mode} onChange=${(event) => setMode(event.target.value)}>${(packs?.allowed_chain_modes || ['session', 'source_ip', 'source_ip_product']).map((value) => html`<option value=${value}>${value === 'session' ? '同一会话' : value === 'source_ip' ? '同一来源 IP（跨会话）' : '同一来源 IP + 蜜罐'}</option>`)}</select></label><label class="config-field"><span>时间窗口（秒）</span><input type="number" min="60" max="86400" value=${windowSeconds} onInput=${(event) => setWindowSeconds(event.target.value)} /></label><label class="config-field"><span>最多事件数</span><input type="number" min="10" max="1000" value=${maxEvents} onInput=${(event) => setMaxEvents(event.target.value)} /></label><button class="button button-primary" type="button" onClick=${saveAggregation} disabled=${saving}>${saving ? '保存中…' : '保存聚合配置'}</button></div>${message ? html`<div class="form-message ${message.includes('失败') ? 'error' : 'success'}">${message}</div>` : null}<p class="panel-footnote">默认按同一会话聚合；窗口和数量上限均由后端校验，事件正文仍只保留受限脱敏预览。</p><//><${Panel} eyebrow="Honeypot strategy matrix" title="各蜜罐当前策略"><div class="strategy-grid">${strategies.map((strategy) => html`<article class=${cn('strategy-card', selected?.product === strategy.product && 'is-selected')}><div class="strategy-card-head"><div><${Badge} tone="blue">${profileLabel(strategy.product)}<//><h3>${strategy.scenario || 'default'}</h3><small>${strategy.profile_id || 'profile'} · ${strategy.version || 'version unknown'}</small></div><strong>${formatNumber(strategy.product === selected?.product && ruleState?.pack_id === selectedPackID ? rules.length : strategy.rule_count || 0)} 条规则</strong></div><div class="strategy-pack-list">${strategyPackSummary(strategy).map((item) => html`<code>${item}</code>`)}</div><button class="outline-button" type="button" onClick=${() => setSelectedProduct(strategy.product)}>编辑规则</button></article>`)}</div><//><${Panel} eyebrow="Detector rules" title=${selected ? `${profileLabel(selected.product)} · 请求匹配规则` : '请求匹配规则'} action=${strategies.length ? html`<div class="button-group"><label class="select-field inline-select"><span>蜜罐</span><select value=${selected?.product || ''} onChange=${(event) => setSelectedProduct(event.target.value)}>${strategies.map((strategy) => html`<option value=${strategy.product}>${profileLabel(strategy.product)}</option>`)}</select></label>${selectedPackID ? html`<${Button} variant="primary" size="sm" icon="plus" onClick=${() => { setRuleMessage(''); setRuleMessageError(false); setEditor({ mode: 'create', rule: null }) }} disabled=${ruleBusy}>新增规则<//>` : null}</div>` : null}>${selectedPackID ? html`<div class="rule-pack-toolbar"><span>规则包 <code>${selectedPackID}</code> · <code>${ruleRevision || 'unknown revision'}</code></span><${Badge} tone=${ruleLifecycle === 'Active' ? 'success' : 'warning'} dot=${true}>${ruleLifecycle || 'Unknown'}<//><small>修改后先验证，再启用；Draft 不会立即替换运行中的规则。</small></div>` : null}${ruleMessage ? html`<div class=${cn('form-message', ruleMessageError && 'error', !ruleMessageError && 'success')}>${ruleMessage}</div>` : null}${rulesLoading ? html`<${LoadingState} label="加载规则…" />` : rules.length ? html`<div class="rule-list">${rules.map((rule) => html`<article class="rule-card" key=${rule.id}><div class="rule-card-head"><div><code>${rule.id}</code><h3>${rule.reason_code}</h3></div><div class="rule-badges"><${Badge} tone="blue">${rule.type}<//><${Badge} tone=${rule.confidence === 'high' ? 'danger' : 'warning'}>${rule.score} 分<//></div></div><p class="rule-summary">${ruleMatchSummary(rule)}</p>${rule.within ? html`<small class="rule-window">窗口：${rule.within}</small>` : null}${rule.where ? html`<details class="rule-detail"><summary>查看字段 / 正则配置</summary><pre class="data-view">${JSON.stringify(rule.where, null, 2)}</pre></details>` : null}<div class="rule-card-actions"><button class="outline-button" type="button" onClick=${() => { setRuleMessage(''); setRuleMessageError(false); setEditor({ mode: 'edit', rule }) }} disabled=${ruleBusy}>编辑</button><button class="text-button rule-delete" type="button" onClick=${() => deleteRule(rule)} disabled=${ruleBusy}>删除</button></div></article>`)}</div>` : html`<${EmptyState} title="当前没有可展示的规则" description="该蜜罐没有解析到 detector pack。" />`}${selectedPackID && ruleLifecycle !== 'Active' ? html`<div class="rule-lifecycle-actions"><span>当前 revision 尚未生效</span><div class="button-group"><${Button} size="sm" variant="secondary" onClick=${() => runRulePackAction('validate')} disabled=${ruleBusy}>验证规则<//><${Button} size="sm" variant="primary" onClick=${() => runRulePackAction('activate')} disabled=${ruleBusy}>启用规则<//></div></div>` : null}<//><${Panel} eyebrow="Release lifecycle" title="规则包发布阶段"><div class="lifecycle">${(packs?.lifecycle || ['Draft', 'Validate', 'UnitTest', 'Replay', 'Shadow', 'Canary', 'Active', 'Rollback']).map((stage, index) => html`<div class=${cn('lifecycle-step', stage === 'Active' && 'is-active')}><span>${stage === 'Active' ? icon('check', 13) : index + 1}</span><b>${stage}</b>${index < 7 ? html`<i></i>` : null}</div>`)}</div><//><${Panel} eyebrow="Identity posture" title="身份策略"><div class="policy-table"><div class="policy-row policy-head"><span>Provider</span><span>Mode</span><span>跨站状态</span><span>状态</span><span>注册页</span></div>${(policies?.providers || []).map((policy) => html`<div class="policy-row"><b>${policy.provider}</b><span>${policy.mode}</span><span>${policy.cross_site}</span><${Badge} tone=${policy.cross_site === 'blocked' || policy.cross_site === 'disabled_by_default' ? 'success' : 'warning'}>${policy.enabled ? '已开启' : '已关闭'}<//><${Toggle} checked=${Boolean(policy.enabled)} onChange=${() => togglePolicy(policy)} disabled=${policyBusy !== ''} label=${`切换 ${policy.provider} 注册页入口`} /></div>`)}</div>${policyMessage ? html`<div class=${cn('form-message', policyMessageError && 'error', !policyMessageError && 'success')}>${policyMessage}</div>` : null}<div class="notice notice-info">${icon('shield', 16)}这里仅控制注册页的本地仿真入口；不会连接第三方 OAuth 服务，也不会接收第三方凭证。</div><//></div>${editor ? html`<${RuleEditorModal} rule=${editor.rule} editing=${editor.mode === 'edit'} busy=${ruleBusy} onClose=${() => setEditor(null)} onSave=${saveRule} />` : null}`
}

function SettingsPage({ username, onRotateEntry }) {
  const rotate = () => { if (window.confirm('轮换后当前管理入口会立即失效，需要从配置或启动输出获取新路径。继续吗？')) onRotateEntry() }
  return html`<div class="page-stack"><${PageHeader} eyebrow="Workspace settings" title="管理设置" description="管理离线恢复凭据和管理端入口。" /><div class="settings-grid"><${Panel} eyebrow="Account security" title="离线恢复" className="settings-form-panel"><div class="security-card"><div class="security-card-icon">${icon('key', 22)}</div><h3>${username || 'owner'} · 恢复凭据</h3><p>管理端不提供在线改密。请使用一次性 recovery code，或在服务器本机通过 hpctl 生成 rescue code 后完成恢复。</p><span class="instance-boundary"><i class="green-dot"></i>恢复码成功使用后立即失效</span></div><//><${Panel} eyebrow="Admin endpoint" title="管理入口"><div class="security-card"><div class="security-card-icon">${icon('key', 22)}</div><h3>随机隐藏路径</h3><p>当前入口路径不会在 API 响应中返回。轮换后会使现有管理会话失效，页面会跳转到新的入口。</p><button class="button button-danger-soft button-full" type="button" onClick=${rotate}>${icon('refresh', 16)}轮换管理入口</button></div><//><${Panel} eyebrow="Data boundary" title="运行边界" className="settings-note-panel"><div class="boundary-list"><div>${icon('shield', 17)}<span><b>事件流受保留策略限制</b><small>SQLite 是权威记录，JSONL 镜像会按保留天数与条数清理。</small></span></div><div>${icon('lock', 17)}<span><b>敏感字段脱敏</b><small>凭据、密码和 token 只保留 keyed fingerprint。</small></span></div><div>${icon('spark', 17)}<span><b>合成响应</b><small>不会运行模型、访问 URL 或连接供应商。</small></span></div></div><//></div></div>`
}

function Toast({ toast, onClose }) {
  if (!toast) return null
  return html`<div class=${cn('toast', toast.tone === 'error' && 'toast-error')} role="status">${icon(toast.tone === 'error' ? 'warning' : 'check', 17)}<span>${toast.message}</span><button class="icon-button" type="button" onClick=${onClose} aria-label="关闭提示">${icon('close', 15)}</button></div>`
}

function AuthLoading() { return html`<div class="auth-loading"><span class="brand-mark">A</span><span class="spinner"></span><p>正在连接 AegisLure 控制平面…</p></div>` }

function App() {
  const [route, setRoute] = useState(routeFromLocation()); const [auth, setAuth] = useState('checking'); const [username, setUsername] = useState(''); const [lastUpdated, setLastUpdated] = useState(null); const [busy, setBusy] = useState(false); const [loadError, setLoadError] = useState(''); const [toast, setToast] = useState(null); const [selectedEvent, setSelectedEvent] = useState(null); const [selectedActor, setSelectedActor] = useState(null); const [data, setData] = useState({ dashboard: null, instances: [], events: [], invocations: [], chains: [], indicators: [], packs: null, policies: null })
  const showToast = useCallback((message, tone = 'success') => { setToast({ message, tone }); window.setTimeout(() => setToast(null), 4200) }, [])
  const onNavigate = useCallback((next) => { setLoadError(''); navigateTo(next) }, [])
  const openActor = useCallback(async (indicator) => {
    const ip = indicator?.ip || ''
    if (!ip) return
    setSelectedActor({ ip, loading: true })
    try { setSelectedActor(await request(`actors/${encodeURIComponent(ip)}`)) } catch (error) { setSelectedActor(null); showToast(error.message || 'IP 详情读取失败', 'error') }
  }, [showToast])
  useEffect(() => { const handlePop = () => setRoute(routeFromLocation()); window.addEventListener('popstate', handlePop); return () => window.removeEventListener('popstate', handlePop) }, [])
  const loadRoute = useCallback(async (target = route, quiet = false) => {
    if (auth !== 'app') return
    if (!quiet) setBusy(true); setLoadError('')
    try {
      if (target === 'dashboard') { const [dashboard, instances] = await Promise.all([request('dashboard'), request('instances')]); setData((current) => ({ ...current, dashboard, instances: instances.instances || [] })) }
      else if (target === 'observations') { const result = await request('events?limit=500'); setData((current) => ({ ...current, events: result.events || [] })) }
      else if (target === 'invocations') { const result = await request('invocations?limit=500'); setData((current) => ({ ...current, invocations: result.invocations || [] })) }
      else if (target === 'chains') { const result = await request('interaction-chains?limit=200'); setData((current) => ({ ...current, chains: result.chains || [] })) }
      else if (target === 'indicators') { const result = await request('indicators'); setData((current) => ({ ...current, indicators: result.items || [] })) }
      else if (target === 'instances') { const result = await request('instances'); setData((current) => ({ ...current, instances: result.instances || [] })) }
      else if (target === 'packs') { const [packs, policies] = await Promise.all([request('packs'), request('identity-policies')]); setData((current) => ({ ...current, packs, policies })) }
      setLastUpdated(new Date())
    } catch (error) { if (error.status === 401) { setAuth('login'); navigateTo('login', true) } else setLoadError(error.message || '数据读取失败') } finally { if (!quiet) setBusy(false) }
  }, [auth, route])
  useEffect(() => {
    let active = true
    const initialize = async () => {
      try {
        const status = await request('setup/status'); if (!active) return
        if (!status.initialized) { setAuth('setup'); navigateTo('setup', true); return }
        try { const dashboard = await request('dashboard'); if (!active) return; setAuth('app'); setData((current) => ({ ...current, dashboard })); if (route === 'login' || route === 'setup') navigateTo('dashboard', true) }
        catch (error) { if (!active) return; if (error.status === 401) { setAuth('login'); if (route !== 'login') navigateTo('login', true) } else { setLoadError(error.message || '控制平面不可用'); setAuth('login') } }
      } catch (error) { if (active) { setLoadError(error.message || '无法读取初始化状态'); setAuth('login') } }
    }
    initialize(); return () => { active = false }
  }, [])
  useEffect(() => { if (auth === 'app') loadRoute(route) }, [auth, route])
  useEffect(() => { if (auth !== 'app') return undefined; const timer = window.setInterval(() => loadRoute(route, true), 30000); return () => window.clearInterval(timer) }, [auth, route, loadRoute])
  const login = async (name, password) => { const result = await request('auth/login', { method: 'POST', body: JSON.stringify({ username: name, password }) }); setUsername(result.username || name); setAuth('app'); navigateTo('dashboard', true); showToast('已安全登录控制平面') }
  const setup = async (name, password) => { if (name === 'continue') { setAuth('login'); navigateTo('login', true); return {} } const result = await request('setup/create-owner', { method: 'POST', body: JSON.stringify({ username: name, password }) }); setUsername(name); showToast('owner 已创建，请先保存恢复码'); return result }
  const forgotPassword = async (name) => request('auth/forgot-password', { method: 'POST', body: JSON.stringify({ username: name }) })
  const recoveryReset = async (name, code, password) => { await request('auth/recovery-code/reset', { method: 'POST', body: JSON.stringify({ username: name, recovery_code: code, new_password: password }) }); showToast('密码已重置，请使用新密码登录') }
  const logout = async () => { try { await request('auth/logout', { method: 'POST' }) } catch (_) {} setAuth('login'); setUsername(''); setSelectedActor(null); setSelectedEvent(null); setData({ dashboard: null, instances: [], events: [], invocations: [], chains: [], indicators: [], packs: null, policies: null }); navigateTo('login', true) }
  const rotateEntry = async () => { try { const result = await request('admin-entry:rotate', { method: 'POST' }); if (result.new_path) { window.location.assign(`${result.new_path}login`); return } setAuth('login'); navigateTo('login', true); showToast('入口已轮换，请从配置文件获取新路径') } catch (error) { showToast(error.message || '入口轮换失败', 'error') } }
  const instanceAction = async (instance, action) => {
    if (action === 'start-all') { setBusy(true); try { for (const item of data.instances) if (item.state !== 'running') await request(`instances/${item.product}/start`, { method: 'POST' }); await loadRoute('instances', true); showToast('启动指令已应用') } catch (error) { showToast(error.message || '启动实例失败', 'error') } finally { setBusy(false) }; return }
    setBusy(true); try { const result = await request(`instances/${instance.product}/${action}`, { method: 'POST' }); setData((current) => ({ ...current, instances: result.instances || current.instances })); showToast(`${profileLabel(instance.product)} ${action === 'restart' ? '已重启' : action === 'start' ? '已启动' : '已停止'}`); if (route === 'dashboard') await loadRoute('dashboard', true) } catch (error) { showToast(error.message || '实例操作失败', 'error') } finally { setBusy(false) }
  }
  if (auth === 'checking') return html`<${AuthLoading} />`
  if (auth === 'setup') return html`<${SetupPage} onSetup=${setup} />`
  if (auth === 'login') return html`<${LoginPage} onLogin=${login} onForgot=${forgotPassword} onRecovery=${recoveryReset} />`
  const page = route === 'observations' ? html`<${ObservationsPage} events=${data.events} onRefresh=${() => loadRoute('observations')} onOpenEvent=${(event) => setSelectedEvent(event)} />` : route === 'invocations' ? html`<${InvocationsPage} invocations=${data.invocations} onRefresh=${() => loadRoute('invocations')} onOpenEvent=${(event) => setSelectedEvent(event)} />` : route === 'chains' ? html`<${ChainsPage} chains=${data.chains} onRefresh=${() => loadRoute('chains')} onOpenEvent=${(event) => setSelectedEvent(event)} />` : route === 'indicators' ? html`<${IndicatorsPage} indicators=${data.indicators} onRefresh=${() => loadRoute('indicators')} onOpenIndicator=${openActor} />` : route === 'instances' ? html`<${InstancesPage} instances=${data.instances} onRefresh=${() => loadRoute('instances')} onAction=${instanceAction} busy=${busy} />` : route === 'packs' ? html`<${PacksPage} packs=${data.packs} policies=${data.policies} onRefresh=${() => loadRoute('packs')} />` : route === 'settings' ? html`<${SettingsPage} username=${username} onRotateEntry=${rotateEntry} />` : html`<${DashboardPage} dashboard=${data.dashboard} instances=${data.instances} onNavigate=${onNavigate} onRefresh=${() => loadRoute('dashboard')} onOpenEvent=${(event) => setSelectedEvent(event)} />`
  return html`<${AppShell} route=${route} onNavigate=${onNavigate} onLogout=${logout} username=${username} lastUpdated=${lastUpdated}><div class=${cn(loadError && 'has-page-error')}>${loadError ? html`<div class="page-error">${icon('warning', 17)}<span>${loadError}</span><button class="text-button" type="button" onClick=${() => loadRoute(route)}>重试</button></div>` : null}${page}</div><//>${selectedActor ? html`<${ActorDetailModal} actor=${selectedActor} onClose=${() => setSelectedActor(null)} onOpenEvent=${(event) => setSelectedEvent(event)} />` : null}${selectedEvent ? html`<${EventDetails} event=${{ ...selectedEvent, onClose: () => setSelectedEvent(null) }} />` : null}<${Toast} toast=${toast} onClose=${() => setToast(null)} />`
}

render(html`<${App} />`, document.getElementById('app'))
