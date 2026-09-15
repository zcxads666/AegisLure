import {
  html,
  render,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from './htm-preact.module.js'

const ADMIN_BASE = document.body.dataset.adminBase || '/'
const BASE = ADMIN_BASE.endsWith('/') ? ADMIN_BASE : `${ADMIN_BASE}/`
const jsonHeaders = { 'Content-Type': 'application/json', Accept: 'application/json' }

const NAV_ITEMS = [
  { id: 'dashboard', label: '总览', icon: 'grid' },
  { id: 'observations', label: '观测记录', icon: 'activity' },
  { id: 'invocations', label: '调用分析', icon: 'spark' },
  { id: 'chains', label: '信息洞察', icon: 'route' },
  { id: 'indicators', label: 'IP 情报', icon: 'shield' },
  { id: 'instances', label: '蜜罐实例', icon: 'server' },
  { id: 'packs', label: '规则与策略', icon: 'layers' },
]

const PROFILE_LABELS = {
  'new-api': 'New API',
  vllm: 'vLLM',
  ollama: 'Ollama',
  sglang: 'SGLang',
  localai: 'LocalAI',
  sub2api: 'Sub2API',
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
  globe: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M3 12h18', 'M12 3c2.2 2.4 3.3 5.4 3.3 9s-1.1 6.6-3.3 9c-2.2-2.4-3.3-5.4-3.3-9S9.8 5.4 12 3Z'],
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

function isAbortError(error) {
  return error?.name === 'AbortError'
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

function useCountUp(target, animationKey, duration = 720) {
  const numericTarget = Number.isFinite(Number(target)) ? Number(target) : 0
  const targetRef = useRef(numericTarget)
  const mountedRef = useRef(false)
  const animatingRef = useRef(false)
  const [displayValue, setDisplayValue] = useState(() => animationKey ? 0 : numericTarget)
  targetRef.current = numericTarget

  useEffect(() => {
    if (!mountedRef.current) {
      mountedRef.current = true
      return
    }
    if (!animatingRef.current) setDisplayValue(numericTarget)
  }, [numericTarget])

  useEffect(() => {
    if (!animationKey) {
      animatingRef.current = false
      setDisplayValue(targetRef.current)
      return undefined
    }
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      animatingRef.current = false
      setDisplayValue(targetRef.current)
      return undefined
    }
    animatingRef.current = true
    setDisplayValue(0)
    let frame = 0
    let startedAt = 0
    const tick = (timestamp) => {
      if (!startedAt) startedAt = timestamp
      const progress = Math.min(1, (timestamp - startedAt) / duration)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplayValue(Math.round(targetRef.current * eased))
      if (progress < 1) frame = window.requestAnimationFrame(tick)
      else {
        animatingRef.current = false
        setDisplayValue(targetRef.current)
      }
    }
    frame = window.requestAnimationFrame(tick)
    return () => {
      window.cancelAnimationFrame(frame)
      animatingRef.current = false
    }
  }, [animationKey, duration])

  return displayValue
}

function formatTime(value, withSeconds = false, timeZone = '') {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  const options = {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined, hour12: false,
  }
  if (timeZone) options.timeZone = timeZone
  return new Intl.DateTimeFormat('zh-CN', options).format(date)
}

function shortValue(value, size = 18) {
  if (!value) return '—'
  const text = String(value)
  return text.length > size ? `${text.slice(0, size)}…` : text
}

function profileLabel(value) { return PROFILE_LABELS[value] || value || '未知' }
function levelLabel(value) { return LEVEL_LABELS[value] || value || '未分级' }
function geoSourceLabel(value) {
  if (value === 'maxmind_geolite2') return 'MaxMind GeoLite2'
  if (value === 'ipinfo_lite') return 'IPinfo Lite'
  if (value === 'ipinfo_mmdb') return 'IPinfo MMDB'
  if (value === 'ipinfo_api') return 'IPinfo API'
  return '离线/回退'
}
function indicatorCountry(row) {
  const country = row.country_zh || row.country || '未知'
  const code = row.country_code && row.country_code !== country ? ` · ${row.country_code}` : ''
  return `${country}${code}`
}
function indicatorPlace(row) {
  const place = [row.city, row.region].filter(Boolean).join(' · ')
  return place || '—'
}
function indicatorNetwork(row) {
  const network = [row.as_name, row.asn].filter(Boolean).join(' · ')
  return network || '—'
}
function apiPath(path) { return `${BASE}admin/api/v1/${path}` }

const LIST_DEFAULTS = {
  observations: { page: 1, q: '', product: '', min_score: '' },
  invocations: { page: 1, q: '', level: '', auth: '', execution: '' },
  chains: { page: 1, q: '' },
  indicators: { page: 1, q: '', risk_level: '', sort: 'latest' },
}

const INDICATOR_RISK_OPTIONS = [
  { value: '', label: '全部风险' },
  { value: 'high', label: '高风险 · 60–100 分' },
  { value: 'medium', label: '中风险 · 30–59 分' },
  { value: 'low', label: '低风险 · 0–29 分' },
]

const INDICATOR_SORT_OPTIONS = [
  { value: 'latest', label: '最近出现优先' },
  { value: 'risk', label: '风险分从高到低' },
]

function responsePagination(result) {
  return result?.pagination || {
    page: Number(result?.page || 1),
    page_size: Number(result?.page_size || 10),
    total: Number(result?.total || 0),
    total_pages: Number(result?.total_pages || 0),
    has_next: Boolean(result?.has_next),
    has_previous: Boolean(result?.has_previous),
  }
}

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

function Badge({ children, tone = 'neutral' }) {
  return html`<span class=${cn('badge', `badge-${tone}`)}>${children}</span>`
}

function Panel({ title, action, className, children, flush = false }) {
  return html`<section class=${cn('panel', flush && 'panel-flush', className)}>
    ${(title || action) ? html`<header class="panel-header"><div>${title ? html`<h2>${title}</h2>` : null}</div>${action || null}</header>` : null}
    ${children}
  </section>`
}

function PageHeader({ title, description, actions }) {
  return html`<header class="page-header"><div><h1>${title}</h1>${description ? html`<p class="page-description">${description}</p>` : null}</div>${actions ? html`<div class="page-actions">${actions}</div>` : null}</header>`
}

function MetricCard({ label, value, suffix = '', detail, animationKey = 0 }) {
  const numericValue = typeof value === 'number' ? value : null
  const animatedValue = useCountUp(numericValue ?? 0, numericValue === null ? 0 : animationKey)
  const displayValue = numericValue === null ? value : formatNumber(animatedValue)
  return html`<article class="metric-card"><strong class="metric-value">${displayValue}${suffix}</strong><span class="metric-label">${label}</span>${detail ? html`<small class="metric-detail">${detail}</small>` : null}</article>`
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
  return html`<${Badge} tone=${running ? 'success' : 'neutral'}>${running ? '运行中' : '已停止'}<//>`
}

function Modal({ title, onClose, children, wide = false }) {
  useEffect(() => {
    const onKey = (event) => event.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])
  return html`<div class="modal-backdrop" onClick=${(event) => event.target === event.currentTarget && onClose()}><section class=${cn('modal', wide && 'modal-wide')} role="dialog" aria-modal="true" aria-label=${title}><header class="modal-header"><h2>${title}</h2><button class="icon-button" type="button" onClick=${onClose} aria-label="关闭">${icon('close', 19)}</button></header><div class="modal-body">${children}</div></section></div>`
}

function DataTable({ columns, rows, onRowClick, emptyTitle, emptyDescription, loading = false, loadingLabel = '读取中…' }) {
  if (loading) return html`<${LoadingState} label=${loadingLabel} />`
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

function semanticRoute(event) {
  const value = String(event?.route_template || '').trim()
  if (!value || value.split('.').pop() === 'unknown' || value.includes('unclassified')) return '未识别协议路由'
  return value
}

function rawRequestRoute(event) {
  const raw = event?.raw_request
  if (raw) return raw.route || raw.url || '—'
  return '历史事件未记录原始请求'
}

function displayRoute(event) {
  const value = String(event?.display_route || event?.metadata?.display_route || '').trim()
  return value || rawRequestRoute(event)
}

function rawRoute(event) { return displayRoute(event) }

function displayRouteCell(event) {
  const count = Number(event?.aggregate_count || 0)
  return html`<span class="route-cell">${displayRoute(event)}${count > 1 ? html`<small> · ${formatNumber(count)} 个前端请求</small>` : null}</span>`
}

function displayEventProjection(event) {
  if (!event) return event
  const route = displayRoute(event)
  return { ...event, route_template: semanticRoute(event), display_route: route }
}

function displayChainProjection(chain) {
  if (!chain) return chain
  return { ...chain, events: (chain.events || []).map(displayEventProjection) }
}

function rejectionReasonLabel(value) {
  const labels = {
    missing_authentication: '缺少认证',
    invalid_authentication: '认证不匹配',
    session_authentication_mismatch: '会话与认证不匹配',
    model_not_allowed_for_key: 'key 不允许该模型',
    model_not_found: '模型不存在',
    invalid_request: '请求非法',
    quota_overflow: '请求配额超限',
    quota_exhausted: '配额不足',
    request_rejected: '请求被拒绝',
  }
  return labels[value] || value || '—'
}

function DeleteButton({ onClick, label = '删除' }) {
  const handleClick = (event) => { event.stopPropagation(); onClick() }
  return html`<button class="text-button danger-text" type="button" onClick=${handleClick}>${label}</button>`
}

function SearchButton({ onClick }) { return html`<button class="outline-button" type="button" onClick=${onClick}>搜索</button>` }

function PaginationControls({ pagination, onPageChange }) {
  if (!pagination) return null
  const page = Number(pagination.page || 1)
  const totalPages = Number(pagination.total_pages || 0)
  const displayPages = Math.max(1, totalPages)
  return html`<div class="pagination-controls"><span>第 ${totalPages ? page : 0} / ${displayPages} 页 · 共 ${formatNumber(pagination.total || 0)} 条</span><div class="button-group"><button class="outline-button" type="button" disabled=${!pagination.has_previous} onClick=${() => onPageChange(page - 1)}>上一页</button><button class="outline-button" type="button" disabled=${!pagination.has_next} onClick=${() => onPageChange(page + 1)}>下一页</button></div></div>`
}

function Select({ label, value, onChange, options, className }) {
  return html`<label class=${cn('select-field', className)}>${label ? html`<span>${label}</span>` : null}<select value=${value} onChange=${(event) => onChange(event.target.value)}>${options.map((option) => html`<option value=${option.value}>${option.label}</option>`)}</select></label>`
}

function TextInput({ label, placeholder, value, onInput, type = 'text', className, ...props }) {
  return html`<label class=${cn('text-field', className)}>${label ? html`<span>${label}</span>` : null}<input type=${type} value=${value} placeholder=${placeholder} onInput=${(event) => onInput(event.target.value)} ...${props} /></label>`
}

function Toggle({ checked, onChange, label, disabled = false }) {
  return html`<button type="button" class=${cn('toggle', checked && 'is-on')} onClick=${() => onChange(!checked)} disabled=${disabled} role="switch" aria-checked=${checked} aria-label=${label || '切换状态'}><span></span></button>`
}

function ActivityChart({ items = [], animationKey = 0 }) {
  const max = Math.max(1, ...items.map((item) => Number(item.count || 0)))
  return html`<div class="activity-chart" aria-label="近 24 小时事件量">${items.map((item, index) => {
    const targetHeight = `${Math.max(5, (Number(item.count || 0) / max) * 100)}%`
    return html`<div class="activity-bar-wrap" key=${item.label || index}><div class="activity-value">${item.count || ''}</div><div class=${cn('activity-bar', animationKey && 'is-dashboard-entry')} style=${`height:${targetHeight};--bar-start-width:100%;--bar-start-height:0%;--bar-end-width:100%;--bar-end-height:${targetHeight};`}></div><small>${item.label}</small></div>`
  })}</div>`
}

function RiskDonut({ distribution = {}, animationKey = 0 }) {
  const items = [
    { key: 'high', name: '高风险', count: Number(distribution.high || 0) },
    { key: 'medium', name: '中风险', count: Number(distribution.medium || 0) },
    { key: 'low', name: '低风险', count: Number(distribution.low || 0) },
  ]
  return html`<${DistributionDonut} items=${items} centerLabel="IP 指标" animationKey=${animationKey} />`
}

function RiskActivityChart({ series = {}, animationKey = 0 }) {
  const [period, setPeriod] = useState('hour')
  const periods = [{ key: 'hour', label: '近24小时', detail: '每小时滚动' }, { key: 'week', label: '近7天', detail: '每日滚动' }, { key: 'month', label: '近30天', detail: '每日滚动' }]
  const selected = series[period] || (period === 'hour' ? series.day : {}) || {}
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
  const dashboardTimezone = selected.timezone || 'Asia/Shanghai'
  return html`<div class="risk-activity"><div class="chart-switcher" role="tablist" aria-label="趋势时间范围">${periods.map((item) => html`<button key=${item.key} type="button" class=${cn(period === item.key && 'is-active')} onClick=${() => setPeriod(item.key)} role="tab" aria-selected=${period === item.key}><b>${item.label}</b><small>${item.detail}</small></button>`)}</div>${points.length ? html`<div class=${cn('risk-chart-canvas', animationKey && 'is-dashboard-entry')} key=${period}><svg viewBox=${`0 0 ${width} ${height}`} role="img" aria-label=${`${periods.find((item) => item.key === period)?.label || ''}风险触发趋势`}>${[0, .25, .5, .75, 1].map((ratio) => html`<line key=${ratio} class="chart-grid-line" x1=${padding.left} x2=${width - padding.right} y1=${y(ratio * max)} y2=${y(ratio * max)}></line>`)}<path class="chart-area" d=${areaPath}></path><path pathLength="1" class="chart-line chart-line-total" d=${totalPath}></path><path pathLength="1" class="chart-line chart-line-risk" d=${riskPath}></path>${points.map((point, index) => html`<g key=${point.key || point.start_at || `${point.label}-${index}`}><circle class="chart-dot chart-dot-total" cx=${x(index)} cy=${y(point.count)} r="3.5"></circle><circle class="chart-dot chart-dot-risk" cx=${x(index)} cy=${y(point.risk_count)} r="3"></circle>${(index === 0 || index === points.length - 1 || index % labelStep === 0) ? html`<text class="chart-label" x=${x(index)} y=${height - 8} text-anchor="middle">${point.label}</text>` : null}</g>`)}</svg></div>` : html`<${EmptyState} title="暂无趋势数据" description="新的观测事件出现后，这里会显示风险波动。" />`}<div class="chart-summary"><span><i class="chart-key key-total"></i><b>${formatNumber(selected.total)}</b> 总事件</span><span><i class="chart-key key-risk"></i><b>${formatNumber(selected.risk_total)}</b> 风险触发</span><span class="chart-threshold">阈值 ≥ ${selected.risk_threshold || 30}</span><span class="chart-window">${selected.bucket === 'hour' ? '按小时滚动' : '按日滚动'} · ${dashboardTimezone} · 下次刷新 ${selected.next_refresh_at ? formatTime(selected.next_refresh_at, false, dashboardTimezone) : '自动'}</span></div></div>`
}

function donutArcPath(startPercent, endPercent, outerRadius = 46, innerRadius = 29) {
  const span = Math.min(99.999, Math.max(0.001, endPercent - startPercent))
  const startAngle = (startPercent / 100) * Math.PI * 2 - Math.PI / 2
  const endAngle = startAngle + (span / 100) * Math.PI * 2
  const point = (radius, angle) => [60 + radius * Math.cos(angle), 60 + radius * Math.sin(angle)]
  const [outerStartX, outerStartY] = point(outerRadius, startAngle)
  const [outerEndX, outerEndY] = point(outerRadius, endAngle)
  const [innerStartX, innerStartY] = point(innerRadius, startAngle)
  const [innerEndX, innerEndY] = point(innerRadius, endAngle)
  const largeArc = span > 50 ? 1 : 0
  return `M ${outerStartX} ${outerStartY} A ${outerRadius} ${outerRadius} 0 ${largeArc} 1 ${outerEndX} ${outerEndY} L ${innerEndX} ${innerEndY} A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${innerStartX} ${innerStartY} Z`
}

function DistributionDonut({ items = [], centerLabel = '事件总量', animationKey = 0 }) {
  const colors = { high: '#ef7185', medium: '#edb968', low: '#56d6bd' }
  const palette = ['#6edfeb', '#9c8cf4', '#ef9b73', '#76a7ff']
  const normalized = items.map((item) => ({ ...item, count: Number(item.count || 0) }))
  const total = normalized.reduce((sum, item) => sum + item.count, 0)
  let cursor = 0
  const segments = normalized.map((item, index) => {
    const start = cursor
    cursor += total ? (item.count / total) * 100 : 0
    return { ...item, start, end: cursor, color: colors[item.key] || palette[index % palette.length], percentage: item.percentage || (total ? Math.round((item.count / total) * 100) : 0) }
  }).filter((item) => item.count > 0)
  return html`<div class="risk-donut-wrap"><div class=${cn('risk-donut', animationKey && 'is-dashboard-entry')} aria-label=${`${centerLabel}分布图`}><svg class="donut-svg" viewBox="0 0 120 120" role="img" aria-hidden="true">${total ? segments.map((item, index) => html`<path key=${item.key || index} class="donut-segment" d=${donutArcPath(item.start, item.end)} fill=${item.color}></path>`) : html`<circle class="donut-track" cx="60" cy="60" r="38"></circle>`}</svg><div class="donut-center"><div><strong>${formatNumber(total)}</strong><small>${centerLabel}</small></div></div></div><div class="donut-legend-stack"><div class="legend-list">${normalized.map((item, index) => { const percentage = item.percentage || (total ? Math.round((item.count / total) * 100) : 0); return html`<div key=${item.key || index}><i class="legend-dot" style=${{ background: colors[item.key] || palette[index % palette.length] }}></i><span>${item.name || item.key}</span><b>${formatNumber(item.count)} <small>${percentage}%</small></b></div>` })}</div></div></div>`
}

function CountryDistribution({ items = [] }) {
  const visible = items.slice(0, 7); const max = Math.max(1, ...visible.map((item) => Number(item.count || 0)))
  if (!visible.length) return html`<${EmptyState} icon="globe" title="暂无来源区域" description="聚合来源 IP 后会显示离线可识别的地址类别。" />`
  return html`<div class="country-list">${visible.map((item) => html`<div class="country-row" key=${item.key || item.name}><div class="country-row-head"><span><i class="country-bullet"></i>${item.name || '未知'}</span><b>${formatNumber(item.count)} <small>${item.percentage || 0}%</small></b></div><div class="share-progress"><i style=${{ width: `${Math.max(3, (Number(item.count || 0) / max) * 100)}%` }}></i></div></div>`)}</div><div class="panel-footnote">本地数据库不可用或查询失败时回退到本地/保留、文档地址或“未知”；切换到 IPinfo 后，公网查询成功会显示对应的 MMDB 或 API 结果。</div>`
}

function HoneypotDistribution({ items = [], animationKey = 0 }) {
  const visible = items.slice(0, 7); const max = Math.max(1, ...visible.map((item) => Number(item.count || 0)))
  if (!visible.length) return html`<${EmptyState} icon="layers" title="暂无蜜罐触发" description="访问公开端点后会按协议统计触发占比。" />`
  return html`<div class="honeypot-list">${visible.map((item, index) => {
    const targetWidth = `${Math.max(3, (Number(item.count || 0) / max) * 100)}%`
    return html`<div class="honeypot-row" key=${item.key || item.name}><div class="honeypot-row-head"><span class="honeypot-rank">${String(index + 1).padStart(2, '0')}</span><div><b>${profileLabel(item.name)}</b><small>${formatNumber(item.count)} 次 · 风险 ${formatNumber(item.risk_count)} 次</small></div><strong>${item.percentage || 0}%</strong></div><div class=${cn('share-progress', animationKey && 'is-dashboard-entry')}><i style=${`width:${targetWidth};--bar-start-width:0%;--bar-start-height:100%;--bar-end-width:${targetWidth};--bar-end-height:100%;`}></i></div></div>`
  })}</div><div class="panel-footnote">占比按事件次数计算；“风险”表示该类型中风险分 ≥ 30 的事件。</div>`
}

function ActorDetailModal({ actor, onClose, onOpenEvent }) {
  if (!actor) return null
  if (actor.loading) return html`<${Modal} title="IP 动作详情" eyebrow="IP intelligence" onClose=${onClose}><${LoadingState} label=${`正在读取 ${actor.ip || 'IP'} 的全部动作…`} /><//>`
  const indicator = actor.indicator || {}; const events = Array.isArray(actor.events) ? actor.events : []; const riskEvents = events.filter((event) => Number(event.score || 0) >= 30).length
  const geo = actor.geo || actor
  const firstSeen = indicator.first_seen || events[events.length - 1]?.observed_at; const lastSeen = indicator.last_seen || events[0]?.observed_at
  const country = actor.country_zh || actor.country || geo.country_zh || geo.country || '未知'
  return html`<${Modal} title="IP 动作详情" eyebrow=${`IP intelligence · ${actor.ip || 'unknown'}`} onClose=${onClose} wide=${true}><div class="actor-hero"><div><p class="actor-kicker">来源 IP</p><code class="actor-ip">${actor.ip || '—'}</code><div class="actor-subline"><span class="country-pill">${country}</span><span>全部事件已加载 · 按时间倒序</span></div></div><${RiskBadge} score=${indicator.score} /></div><div class="actor-summary-grid"><div><span>来源区域</span><strong>${country}</strong></div><div><span>国家码</span><strong>${geo.country_code || '—'}</strong></div><div><span>地理来源</span><strong>${geoSourceLabel(geo.geo_source || geo.source)}</strong></div><div><span>证据次数</span><strong>${formatNumber(indicator.evidence_count || events.length)}</strong></div><div><span>风险事件</span><strong>${formatNumber(riskEvents)}</strong></div><div><span>置信度</span><strong>${indicator.confidence || 'low'}</strong></div><div><span>首次出现</span><strong>${formatTime(firstSeen)}</strong></div><div><span>最近出现</span><strong>${formatTime(lastSeen)}</strong></div></div><div class="actor-geo-row"><span>网络归属</span><b>${geo.as_name || '—'}</b><small>${geo.asn || 'ASN 未返回'}${geo.as_domain ? ` · ${geo.as_domain}` : ''} · ${geo.continent || '洲信息未知'}</small></div><div class="actor-meta-row"><div><span>命中蜜罐</span><div class="chip-list compact">${(indicator.products || []).map((product) => html`<${Badge} tone="neutral" key=${product}>${profileLabel(product)}<//>`)}</div></div><div><span>建议处置</span><b class=${cn('action-label', indicator.score >= 60 && 'action-risk')}>${indicator.recommended_action || 'observe'}</b></div></div><div class="detail-section actor-actions-section"><div class="actor-actions-head"><div><p class="eyebrow">Evidence timeline</p><h3>全部动作</h3></div><span class="panel-meta">${formatNumber(events.length)} 条原始动作</span></div>${events.length ? html`<div class="actor-timeline">${events.map((event, index) => html`<button class="actor-action-row" type="button" key=${event.event_id || index} onClick=${() => onOpenEvent(event)}><span class=${cn('actor-action-marker', Number(event.score || 0) >= 60 && 'is-high', Number(event.score || 0) >= 30 && Number(event.score || 0) < 60 && 'is-medium')}></span><span class="actor-action-main"><b>${event.event_type || semanticRoute(event)}</b><small>${profileLabel(event.product)} · ${event.method || 'HTTP'} ${displayRoute(event)}</small><em>${event.execution_outcome || event.auth_outcome || event.effect_outcome || '已记录'}${event.rejection_reason ? ` · ${rejectionReasonLabel(event.rejection_reason)}` : ''} · ${levelLabel(event.invocation_level)}</em></span><span class="actor-action-side"><${RiskBadge} score=${event.score} /><time>${formatTime(event.observed_at, true)}</time></span>${icon('chevron', 15)}</button>`)}</div>` : html`<${EmptyState} title="该 IP 暂无动作" description="指标仍存在，但当前没有可展示的事件记录。" />`}</div><div class="panel-footnote">点击任意动作可查看完整原始请求；旧事件会明确标记原文缺失。</div></${Modal}>`
}

function EventDetails({ event }) {
  if (!event) return null
  if (event.loading) return html`<${Modal} title="观测详情" eyebrow="event" onClose=${event.onClose}><${LoadingState} label="正在读取完整原始请求…" /><//>`
  event = displayEventProjection(event)
  const displayedRoute = displayRoute(event)
  const fields = [['事件 ID', event.event_id], ['观测时间', formatTime(event.observed_at, true)], ['产品', profileLabel(event.product)], ['来源 IP', event.source_ip], ['展示路由', displayedRoute !== rawRequestRoute(event) ? displayedRoute : ''], ['原始请求路由', rawRequestRoute(event)], ['内部分类路由', semanticRoute(event)], ['请求方法', event.method], ['状态码', event.status], ['风险分', event.score], ['意图分类', event.intent_class], ['调用等级', levelLabel(event.invocation_level)], ['鉴权结果', event.auth_outcome], ['执行结果', event.execution_outcome], ['拒绝原因', rejectionReasonLabel(event.rejection_reason)], ['效果结果', event.effect_outcome], ['模型', event.model_id], ['会话 ID', event.session_id], ['聚合前端 GET', event.aggregate_count > 1 ? `${formatNumber(event.aggregate_count)} 次` : '']]
  const raw = event.raw_request
  return html`<${Modal} title="观测详情" eyebrow=${event.event_type || 'event'} onClose=${event.onClose} wide=${true}><div class="detail-grid">${fields.filter((item) => item[1] !== undefined && item[1] !== '').map((item) => html`<div class="detail-item"><span>${item[0]}</span><strong>${String(item[1])}</strong></div>`)}</div>${event.reason_codes?.length ? html`<div class="detail-section"><h3>命中原因</h3><div class="chip-list">${event.reason_codes.map((reason) => html`<${Badge} tone="warning">${reason}<//>`)}</div></div>` : null}<div class="detail-section"><h3>完整原始请求</h3>${raw ? html`<div class="raw-request-grid"><div class="detail-item"><span>原始 URL / 请求目标</span><code>${raw.url || '—'}</code></div><div class="detail-item"><span>完整路径</span><code>${raw.route || '—'}</code></div><div class="detail-item"><span>Host</span><code>${raw.host || '—'}</code></div></div><h4>全部请求头（重复值保留）</h4><pre class="json-view">${JSON.stringify(raw.headers || {}, null, 2)}</pre><h4>原始请求体 Base64</h4><pre class="json-view raw-body-view">${raw.body_base64 || ''}</pre>${raw.truncated ? html`<div class="notice notice-warning">原始请求已截断：${raw.truncation_reason || '超过采集限制'}；以上为已保存前缀。</div>` : null}` : html`<div class="notice notice-warning">历史事件未记录原始请求，无法恢复原始 URL、请求头或请求体。</div>`}</div><div class="detail-section"><h3>事件记录</h3><pre class="json-view">${JSON.stringify({ ...event, onClose: undefined }, null, 2)}</pre></div><//>`
}


function LoginPage({ onLogin, onRecovery, onForgot }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [modal, setModal] = useState(null)
  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    try { await onLogin(username, password) } catch (error) { setMessage(error.message || '登录失败，请检查账号和密码。') } finally { setBusy(false) }
  }
  return html`
    <div class="auth-layout">
      <section class="auth-art" aria-label="AegisLure 安全观测控制台">
        <div class="auth-brand"><span class="brand-mark">A</span><strong>AegisLure</strong></div>
        <div class="auth-copy">
          <h1>看见每一次<br /><em>可疑调用。</em></h1>
          <p>把模型服务蜜罐里的发现、调用与风险证据，收拢成一条清晰的操作链路。</p>
          <div class="auth-facts"><span>${icon('shield', 16)}本地存储</span><span>${icon('lock', 16)}同源会话</span><span>${icon('spark', 16)}合成响应</span></div>
        </div>
        <div class="auth-art-foot">安全观测控制台</div>
      </section>
      <main class="auth-main">
        <div class="auth-card">
          <div class="mobile-brand"><span class="brand-mark">A</span><strong>AegisLure</strong></div>
          <h2>欢迎回来</h2>
          <p class="auth-subtitle">登录以继续查看传感器状态和观测证据。</p>
          <form onSubmit=${submit} class="auth-form">
            <${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" maxLength="128" required=${true} />
            <${TextInput} label="密码" placeholder="输入密码" type="password" value=${password} onInput=${setPassword} autoComplete="current-password" required=${true} />
            <button class="button button-primary button-lg auth-submit" type="submit" disabled=${busy}>${busy ? html`<span class="spinner spinner-dark"></span>登录中…` : html`登录控制台 ${icon('arrow', 17)}`}</button>
          </form>
          ${message ? html`<div class="form-message error" role="alert">${message}</div>` : null}
          <button class="link-button" type="button" onClick=${() => setModal('forgot')}>忘记密码？使用恢复码</button>
          <div class="auth-note">${icon('shield', 15)}管理端建议仅通过可信网络或 VPN 访问。</div>
        </div>
        <p class="auth-footer">仅生成合成遥测 · 不访问真实模型或网址</p>
      </main>
    </div>
    ${modal === 'forgot' ? html`<${RecoveryModal} onClose=${() => setModal(null)} onForgot=${onForgot} onRecovery=${onRecovery} />` : null}
  `
}

function RecoveryModal({ onClose, onForgot, onRecovery }) {
  const [username, setUsername] = useState(''); const [code, setCode] = useState(''); const [password, setPassword] = useState(''); const [confirm, setConfirm] = useState(''); const [busy, setBusy] = useState(false); const [message, setMessage] = useState(''); const [sent, setSent] = useState(false)
  const submitForgot = async (event) => { event.preventDefault(); setBusy(true); setMessage(''); try { await onForgot(username); setSent(true) } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  const submitReset = async (event) => { event.preventDefault(); if (password !== confirm) { setMessage('两次输入的新密码不一致。'); return } setBusy(true); setMessage(''); try { await onRecovery(username, code, password); onClose() } catch (error) { setMessage(error.message) } finally { setBusy(false) } }
  return html`<${Modal} title="恢复管理员访问" eyebrow="Account recovery" onClose=${onClose}>${!sent ? html`<form class="stack-form" onSubmit=${submitForgot}><p class="modal-copy">如果部署配置了恢复流程，系统会向对应渠道发送说明。账号是否存在不会通过响应泄露。</p><${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" required=${true} /><button class="button button-primary button-full" type="submit" disabled=${busy}>${busy ? '提交中…' : '发送恢复说明'}</button></form>` : html`<form class="stack-form" onSubmit=${submitReset}><div class="notice notice-info">请输入一次性恢复码。恢复码成功使用后会立即失效。</div><${TextInput} label="管理员账号" placeholder="输入账号" value=${username} onInput=${setUsername} autoComplete="username" required=${true} /><${TextInput} label="恢复码" placeholder="输入离线保存的恢复码" value=${code} onInput=${setCode} autoComplete="one-time-code" required=${true} /><${TextInput} label="新密码" placeholder="至少 8 个字符" type="password" value=${password} onInput=${setPassword} minLength="8" maxLength="128" required=${true} /><${TextInput} label="确认新密码" placeholder="再次输入新密码" type="password" value=${confirm} onInput=${setConfirm} minLength="8" maxLength="128" required=${true} /><button class="button button-primary button-full" type="submit" disabled=${busy}>${busy ? '重置中…' : '重置密码'}</button></form>`}${message ? html`<div class="form-message error">${message}</div>` : null}<//>`
}


function SetupPage({ onSetup }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [codes, setCodes] = useState([])
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [copied, setCopied] = useState(false)
  const submit = async (event) => {
    event.preventDefault()
    if (password !== confirm) { setMessage('两次输入的密码不一致。'); return }
    setBusy(true)
    setMessage('')
    try { const result = await onSetup(username, password); setCodes(result.recovery_codes || []) } catch (error) { setMessage(error.message) } finally { setBusy(false) }
  }
  const copyCodes = async () => {
    try { await navigator.clipboard.writeText(codes.join('\n')); setCopied(true); setTimeout(() => setCopied(false), 1800) } catch (_) { setMessage('浏览器不允许自动复制，请手动保存恢复码。') }
  }
  return html`
    <div class="auth-layout setup-layout">
      <section class="auth-art" aria-label="AegisLure 初始化">
        <div class="auth-brand"><span class="brand-mark">A</span><strong>AegisLure</strong></div>
        <div class="auth-copy">
          <h1>建立你的<br /><em>观测中枢。</em></h1>
          <p>初始化本地管理员后，你就可以查看事件、控制蜜罐实例并管理风险证据。</p>
          <div class="auth-facts"><span>${icon('lock', 16)}Argon2id 密码</span><span>${icon('key', 16)}一次性恢复码</span><span>${icon('shield', 16)}本地管理</span></div>
        </div>
        <div class="auth-art-foot">安全观测控制台</div>
      </section>
      <main class="auth-main">
        <div class="auth-card">
          ${codes.length === 0 ? html`
            <h2>创建管理员</h2>
            <p class="auth-subtitle">设置本地控制台的唯一管理员账号。</p>
            <form class="auth-form" onSubmit=${submit}>
              <${TextInput} label="管理员账号" placeholder="例如 admin" value=${username} onInput=${setUsername} autoComplete="username" maxLength="128" required=${true} />
              <${TextInput} label="密码" placeholder="至少 8 个字符" type="password" value=${password} onInput=${setPassword} minLength="8" maxLength="128" required=${true} />
              <${TextInput} label="确认密码" placeholder="再次输入密码" type="password" value=${confirm} onInput=${setConfirm} minLength="8" maxLength="128" required=${true} />
              <button class="button button-primary button-lg button-full" type="submit" disabled=${busy}>${busy ? '创建中…' : '创建管理员'} ${icon('arrow', 17)}</button>
            </form>
            ${message ? html`<div class="form-message error" role="alert">${message}</div>` : null}
            <div class="auth-note">${icon('warning', 15)}恢复码只显示一次，请离线保存。</div>
          ` : html`
            <h2>保存恢复码</h2>
            <p class="auth-subtitle">账号已经创建。请在继续登录前，把以下恢复码保存到安全位置。</p>
            <div class="recovery-codes">${codes.map((code) => html`<code>${code}</code>`)}</div>
            <div class="code-actions"><button class="button button-secondary button-full" type="button" onClick=${copyCodes}>${icon('copy', 16)}${copied ? '已复制' : '复制全部恢复码'}</button><button class="button button-primary button-full" type="button" onClick=${() => onSetup('continue')}>前往登录 ${icon('arrow', 16)}</button></div>
            <div class="notice notice-warning">恢复码只会在本次初始化响应中返回。不要把它提交到仓库或聊天记录。</div>
          `}
        </div>
        <p class="auth-footer">仅生成合成遥测 · 不访问真实模型或网址</p>
      </main>
    </div>
  `
}


function AppShell({ route, onNavigate, onLogout, username, lastUpdated, children }) {
  const [mobileOpen, setMobileOpen] = useState(false)
  const current = NAV_ITEMS.some((item) => item.id === route) ? route : 'dashboard'
  const closeAndNavigate = (next) => { setMobileOpen(false); onNavigate(next) }
  const nav = html`<nav class="sidebar-nav" aria-label="主导航">${NAV_ITEMS.map((item) => html`<button class=${cn('nav-item', current === item.id && 'is-active')} type="button" onClick=${() => closeAndNavigate(item.id)}>${icon(item.icon, 17)}<span>${item.label}</span></button>`)}</nav>`
  return html`
    <div class="app-shell">
      <aside class=${cn('sidebar', mobileOpen && 'is-open')}>
        <div class="sidebar-brand"><span class="brand-mark">A</span><strong>AegisLure</strong><button class="sidebar-close icon-button" type="button" onClick=${() => setMobileOpen(false)} aria-label="关闭菜单">${icon('close', 18)}</button></div>
        ${nav}
      </aside>
      ${mobileOpen ? html`<div class="sidebar-scrim" onClick=${() => setMobileOpen(false)}></div>` : null}
      <main class="app-main">
        <header class="topbar">
          <div class="topbar-left"><button class="mobile-menu icon-button" type="button" onClick=${() => setMobileOpen(true)} aria-label="打开菜单">${icon('menu', 20)}</button><div class="breadcrumb"><span>AegisLure</span><i>/</i><b>${NAV_ITEMS.find((item) => item.id === current)?.label || '总览'}</b></div></div>
          <div class="topbar-right">${lastUpdated ? html`<span class="last-updated">更新于 ${formatTime(lastUpdated)}</span>` : null}<button class="topbar-icon icon-button" type="button" onClick=${() => onNavigate('settings')} aria-label="设置">${icon('user', 18)}</button><div class="user-chip"><span>${String(username || 'admin').slice(0, 1).toUpperCase()}</span><b>${username || 'admin'}</b></div><button class="topbar-icon icon-button" type="button" onClick=${onLogout} aria-label="退出登录">${icon('logout', 18)}</button></div>
        </header>
        <div class="content-wrap">${children}</div>
      </main>
    </div>
  `
}


function DashboardControlPage({ dashboard, instances, onNavigate, onRefresh, onOpenEvent, animationKey = 0 }) {
  if (!dashboard) return html`<${LoadingState} label="加载控制台数据…" />`
  const counts = dashboard.counts || {}
  const summary = dashboard.risk_summary || {}
  const recent = dashboard.recent_events || []
  const running = (instances || []).filter((item) => item.state === 'running').length
  const riskEvents = summary.event_count ?? counts.risk_events ?? 0
  const riskRate = summary.event_rate ?? counts.risk_rate ?? 0
  const geoProvider = geoSourceLabel((dashboard.source_countries || []).map((item) => item.geo_source).find(Boolean))
  return html`
    <div class="page-stack">
      <${PageHeader}
        title="观测总览"
        description="追踪蜜罐流量、风险触发与每一条可回溯的动作证据。"
        actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新数据<//>`}
      />
      <section class="metrics-panel" aria-label="关键指标">
        <div class="metrics-grid">
          <${MetricCard} label="总观测" value=${Number(counts.events || 0)} animationKey=${animationKey} detail=${`风险触发 ${formatNumber(riskEvents)} · ${riskRate}%`} />
          <${MetricCard} label="调用尝试" value=${Number(counts.invocations || 0)} animationKey=${animationKey} detail="全部响应均为合成" />
          <${MetricCard} label="高风险" value=${Number(counts.high_risk || 0)} animationKey=${animationKey} detail=${`唯一 IP ${formatNumber(counts.unique_ips)}`} />
          <${MetricCard} label="活跃实例" value=${running} suffix=${`/${(instances || []).length || 0}`} animationKey=${animationKey} detail="可从实例页控制" />
        </div>
      </section>
      <div class="dashboard-hero-grid">
        <${Panel} className="dashboard-trend-panel" title="风险触发趋势" action=${html`<span class="panel-meta">按小时 / 日滚动</span>`}>
          <${RiskActivityChart} key=${animationKey} series=${dashboard.risk_activity || {}} animationKey=${animationKey} />
        <//>
        <${Panel} className="dashboard-country-panel" title="风险 IP 来源区域" action=${html`<${Badge} tone="blue">${geoProvider}<//>`}>
          <${CountryDistribution} items=${dashboard.source_countries || []} />
        <//>
      </div>
      <div class="dashboard-analytics-grid">
        <${Panel} title="蜜罐触发占比"><${HoneypotDistribution} key=${animationKey} items=${dashboard.honeypot_distribution || []} animationKey=${animationKey} /><//>
        <${Panel} title="触发风险占比"><${DistributionDonut} key=${animationKey} items=${dashboard.risk_trigger_distribution || []} centerLabel="风险事件" animationKey=${animationKey} /><div class="panel-footnote">按事件风险分分档；中风险起算阈值为 ≥ ${dashboard.risk_threshold || 30}。</div><//>
        <${Panel} title="IP 风险分布"><${RiskDonut} key=${animationKey} distribution=${dashboard.risk_distribution || {}} animationKey=${animationKey} /><div class="panel-footnote">IP 维度聚合；风险分只表示观测证据，不等同于真实身份。</div><//>
      </div>
      <div class="dashboard-grid">
        <${Panel} className="span-7" title="最近观测" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('observations')}>查看全部 ${icon('arrow', 14)}</button>`} flush=${true}>
          ${recent.length ? html`<div class="event-feed">${recent.map((event) => html`<button class="event-feed-row" key=${event.event_id} type="button" onClick=${() => onOpenEvent(event)}><span class="feed-marker" aria-hidden="true"></span><span class="feed-main"><b>${rawRoute(event)}</b><small>${profileLabel(event.product)} · ${event.source_ip || 'unknown'} · ${formatTime(event.observed_at)}</small></span><${RiskBadge} score=${event.score} /><${Badge} tone=${event.status >= 400 ? 'danger' : 'success'}>${event.status || '—'}<//></button>`)}</div>` : html`<${EmptyState} title="还没有观测" description="访问任一公开蜜罐端点后，事件会出现在这里。" />`}
        <//>
        <${Panel} className="span-5" title="实例状态" action=${html`<button class="text-button" type="button" onClick=${() => onNavigate('instances')}>管理实例 ${icon('arrow', 14)}</button>`}>
          ${instances?.length ? html`<div class="fleet-list">${instances.slice(0, 5).map((instance) => html`<div class="fleet-row" key=${instance.product}><span class="fleet-mark">${profileLabel(instance.product).slice(0, 1)}</span><div><b>${profileLabel(instance.product)}</b><small>${instance.port ? `:${instance.port}` : '未配置端口'} · ${instance.scenario || 'default'}</small></div><${StatusBadge} state=${instance.state} /></div>`)}</div>` : html`<${EmptyState} title="实例数据不可用" />`}
        <//>
      </div>
    </div>
  `
}


function chainModeLabel(value) {
  if (value === 'source_ip_day') return '同一 IP · Asia/Shanghai 日'
  if (value === 'source_ip') return '同一来源 IP（跨会话）'
  if (value === 'source_ip_product') return '同一来源 IP + 蜜罐'
  return value === 'session' ? '同一会话' : value || '未配置'
}

function ServerObservationsPage({ events = [], pagination, onRefresh, onOpenEvent, onSearch, onPageChange, onDelete, loading = false }) {
  const [product, setProduct] = useState('')
  const [query, setQuery] = useState('')
  const [minScore, setMinScore] = useState('')
  const apply = () => onSearch({ page: 1, q: query, product, min_score: minScore })
  const reset = () => { setProduct(''); setQuery(''); setMinScore(''); onSearch({ page: 1, q: '', product: '', min_score: '' }) }
  const columns = [
    { label: '观测时间', render: (row) => html`<span class="table-time">${formatTime(row.observed_at)}</span>` },
    { label: '来源 IP', render: (row) => html`<code class="mono">${row.source_ip || '—'}</code>` },
    { label: '产品', render: (row) => html`<${Badge} tone="neutral">${profileLabel(row.product)}<//>` },
    { label: '展示路由', render: (row) => displayRouteCell(row) },
    { label: '状态', render: (row) => html`<${Badge} tone=${row.status >= 400 ? 'danger' : 'success'}>${row.status || '—'}<//>` },
    { label: '调用/拒绝', render: (row) => html`<span class="outcome-text">${row.rejection_reason ? rejectionReasonLabel(row.rejection_reason) : levelLabel(row.invocation_level)}</span>` },
    { label: '风险', className: 'align-right', render: (row) => html`<${RiskBadge} score=${row.score} />` },
    { label: '操作', className: 'align-right', render: (row) => html`<${DeleteButton} onClick=${() => onDelete(row.event_id)} />` },
  ]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Evidence stream" title="观测记录" description="检索每一条请求的完整原始请求、调用阶段与风险证据。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新记录<//>`} /><${Panel} className="table-panel" title="事件流" action=${html`<span class="panel-meta">每页 10 条 · 共 ${formatNumber(pagination?.total || 0)} 条</span>`}><${FilterBar} onReset=${reset}><label class="search-field">${icon('search', 17)}<input value=${query} onInput=${(event) => setQuery(event.target.value)} onKeyDown=${(event) => event.key === 'Enter' && apply()} placeholder="搜索 IP、原始路由、请求体或事件类型" /></label><${Select} value=${product} onChange=${setProduct} options=${[{ value: '', label: '全部产品' }, ...Object.entries(PROFILE_LABELS).map(([value, label]) => ({ value, label }))]} /><label class="score-filter"><span>最低风险</span><input type="number" min="0" max="100" value=${minScore} onInput=${(event) => setMinScore(event.target.value)} placeholder="0" /></label><${SearchButton} onClick=${apply} /></${FilterBar}><${DataTable} columns=${columns} rows=${events} onRowClick=${onOpenEvent} loading=${loading} loadingLabel="正在加载观测记录…" emptyTitle="没有匹配的观测" emptyDescription="尝试清除筛选条件，或等待新的蜜罐请求。" /><${PaginationControls} pagination=${pagination} onPageChange=${onPageChange} /><//><p class="page-note">新事件显示完整原始 URL、路径、Host、重复请求头和 Base64 请求体；旧事件会明确标记原始请求缺失。超限请求显示已保存前缀和截断原因。</p></div>`
}

function ServerInvocationsPage({ invocations = [], pagination, onRefresh, onOpenEvent, onSearch, onPageChange, onDelete, loading = false }) {
  const [query, setQuery] = useState('')
  const [level, setLevel] = useState('')
  const [auth, setAuth] = useState('')
  const [execution, setExecution] = useState('')
  const apply = () => onSearch({ page: 1, q: query, level, auth, execution })
  const reset = () => { setQuery(''); setLevel(''); setAuth(''); setExecution(''); onSearch({ page: 1, q: '', level: '', auth: '', execution: '' }) }
  const columns = [
    { label: '时间', render: (row) => html`<span class="table-time">${formatTime(row.observed_at)}</span>` },
    { label: '调用 ID', render: (row) => html`<code class="mono">${shortValue(row.invocation_id, 22)}</code>` },
    { label: '模型', render: (row) => html`<span class="route-cell">${row.model_id || '未解析'}</span>` },
    { label: '产品', render: (row) => html`<${Badge} tone="neutral">${profileLabel(row.product)}<//>` },
    { label: '鉴权', render: (row) => html`<span class="outcome-text">${row.auth_outcome || '—'}</span>` },
    { label: '执行', render: (row) => html`<span class=${cn('outcome-text', row.execution_outcome === 'rejected_before_dispatch' && 'text-danger')}>${row.execution_outcome || '—'}</span>` },
    { label: '拒绝原因', render: (row) => html`<span class="outcome-text">${rejectionReasonLabel(row.rejection_reason)}</span>` },
    { label: '阶段', render: (row) => html`<${Badge} tone=${row.invocation_level?.startsWith('L4') ? 'success' : row.invocation_level?.startsWith('L1') ? 'danger' : 'blue'}>${levelLabel(row.invocation_level)}<//>` },
    { label: '风险', className: 'align-right', render: (row) => html`<${RiskBadge} score=${row.score} />` },
    { label: '操作', className: 'align-right', render: (row) => html`<${DeleteButton} onClick=${() => onDelete(row.invocation_id)} />` },
  ]
  return html`<div class="page-stack"><${PageHeader} eyebrow="Synthetic execution trail" title="调用分析" description="查看每次模型调用尝试、鉴权结果、拒绝原因与合成执行阶段。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新调用<//>`} /><div class="callout callout-blue">${icon('spark', 18)}<div><b>合成执行边界</b><p>所有“已接受”调用只返回确定性的兼容响应，不会加载模型、执行 prompt 工具或连接供应商；成功和失败尝试都会提高风险分。</p></div></div><${Panel} className="table-panel" title="调用事件" action=${html`<span class="panel-meta">每页 10 条 · 共 ${formatNumber(pagination?.total || 0)} 条</span>`}><${FilterBar} onReset=${reset}><label class="search-field">${icon('search', 17)}<input value=${query} onInput=${(event) => setQuery(event.target.value)} onKeyDown=${(event) => event.key === 'Enter' && apply()} placeholder="搜索调用 ID、模型、IP 或拒绝原因" /></label><${Select} value=${level} onChange=${setLevel} options=${[{ value: '', label: '全部阶段' }, ...Object.entries(LEVEL_LABELS).map(([value, label]) => ({ value, label }))]} /><${Select} value=${auth} onChange=${setAuth} options=${[{ value: '', label: '全部鉴权' }, { value: 'valid_honey_key', label: '有效 honey key' }, { value: 'bypass_simulated', label: '模拟绕过' }, { value: 'missing', label: '缺失' }, { value: 'invalid', label: '无效' }]} /><${Select} value=${execution} onChange=${(event) => setExecution(event.target.value)} options=${[{ value: '', label: '全部执行结果' }, { value: 'synthetic_accepted', label: '合成已接受' }, { value: 'synthetic_stream_completed', label: '合成流完成' }, { value: 'rejected_before_dispatch', label: '派发前拒绝' }]} /><${SearchButton} onClick=${apply} /></${FilterBar}><${DataTable} columns=${columns} rows=${invocations} onRowClick=${onOpenEvent} loading=${loading} loadingLabel="正在加载调用记录…" emptyTitle="还没有调用事件" emptyDescription="蜜罐记录到调用请求后，分析结果会显示在这里。" /><${PaginationControls} pagination=${pagination} onPageChange=${onPageChange} /><//></div>`
}

function insightIdentityLabel(value) {
  if (value === 'account') return '账户跨 IP'
  if (value === 'key') return 'Key 跨 IP'
  if (value === 'detection') return '前端检测'
  return value || '洞察'
}

function insightFindingLabel(value) {
  if (value === 'dns_region') return 'DNS / 地区不一致'
  if (value === 'webrtc_ip') return 'WebRTC 暴露地址'
  return value || '一致性异常'
}

function ServerChainsPage({ chains = [], pagination, onRefresh, onOpenEvent, onSearch, onPageChange, onDelete, loading = false }) {
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState(null)
  chains = chains.map((item) => ({ ...item, events: (item.events || []).map(displayEventProjection) }))
  const apply = () => onSearch({ page: 1, q: query })
  const reset = () => { setQuery(''); onSearch({ page: 1, q: '' }) }
  return html`<div class="page-stack"><${PageHeader} eyebrow="Information intelligence" title="信息洞察" description="聚合账户或 API key 的创建与跨 IP 使用；同时记录成功登录后的地区一致性与 WebRTC 地址检测结果。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新洞察<//>`} /><div class="callout callout-blue">${icon('shield', 18)}<div><b>判定边界</b><p>只有“创建 IP”与“使用 IP”不同才生成跨 IP 洞察；New API root 账户组排除，但 root 创建的 key 仍保留。前端检测仅在设置中开启并且登录成功后运行。</p></div></div><${Panel} className="table-panel" title="洞察筛选" action=${html`<span class="panel-meta">每页 10 条 · 共 ${formatNumber(pagination?.total || 0)} 条</span>`}><${FilterBar} onReset=${reset}><label class="search-field">${icon('search', 17)}<input value=${query} onInput=${(event) => setQuery(event.target.value)} onKeyDown=${(event) => event.key === 'Enter' && apply()} placeholder="搜索账户 / key 指纹、IP、地区或检测类型" /></label><${SearchButton} onClick=${apply} /></${FilterBar}></${Panel}>${loading ? html`<${LoadingState} label="正在加载信息洞察…" />` : chains?.length ? html`<div class="chain-grid">${chains.map((item) => html`<article class="chain-card insight-card" key=${item.id}><header class="chain-card-header"><div class="chain-id"><span class="chain-mark">${icon(item.identity_type === 'detection' ? 'shield' : 'route', 17)}</span><div><b>${insightIdentityLabel(item.identity_type)}</b><small>${shortValue(item.subject_fingerprint, 24)}${item.related_account ? ` · 账户 ${shortValue(item.related_account, 14)}` : ''}</small></div></div><${RiskBadge} score=${item.score} /></header><div class="chain-meta"><span>${icon('clock', 14)}${item.event_count || 0} 个事件</span><span>${icon('clock', 14)}最近 ${formatTime(item.last_seen, true)}</span><${Badge} tone=${item.identity_type === 'detection' ? 'warning' : 'blue'}>${insightIdentityLabel(item.identity_type)}<//>${item.different_ip_count ? html`<${Badge} tone="danger">${item.different_ip_count} 个跨 IP 使用<//>` : null}</div>${item.identity_type !== 'detection' ? html`<div class="insight-ip-grid"><div><span>创建 IP</span><code>${(item.creation_ips || []).join(' · ') || '—'}</code></div><div><span>使用 IP</span><code>${(item.usage_ips || []).join(' · ') || '—'}</code></div></div>` : null}${item.detection_findings?.length ? html`<div class="insight-findings">${item.detection_findings.map((finding, index) => html`<div class="insight-finding" key=${finding.event_id || index}><${Badge} tone="warning">${insightFindingLabel(finding.kind)}<//><span>${finding.inferred_ip || finding.server_ip || '—'} · ${finding.inferred_region || finding.ip_region || '地区未知'}</span><small>访客 ${finding.visitor_region || '未知'} · ${finding.visitor_timezone || '时区未知'} · ${formatTime(finding.observed_at, true)}</small></div>`)}</div>` : null}<div class="chain-line">${(item.events || []).slice(-5).map((event, index, visible) => html`<button type="button" class="chain-event" onClick=${() => onOpenEvent(event)}><i class=${cn('chain-dot', event.score >= 60 && 'is-risk')}></i><span><b>${event.event_type || semanticRoute(event)}</b><small>${formatTime(event.observed_at)} · ${event.status || '—'} · ${rawRoute(event)}</small></span>${index === visible.length - 1 ? html`<em>latest</em>` : null}</button>`)}</div><div class="chain-card-actions"><button class="chain-expand" type="button" onClick=${() => setExpanded(expanded === item.id ? null : item.id)}>${expanded === item.id ? '收起详情' : '查看完整证据'} ${icon('chevron', 14)}</button><${DeleteButton} onClick=${() => onDelete(item.id)} /></div>${expanded === item.id ? html`<div class="chain-expanded"><pre class="json-view">${JSON.stringify(item, null, 2)}</pre></div>` : null}</article>`)}</div>` : html`<${Panel}><${EmptyState} icon="shield" title="还没有信息洞察" description="当同一账户或 key 在不同 IP 上出现创建与使用，或前端检测发现不一致时，这里会出现证据卡片。" /><//>`}<${PaginationControls} pagination=${pagination} onPageChange=${onPageChange} /></div>`
}

function ServerIndicatorsPage({ indicators = [], pagination, onRefresh, onOpenIndicator, onSearch, onPageChange, onDelete, loading = false }) {
  const [query, setQuery] = useState('')
  const [riskLevel, setRiskLevel] = useState('')
  const [sortMode, setSortMode] = useState('latest')
  const apply = () => onSearch({ page: 1, q: query, risk_level: riskLevel, sort: sortMode })
  const reset = () => { setQuery(''); setRiskLevel(''); setSortMode('latest'); onSearch({ page: 1, q: '', risk_level: '', sort: 'latest' }) }
  const exportIndicators = (format) => {
    const params = new URLSearchParams({ format, q: query, sort: sortMode })
    if (riskLevel) params.set('risk_level', riskLevel)
    const link = document.createElement('a'); link.href = `${apiPath('indicators')}?${params}`; link.download = `aegislure-indicators.${format}`; document.body.appendChild(link); link.click(); link.remove()
  }
  const columns = [
    { label: '来源 IP', render: (row) => html`<div class="indicator-ip-stack"><div><code class="mono ip-cell">${row.ip}</code>${row.associated ? html`<${Badge} tone="warning">已关联<//>` : null}</div>${row.associated ? html`<small class="geo-subcell">关联：${(row.associated_ips || []).join(' · ') || '—'}</small>` : null}</div>` },
    { label: '国家/地区', render: (row) => html`<span class="geo-cell">${row.country_zh || indicatorCountry(row)}</span><small class="geo-subcell">${row.country_code || '—'}</small>` },
    { label: '城市 / 地区', render: (row) => html`<span class="geo-cell">${indicatorPlace(row)}</span>` },
    { label: '网络 / ASN', render: (row) => html`<span class="geo-cell">${indicatorNetwork(row)}</span>` },
    { label: '来源', render: (row) => html`<span class="geo-cell">${geoSourceLabel(row.geo_source)}</span>` },
    { label: '风险分', render: (row) => html`<${RiskBadge} score=${row.score} />` },
    { label: '证据', render: (row) => html`<span>${formatNumber(row.evidence_count)} 次</span>` },
    { label: '最近出现', render: (row) => html`<span class="table-time">${formatTime(row.last_seen)}</span>` },
    { label: '操作', className: 'align-right', render: (row) => html`<${DeleteButton} onClick=${() => onDelete(row.id || row.ip)} />` },
  ]
  const selectedRiskLabel = INDICATOR_RISK_OPTIONS.find((option) => option.value === riskLevel)?.label || '全部风险'
  const selectedSortLabel = INDICATOR_SORT_OPTIONS.find((option) => option.value === sortMode)?.label || '最近出现优先'
  return html`<div class="page-stack"><${PageHeader} eyebrow="Risk intelligence" title="IP 情报" description="默认按最近出现时间排序；也可切换为风险分从高到低，并按低、中、高风险区间筛选。" actions=${html`<div class="button-group"><${Button} icon="download" size="sm" onClick=${() => exportIndicators('csv')}>导出 CSV<//><${Button} icon="refresh" size="sm" onClick=${onRefresh}>刷新<//></div>`} /><${Panel} className="table-panel" title="指标列表" action=${html`<span class="panel-meta">每页 10 条 · 共 ${formatNumber(pagination?.total || 0)} 个指标</span>`}><${FilterBar} onReset=${reset}><label class="search-field">${icon('search', 17)}<input value=${query} onInput=${(event) => setQuery(event.target.value)} onKeyDown=${(event) => event.key === 'Enter' && apply()} placeholder="搜索 IP（完整或部分）" /></label><${Select} label="风险等级" value=${riskLevel} onChange=${setRiskLevel} options=${INDICATOR_RISK_OPTIONS} /><${Select} label="排序方式" value=${sortMode} onChange=${setSortMode} options=${INDICATOR_SORT_OPTIONS} /><${SearchButton} onClick=${apply} /><//><div class="indicator-tools"><div class="indicator-order-note"><span>筛选：${selectedRiskLabel}</span><span>排序：${selectedSortLabel}</span></div><div class="button-group"><button class="outline-button" type="button" onClick=${() => exportIndicators('plain')}>导出纯文本</button><button class="outline-button" type="button" onClick=${() => exportIndicators('csv')}>下载 CSV</button></div></div><${DataTable} columns=${columns} rows=${indicators} onRowClick=${onOpenIndicator} loading=${loading} loadingLabel="正在加载 IP 指标…" emptyTitle="还没有 IP 指标" emptyDescription="当观测到公开蜜罐端点请求后，风险聚合会出现在这里。" /><${PaginationControls} pagination=${pagination} onPageChange=${onPageChange} /><//><p class="page-note">地理信息由当前 GeoIP provider 查询；provider 切换后会重新查询历史 IP。删除 IP 只写入事件 tombstone，不修改权威原始事件。</p></div>`
}

function InstanceCard({ instance, busy, onAction }) {
  const running = instance.state === 'running'
  return html`<article class=${cn('instance-card', running && 'is-running')}><div class="instance-card-head"><div class="instance-logo">${profileLabel(instance.product).slice(0, 1)}</div><div class="instance-title"><div><h3>${profileLabel(instance.product)}</h3><${StatusBadge} state=${instance.state} /></div><p>${instance.profile_id || 'profile'} · ${instance.version || 'version unknown'}</p></div><${Toggle} checked=${running} label=${`${profileLabel(instance.product)} 开关`} onChange=${(next) => onAction(instance, next ? 'start' : 'stop')} /></div><div class="instance-details"><div><span>监听端口</span><b>${instance.port || '—'}</b></div><div><span>场景</span><b>${instance.scenario || 'default'}</b></div><div><span>端点</span><code>${instance.endpoint || '—'}</code></div></div><div class="instance-card-foot"><span>${instance.synthetic_only ? html`<span class="instance-boundary">安全合成边界</span>` : '—'}</span><div class="button-group"><${Button} size="sm" variant="ghost" icon="refresh" onClick=${() => onAction(instance, 'restart')} disabled=${busy}>重启<//>${running ? html`<${Button} size="sm" variant="danger-ghost" icon="pause" onClick=${() => onAction(instance, 'stop')} disabled=${busy}>停止<//>` : html`<${Button} size="sm" variant="primary-soft" icon="play" onClick=${() => onAction(instance, 'start')} disabled=${busy}>启动<//>`}</div></div></article>`
}


function InstancesPage({ instances, onRefresh, onAction, busy }) {
  const running = (instances || []).filter((item) => item.state === 'running').length
  return html`
    <div class="page-stack">
      <${PageHeader} title="蜜罐实例" description="按协议启停公开端点，所有实例都保持在安全的合成响应边界内。" actions=${html`<div class="button-group"><${Button} variant="secondary" icon="play" onClick=${() => onAction({ product: '__all__' }, 'start-all')} disabled=${busy}>启动全部<//><${Button} icon="refresh" onClick=${onRefresh}>刷新状态<//></div>`} />
      <section class="fleet-summary" aria-label="实例摘要"><div class="fleet-summary-item"><span>运行实例</span><strong>${running} / ${(instances || []).length}</strong></div><div class="fleet-summary-item"><span>协议</span><strong>HTTP</strong></div><div class="fleet-summary-item"><span>上游访问</span><strong>已隔离</strong></div></section>
      <div class="instance-grid">${instances?.map((instance) => html`<${InstanceCard} instance=${instance} busy=${busy} onAction=${onAction} />`)}</div>
      <p class="page-note">停止实例会关闭对应公开监听器并更新运行配置；管理端与公开监听器彼此独立。</p>
    </div>
  `
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
  if (rule.references?.length) conditions.push(`参考：${rule.references.join(' · ')}`)
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
    references: (rule?.references || []).join('\n'),
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
  const references = ruleLines(form.references)
  if (references.length) result.references = references
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
  return html`<${Modal} title=${editing ? '编辑规则' : '新增规则'} eyebrow="Detector rule CRUD" onClose=${onClose} wide=${true}><form class="stack-form" onSubmit=${submit}><div class="rule-form-grid"><${TextInput} label="规则 ID" placeholder="例如 CUSTOM_ROUTE_V1" value=${form.id} onInput=${(value) => update('id', value)} maxLength="128" disabled=${editing} required=${true} /><label class="select-field"><span>规则类型</span><select value=${form.type} onChange=${(event) => update('type', event.target.value)}><option value="atomic">atomic · 单事件</option><option value="sequence">sequence · 事件序列</option><option value="threshold">threshold · 阈值</option><option value="credential_reuse">credential_reuse · 凭据复用</option><option value="campaign">campaign · 活动关联</option></select></label><${TextInput} label="命中原因" placeholder="例如 suspicious_route_probe" value=${form.reason_code} onInput=${(value) => update('reason_code', value)} maxLength="128" required=${true} /><${TextInput} label="风险分" type="number" min="0" max="100" value=${form.score} onInput=${(value) => update('score', value)} required=${true} /><label class="select-field"><span>置信度</span><select value=${form.confidence} onChange=${(event) => update('confidence', event.target.value)}><option value="low">low · 低</option><option value="medium">medium · 中</option><option value="high">high · 高</option></select></label><${TextInput} label="时间窗口（可选）" placeholder="例如 10m 或 1h" value=${form.within} onInput=${(value) => update('within', value)} maxLength="32" /></div><div class="rule-form-grid"><label class="text-field rule-form-wide"><span>事件步骤（每行一个，仅 sequence 使用）</span><textarea rows="5" value=${form.steps} onInput=${(event) => update('steps', event.target.value)} placeholder="newapi.user.login.success\nllm.invoke.accepted"></textarea></label><label class="text-field rule-form-wide"><span>URL 分类（每行一个，可选）</span><textarea rows="5" value=${form.url_classes} onInput=${(event) => update('url_classes', event.target.value)} placeholder="loopback\nprivate"></textarea></label>${form.type === 'sequence' ? html`<label class="select-field"><span>序列匹配</span><select value=${form.sequence_mode} onChange=${(event) => update('sequence_mode', event.target.value)}><option value="ordered">ordered · 有序</option><option value="unordered">unordered · 无序</option></select></label>` : null}</div><div class="rule-form-grid"><label class="text-field rule-form-wide"><span>字段 / 正则配置（JSON，可选）</span><textarea rows="8" value=${form.where} onInput=${(event) => update('where', event.target.value)} placeholder='{"field":"route_template","op":"eq","value":"ollama.home"}'></textarea></label><label class="text-field rule-form-wide"><span>参考编号（每行一个，可选）</span><textarea rows="4" value=${form.references} onInput=${(event) => update('references', event.target.value)} placeholder="GHSA-xxxx\nCVE-2026-xxxx"></textarea></label></div><div class="button-group"><button class="button button-primary" type="submit" disabled=${busy}>${busy ? '保存中…' : editing ? '保存修改' : '新增规则'}</button><button class="button button-secondary" type="button" onClick=${onClose} disabled=${busy}>取消</button></div>${message ? html`<div class="form-message error">${message}</div>` : null}</form><p class="modal-copy">规则会先保存为 Draft revision；完成验证并点击“启用规则”后，才会替换当前运行中的规则。</p><//>`
}

function PacksPage({ packs, policies, onRefresh }) {
  const revisions = packs ? [['Fingerprint pack', packs.fingerprint_revision, '来源指纹与协议特征'], ['Model catalog', packs.model_catalog_revision, '安全模型目录与别名'], ['Scenario pack', packs.scenario_revision, '场景与响应契约'], ['Detector rules', packs.detector_revision, '风险检测规则']] : []
  const aggregation = packs?.chain_aggregation || { mode: 'source_ip_day', window_seconds: 86400, max_events: 200 }
  const [mode, setMode] = useState(aggregation.mode || 'source_ip_day')
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
  const [rulePage, setRulePage] = useState(1)
  const [ruleQuery, setRuleQuery] = useState('')
  const [policyBusy, setPolicyBusy] = useState('')
  const [policyMessage, setPolicyMessage] = useState('')
  const [policyMessageError, setPolicyMessageError] = useState(false)
  const strategies = packs?.strategies || []
  const identityPolicies = [...(policies?.providers || []), ...(policies?.sub2api_providers || [])].filter((policy, index, values) => values.findIndex((item) => item.provider === policy.provider) === index)
  const selected = strategies.find((item) => item.product === selectedProduct) || strategies[0]
  const selectedPackID = selected?.rule_pack?.id || ''
  useEffect(() => {
    setMode(aggregation.mode || 'source_ip_day')
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
    const query = new URLSearchParams({ page: String(rulePage), page_size: '10' })
    if (ruleQuery) query.set('q', ruleQuery)
    request(`rule-packs/${encodeURIComponent(selectedPackID)}/rules?${query}`).then((result) => {
      if (active) setRuleState(result)
    }).catch((error) => {
      if (active) { setRuleState(null); setRuleMessage(error.message || '规则读取失败。'); setRuleMessageError(true) }
    }).finally(() => { if (active) setRulesLoading(false) })
    return () => { active = false }
  }, [selectedPackID, rulePage, ruleQuery])
  useEffect(() => { setRulePage(1); setRuleQuery('') }, [selectedPackID])
  const saveAggregation = async () => {
    setSaving(true); setMessage('')
    try {
      await request('chain-config', { method: 'PUT', body: JSON.stringify({ mode, window_seconds: Number(windowSeconds), max_events: Number(maxEvents) }) })
      setMessage('交互链路聚合配置已保存。'); await onRefresh()
    } catch (error) { setMessage(error.message || '配置保存失败。') } finally { setSaving(false) }
  }
  const refreshRules = async () => {
    if (!selectedPackID) return null
    const query = new URLSearchParams({ page: String(rulePage), page_size: '10' })
    if (ruleQuery) query.set('q', ruleQuery)
    const result = await request(`rule-packs/${encodeURIComponent(selectedPackID)}/rules?${query}`)
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
      const result = await refreshRules(); if (rulePage > 1 && result && (result.rules || []).length === 0 && Number(result.total || 0) > 0) setRulePage((page) => page - 1); await onRefresh(); setRuleMessage(`规则 ${rule.id} 已删除，当前为 Draft revision。`)
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
  return html`<div class="page-stack"><${PageHeader} eyebrow="Configuration registry" title="规则与策略" description="查看每个蜜罐当前生效的策略、规则和请求匹配条件；规则支持新增、编辑、删除，修改会先进入 Draft revision。" actions=${html`<${Button} icon="refresh" onClick=${onRefresh}>刷新配置<//>`} /><div class="pack-grid">${revisions.map((revision) => html`<article class="pack-card"><div class="pack-icon">${icon('layers', 19)}</div><div><p>${revision[0]}</p><h3>${revision[1] || 'unknown'}</h3><small>${revision[2]}</small></div><${Badge} tone="success">Active<//></article>`)}</div><${Panel} eyebrow="Interaction aggregation" title="交互链路聚合方式"><div class="config-form"><label class="select-field"><span>聚合键</span><select value=${mode} onChange=${(event) => setMode(event.target.value)}>${(packs?.allowed_chain_modes || ['source_ip_day', 'session', 'source_ip', 'source_ip_product']).map((value) => html`<option value=${value}>${chainModeLabel(value)}</option>`)}</select></label><label class="config-field"><span>时间窗口（秒）</span><input type="number" min="60" max="86400" value=${windowSeconds} onInput=${(event) => setWindowSeconds(event.target.value)} /></label><label class="config-field"><span>最多事件数</span><input type="number" min="10" max="1000" value=${maxEvents} onInput=${(event) => setMaxEvents(event.target.value)} /></label><button class="button button-primary" type="button" onClick=${saveAggregation} disabled=${saving}>${saving ? '保存中…' : '保存聚合配置'}</button></div>${message ? html`<div class="form-message ${message.includes('失败') ? 'error' : 'success'}">${message}</div>` : null}<p class="panel-footnote">默认按 Asia/Shanghai 自然日聚合同一 IP，跨会话与蜜罐合并；午夜自动切分。窗口和数量上限均由后端校验。</p><//><${Panel} eyebrow="Honeypot strategy matrix" title="各蜜罐当前策略"><div class="strategy-grid">${strategies.map((strategy) => html`<article class=${cn('strategy-card', selected?.product === strategy.product && 'is-selected')}><div class="strategy-card-head"><div><${Badge} tone="blue">${profileLabel(strategy.product)}<//><h3>${strategy.scenario || 'default'}</h3><small>${strategy.profile_id || 'profile'} · ${strategy.version || 'version unknown'}</small></div><strong>${formatNumber(strategy.product === selected?.product && ruleState?.pack_id === selectedPackID ? ruleState?.total || rules.length : strategy.rule_count || 0)} 条规则</strong></div><div class="strategy-pack-list">${strategyPackSummary(strategy).map((item) => html`<code>${item}</code>`)}</div><button class="outline-button" type="button" onClick=${() => setSelectedProduct(strategy.product)}>编辑规则</button></article>`)}</div><//><${Panel} eyebrow="Detector rules" title=${selected ? `${profileLabel(selected.product)} · 请求匹配规则` : '请求匹配规则'} action=${strategies.length ? html`<div class="button-group"><label class="select-field inline-select"><span>蜜罐</span><select value=${selected?.product || ''} onChange=${(event) => setSelectedProduct(event.target.value)}>${strategies.map((strategy) => html`<option value=${strategy.product}>${profileLabel(strategy.product)}</option>`)}</select></label>${selectedPackID ? html`<${Button} variant="primary" size="sm" icon="plus" onClick=${() => { setRuleMessage(''); setRuleMessageError(false); setEditor({ mode: 'create', rule: null }) }} disabled=${ruleBusy}>新增规则<//>` : null}</div>` : null}>${selectedPackID ? html`<div class="rule-pack-toolbar"><span>规则包 <code>${selectedPackID}</code> · <code>${ruleRevision || 'unknown revision'}</code></span><${Badge} tone=${ruleLifecycle === 'Active' ? 'success' : 'warning'}>${ruleLifecycle || 'Unknown'}<//><small>修改后先验证，再启用；Draft 不会立即替换运行中的规则。</small></div><${FilterBar} onReset=${() => { setRuleQuery(''); setRulePage(1) }}><label class="search-field">${icon('search', 17)}<input value=${ruleQuery} onInput=${(event) => { setRuleQuery(event.target.value); setRulePage(1) }} onKeyDown=${(event) => event.key === 'Enter' && setRulePage(1)} placeholder="搜索规则 ID、原因码或匹配字段" /></label><${SearchButton} onClick=${() => setRulePage(1)} /></${FilterBar}>` : null}${ruleMessage ? html`<div class=${cn('form-message', ruleMessageError && 'error', !ruleMessageError && 'success')}>${ruleMessage}</div>` : null}${rulesLoading ? html`<${LoadingState} label="加载规则…" />` : rules.length ? html`<div class="rule-list">${rules.map((rule) => html`<article class="rule-card" key=${rule.id}><div class="rule-card-head"><div><code>${rule.id}</code><h3>${rule.reason_code}</h3></div><div class="rule-badges"><${Badge} tone="blue">${rule.type}<//><${Badge} tone=${rule.confidence === 'high' ? 'danger' : 'warning'}>${rule.score} 分<//></div></div><p class="rule-summary">${ruleMatchSummary(rule)}</p>${rule.within ? html`<small class="rule-window">窗口：${rule.within}</small>` : null}${rule.where ? html`<details class="rule-detail"><summary>查看字段 / 正则配置</summary><pre class="data-view">${JSON.stringify(rule.where, null, 2)}</pre></details>` : null}<div class="rule-card-actions"><button class="outline-button" type="button" onClick=${() => { setRuleMessage(''); setRuleMessageError(false); setEditor({ mode: 'edit', rule }) }} disabled=${ruleBusy}>编辑</button><button class="text-button rule-delete" type="button" onClick=${() => deleteRule(rule)} disabled=${ruleBusy}>删除</button></div></article>`)}</div>` : html`<${EmptyState} title="当前没有可展示的规则" description="该蜜罐没有解析到 detector pack。" />`}${selectedPackID ? html`<${PaginationControls} pagination=${ruleState?.pagination || ruleState} onPageChange=${setRulePage} />` : null}${selectedPackID && ruleLifecycle !== 'Active' ? html`<div class="rule-lifecycle-actions"><span>当前 revision 尚未生效</span><div class="button-group"><${Button} size="sm" variant="secondary" onClick=${() => runRulePackAction('validate')} disabled=${ruleBusy}>验证规则<//><${Button} size="sm" variant="primary" onClick=${() => runRulePackAction('activate')} disabled=${ruleBusy}>启用规则<//></div></div>` : null}<//><${Panel} eyebrow="Identity posture" title="身份策略"><div class="policy-table"><div class="policy-row policy-head"><span>Provider</span><span>Mode</span><span>跨站状态</span><span>状态</span><span>注册页</span></div>${identityPolicies.map((policy) => html`<div class="policy-row"><b>${policy.provider}</b><span>${policy.mode}</span><span>${policy.cross_site}</span><${Badge} tone=${policy.cross_site === 'blocked' || policy.cross_site === 'disabled_by_default' ? 'success' : 'warning'}>${policy.enabled ? '已开启' : '已关闭'}<//><${Toggle} checked=${Boolean(policy.enabled)} onChange=${() => togglePolicy(policy)} disabled=${policyBusy !== ''} label=${`切换 ${policy.provider} 注册页入口`} /></div>`)}</div>${policyMessage ? html`<div class=${cn('form-message', policyMessageError && 'error', !policyMessageError && 'success')}>${policyMessage}</div>` : null}<//></div>${editor ? html`<${RuleEditorModal} rule=${editor.rule} editing=${editor.mode === 'edit'} busy=${ruleBusy} onClose=${() => setEditor(null)} onSave=${saveRule} />` : null}`
}

function SettingsPage({ username, ipinfo, frontendDetection, onRotateEntry, onSaveIPInfo, onSaveFrontendDetection }) {
  const [provider, setProvider] = useState(ipinfo?.provider || 'maxmind')
  const [token, setToken] = useState('')
  const [message, setMessage] = useState('')
  const [messageTone, setMessageTone] = useState('success')
  const [busy, setBusy] = useState(false)
  const [detectionBusy, setDetectionBusy] = useState('')
  const [detectionMessage, setDetectionMessage] = useState('')
  const configured = Boolean(ipinfo?.configured)
  const ipinfoConfigured = Boolean(ipinfo?.ipinfo_configured)
  const maxmind = ipinfo?.maxmind || {}
  const ipinfoMMDB = ipinfo?.ipinfo_mmdb || {}
  const isIPInfoAPI = provider === 'ipinfo_api' || provider === 'ipinfo_lite'
  const apiProviderName = provider === 'ipinfo_api' ? 'IPinfo API' : 'IPinfo Lite'
  const isIPInfoMMDB = provider === 'ipinfo_mmdb'
  const detectionConfig = frontendDetection?.config || frontendDetection || {}
  useEffect(() => { if (ipinfo?.provider) setProvider(ipinfo.provider) }, [ipinfo?.provider])
  const rotate = () => { if (window.confirm('轮换后当前管理入口会立即失效，需要从配置或启动输出获取新路径。继续吗？')) onRotateEntry() }
  const updateDetection = async (field, value) => {
    const next = { dns_leak_detection: Boolean(detectionConfig.dns_leak_detection), webrtc_ip_detection: Boolean(detectionConfig.webrtc_ip_detection), [field]: Boolean(value) }
    setDetectionBusy(field); setDetectionMessage('')
    try { await onSaveFrontendDetection(next); setDetectionMessage('设置已保存。') } catch (error) { setDetectionMessage(error.message || '前端检测设置保存失败。') } finally { setDetectionBusy('') }
  }
  const save = async (nextProvider = provider, nextToken = token, includeToken = false) => {
    setBusy(true); setMessage(''); setMessageTone('success')
    try {
      await onSaveIPInfo(nextProvider, nextToken, includeToken)
      setToken('')
      setMessage(nextProvider === 'maxmind' ? (maxmind.ready ? 'MaxMind GeoLite2 已启用。' : '已切换到 MaxMind；请先放置 City 与 ASN 数据库。') : nextProvider === 'ipinfo_mmdb' ? (ipinfoMMDB.ready ? 'IPinfo MMDB 已启用。' : '已切换到 IPinfo MMDB；请先放置 Location 与 ASN 数据库。') : (includeToken ? `${apiProviderName} key 已保存；完整 key 不会回显。` : ipinfoConfigured ? `${apiProviderName} 已保持启用。` : `已选择 ${apiProviderName}；请输入 key 后启用。`))
    } catch (error) {
      setMessage(error.message || '地理情报设置保存失败。'); setMessageTone('error')
    } finally { setBusy(false) }
  }
  const providerOptions = (ipinfo?.available_providers || [{ id: 'maxmind', label: 'MaxMind GeoLite2 City + ASN' }, { id: 'ipinfo_api', label: 'IPinfo API（City + ASN）' }, { id: 'ipinfo_lite', label: 'IPinfo Lite API' }, { id: 'ipinfo_mmdb', label: 'IPinfo Location + ASN MMDB' }]).map((item) => ({ value: item.id, label: item.label }))
  const statusTone = configured ? 'success' : 'warning'
  const databaseCard = (title, locationLabel, locationAvailable, locationFile, asnAvailable, asnFile, description, linkLabel, linkURL) => html`<div class="geoip-provider-panel"><h4>${title}</h4><div class="geoip-status-grid"><div><span>${locationLabel}</span><b class=${locationAvailable ? 'is-ready' : 'is-missing'}>${locationAvailable ? '可用' : '未找到'}</b><small>${locationFile || 'ipinfo_location.mmdb'}</small></div><div><span>ASN 数据库</span><b class=${asnAvailable ? 'is-ready' : 'is-missing'}>${asnAvailable ? '可用' : '未找到'}</b><small>${asnFile || 'ipinfo_asn.mmdb'}</small></div></div><p class="panel-footnote">${description}</p><p class="panel-footnote">数据获取与许可说明见 <a href=${linkURL} target="_blank" rel="noreferrer">${linkLabel}</a>。</p></div>`
  const providerPanel = isIPInfoAPI ? html`<div class="geoip-provider-panel"><${TextInput} label=${provider === 'ipinfo_api' ? 'IPinfo API Token / Key' : 'IPinfo Lite Token / Key'} type="password" value=${token} onInput=${setToken} placeholder=${ipinfoConfigured ? `当前已配置（${ipinfo?.masked_token || '已隐藏'}），输入新 key 可替换` : '粘贴 IPinfo token（不会返回原文）'} autoComplete="new-password" maxLength=${256} /><div class="ipinfo-facts"><span>接口</span><code>${ipinfo?.endpoint || (provider === 'ipinfo_api' ? 'https://ipinfo.io/{ip}' : 'https://api.ipinfo.io/lite/{ip}')}</code><span>超时 / 成功缓存</span><b>${ipinfo?.timeout_seconds || 2}s / ${Math.round((ipinfo?.cache_ttl_seconds || 86400) / 3600)}h</b><span>失败缓存 / 单次首页上限</span><b>${Math.round((ipinfo?.failure_cache_ttl_seconds || 300) / 60)}min / ${ipinfo?.dashboard_lookup_limit || 128} 个 IP</b></div><p class="panel-footnote">key 只提交到后端，浏览器不会读取或回显完整 token；查询数据来自 <a href=${provider === 'ipinfo_api' ? 'https://ipinfo.io/developers/ip-to-geolocation-database' : 'https://ipinfo.io/lite'} target="_blank" rel="noreferrer">${provider === 'ipinfo_api' ? 'IPinfo IP Geolocation API' : 'IPinfo Lite'}</a>。</p></div>` : isIPInfoMMDB ? databaseCard('IPinfo 离线数据库', 'Location 数据库', ipinfoMMDB.location_available, ipinfoMMDB.location_file, ipinfoMMDB.asn_available, ipinfoMMDB.asn_file, '将 IPinfo 的 ipinfo_location.mmdb 与 ipinfo_asn.mmdb 放入数据目录的 geoip 子目录；更新文件后重启服务。', 'IPinfo Database Downloads', 'https://ipinfo.io/developers/database-download') : databaseCard('MaxMind 离线数据库', 'City 数据库', maxmind.city_available, maxmind.city_file, maxmind.asn_available, maxmind.asn_file, '将官方 GeoLite2 City 与 ASN 文件放入数据目录的 geoip 子目录；更新文件后重启服务。', 'MaxMind GeoLite2', 'https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/')
  return html`<div class="page-stack"><${PageHeader} eyebrow="Workspace settings" title="管理设置" description="管理离线恢复凭据、管理端入口、IP 地理情报来源和登录后的前端检测。" /><div class="settings-grid"><${Panel} eyebrow="Account security" title="离线恢复" className="settings-form-panel"><div class="security-card"><div class="security-card-icon">${icon('key', 22)}</div><h3>${username || 'owner'} · 恢复凭据</h3><p>管理端不提供在线改密。请使用一次性 recovery code，或在服务器本机通过 hpctl 生成 rescue code 后完成恢复。</p><span class="instance-boundary">恢复码成功使用后立即失效</span></div><//><${Panel} eyebrow="Admin endpoint" title="管理入口"><div class="security-card"><div class="security-card-icon">${icon('key', 22)}</div><h3>随机隐藏路径</h3><p>当前入口路径不会在 API 响应中返回。轮换后会使现有管理会话失效，页面会跳转到新的入口。</p><button class="button button-danger-soft button-full" type="button" onClick=${rotate}>${icon('refresh', 16)}轮换管理入口</button></div><//><${Panel} eyebrow="IP intelligence" title="IP 地理情报" className="settings-form-panel"><div class="security-card ipinfo-settings-card"><div class="settings-card-heading"><div class="security-card-icon">${icon('globe', 22)}</div><${Badge} tone=${statusTone}>${configured ? '已就绪' : '未就绪'}<//></div><h3>选择公网 IP 查询来源</h3><p>本地、保留和文档地址始终直接离线识别；公网地址优先使用当前 provider，数据库/API 不可用时回退为“未知”。切换 provider 后下一次总览刷新会自动重新查询。</p><${Select} label="查询 provider" value=${provider} onChange=${setProvider} options=${providerOptions} /><div class="button-group geoip-save-row"><${Button} variant="primary" size="sm" onClick=${() => save(provider, token, isIPInfoAPI && Boolean(token.trim()))} disabled=${busy || (isIPInfoAPI && !token.trim() && !ipinfoConfigured)}>${busy ? '保存中…' : '保存查询设置'}<//>${isIPInfoAPI && ipinfoConfigured ? html`<${Button} variant="ghost" size="sm" onClick=${() => save('ipinfo_lite', '', true)} disabled=${busy}>清除并停用 key<//>` : null}</div>${providerPanel}${message ? html`<div class=${cn('form-message', messageTone === 'error' && 'error', messageTone !== 'error' && 'success')}>${message}</div>` : null}</div><//><${Panel} eyebrow="Frontend detection" title="登录后前端检测" className="settings-form-panel"><div class="security-card"><div class="settings-card-heading"><div class="security-card-icon">${icon('shield', 22)}</div><${Badge} tone=${detectionConfig.dns_leak_detection || detectionConfig.webrtc_ip_detection ? 'success' : 'neutral'}>${detectionConfig.dns_leak_detection || detectionConfig.webrtc_ip_detection ? '已开启' : '未开启'}<//></div><p>仅在 New API / Sub2API 前端成功登录后执行。检测使用浏览器语言、时区与服务端 GeoIP 比对地区一致性；WebRTC 只上报候选 IP，不采集凭据或页面内容。</p><div class="boundary-list"><div><${Toggle} checked=${Boolean(detectionConfig.dns_leak_detection)} onChange=${(next) => updateDetection('dns_leak_detection', next)} disabled=${detectionBusy !== ''} label="切换 DNS / 地区一致性检测" /><span><b>DNS / 地区一致性</b><small>发现访客地区与来源 IP 地区不一致时记录推断 IP / 地区。</small></span></div><div><${Toggle} checked=${Boolean(detectionConfig.webrtc_ip_detection)} onChange=${(next) => updateDetection('webrtc_ip_detection', next)} disabled=${detectionBusy !== ''} label="切换 WebRTC IP 检测" /><span><b>WebRTC 实际 IP</b><small>发现 WebRTC 候选地址与请求来源不同时时记录候选 IP / GeoIP。</small></span></div></div>${detectionMessage ? html`<div class="form-message ${detectionMessage.includes('失败') ? 'error' : 'success'}">${detectionMessage}</div>` : null}</div><//><${Panel} eyebrow="Data boundary" title="运行边界" className="settings-note-panel"><div class="boundary-list"><div>${icon('shield', 17)}<span><b>事件流受保留策略限制</b><small>SQLite 是权威记录，JSONL 镜像会按保留天数与条数清理。</small></span></div><div>${icon('lock', 17)}<span><b>敏感字段脱敏</b><small>凭据、密码和 token 只保留 keyed fingerprint。</small></span></div><div>${icon('spark', 17)}<span><b>合成响应</b><small>不会运行模型、访问 URL 或连接供应商。</small></span></div></div><//></div></div>`
}

function Toast({ toast, onClose }) {
  if (!toast) return null
  return html`<div class=${cn('toast', toast.tone === 'error' && 'toast-error')} role="status">${icon(toast.tone === 'error' ? 'warning' : 'check', 17)}<span>${toast.message}</span><button class="icon-button" type="button" onClick=${onClose} aria-label="关闭提示">${icon('close', 15)}</button></div>`
}

function AuthLoading() { return html`<div class="auth-loading"><span class="brand-mark">A</span><span class="spinner"></span><p>正在连接 AegisLure 控制平面…</p></div>` }

const ObservationsPage = ServerObservationsPage
const InvocationsPage = ServerInvocationsPage
const ChainsPage = ServerChainsPage
const IndicatorsPage = ServerIndicatorsPage

function App() {
  const [route, setRoute] = useState(routeFromLocation()); const [auth, setAuth] = useState('checking'); const [username, setUsername] = useState(''); const [lastUpdated, setLastUpdated] = useState(null); const [busy, setBusy] = useState(false); const [loadError, setLoadError] = useState(''); const [toast, setToast] = useState(null); const [selectedEvent, setSelectedEvent] = useState(null); const [selectedActor, setSelectedActor] = useState(null); const [data, setData] = useState({ dashboard: null, instances: [], events: [], invocations: [], chains: [], indicators: [], packs: null, policies: null, ipinfo: null, frontendDetection: null, pagination: { observations: null, invocations: null, chains: null, indicators: null } })
  const [dashboardAnimationKey, setDashboardAnimationKey] = useState(0)
  const [, setListParams] = useState(LIST_DEFAULTS)
  const listParamsRef = useRef(LIST_DEFAULTS)
  const routeRequestsRef = useRef(new Map())
  const listLoadingRef = useRef(null)
  const [listLoading, setListLoading] = useState(null)
  const busyRequestRef = useRef(null)
  const detailRequestRef = useRef(null)
  const showToast = useCallback((message, tone = 'success') => { setToast({ message, tone }); window.setTimeout(() => setToast(null), 4200) }, [])
  const onNavigate = useCallback((next) => { setLoadError(''); navigateTo(next) }, [])
  const beginDetailRequest = useCallback(() => {
    detailRequestRef.current?.controller?.abort()
    const requestState = { controller: new AbortController(), version: Date.now() + Math.random() }
    detailRequestRef.current = requestState
    return requestState
  }, [])
  const isCurrentDetailRequest = useCallback((requestState) => detailRequestRef.current === requestState, [])
  const openEvent = useCallback(async (event) => {
    const eventID = event?.event_id || event?.id || ''
    if (!eventID) return
    const requestState = beginDetailRequest()
    setSelectedEvent({ ...event, loading: true })
    try {
      const result = await request(`events/${encodeURIComponent(eventID)}`, { signal: requestState.controller.signal })
      if (!isCurrentDetailRequest(requestState)) return
      setSelectedEvent(result?.event || result)
    } catch (error) {
      if (isAbortError(error) || !isCurrentDetailRequest(requestState)) return
      setSelectedEvent(null)
      showToast(error.message || '事件详情读取失败', 'error')
    }
  }, [beginDetailRequest, isCurrentDetailRequest, showToast])
  const openActor = useCallback(async (indicator) => {
    const ip = indicator?.ip || ''
    if (!ip) return
    const requestState = beginDetailRequest()
    setSelectedActor({ ip, loading: true })
    try {
      const result = await request(`actors/${encodeURIComponent(ip)}?projection=summary`, { signal: requestState.controller.signal })
      if (!isCurrentDetailRequest(requestState)) return
      setSelectedActor(result)
    } catch (error) {
      if (isAbortError(error) || !isCurrentDetailRequest(requestState)) return
      setSelectedActor(null)
      showToast(error.message || 'IP 详情读取失败', 'error')
    }
  }, [beginDetailRequest, isCurrentDetailRequest, showToast])
  const closeDetail = useCallback(() => {
    detailRequestRef.current?.controller?.abort()
    detailRequestRef.current = null
    setSelectedActor(null)
    setSelectedEvent(null)
  }, [])
  useEffect(() => { const handlePop = () => setRoute(routeFromLocation()); window.addEventListener('popstate', handlePop); return () => window.removeEventListener('popstate', handlePop) }, [])
  useEffect(() => {
    const activeKey = `route:${route}`
    for (const [key, requestState] of routeRequestsRef.current.entries()) {
      if (key === activeKey) continue
      requestState.controller.abort()
      routeRequestsRef.current.delete(key)
    }
  }, [route])
  const loadRoute = useCallback(async (target = route, quiet = false, overrideParams = null) => {
    if (auth !== 'app') return
    const key = `route:${target}`
    const existing = routeRequestsRef.current.get(key)
    if (existing && quiet) return null
    existing?.controller?.abort()
    const requestState = { controller: new AbortController(), version: Date.now() + Math.random() }
    routeRequestsRef.current.set(key, requestState)
    const current = () => routeRequestsRef.current.get(key) === requestState
    const options = { signal: requestState.controller.signal }
    const isListTarget = target === 'observations' || target === 'invocations' || target === 'chains' || target === 'indicators'
    if (!quiet && isListTarget) {
      const loading = { target, query: overrideParams !== null, requestState }
      listLoadingRef.current = loading
      setListLoading({ target, query: loading.query })
    }
    if (!quiet) { busyRequestRef.current = requestState; setBusy(true) }
    setLoadError('')
    let loaded = null
    try {
      if (target === 'dashboard') { const results = await Promise.allSettled([request('dashboard?projection=summary', options).then((dashboard) => { if (current()) { dashboard.recent_events = (dashboard.recent_events || []).map(displayEventProjection); setData((value) => ({ ...value, dashboard })) }; return dashboard }), request('instances', options).then((instances) => { if (current()) setData((value) => ({ ...value, instances: instances.instances || [] })); return instances })]); const failed = results.find((result) => result.status === 'rejected'); if (failed) throw failed.reason }
      else if (target === 'observations') { const params = overrideParams || listParamsRef.current.observations; const query = new URLSearchParams({ page: String(params.page || 1), page_size: '10', projection: 'summary' }); if (params.q) query.set('q', params.q); if (params.product) query.set('product', params.product); if (params.min_score !== '' && params.min_score != null) query.set('min_score', String(params.min_score)); loaded = await request(`events?${query}`, options); if (!current()) return null; setData((value) => ({ ...value, events: loaded.events || [], pagination: { ...value.pagination, observations: responsePagination(loaded) } })) }
      else if (target === 'invocations') { const params = overrideParams || listParamsRef.current.invocations; const query = new URLSearchParams({ page: String(params.page || 1), page_size: '10', projection: 'summary' }); if (params.q) query.set('q', params.q); if (params.level) query.set('level', params.level); if (params.auth) query.set('auth', params.auth); if (params.execution) query.set('execution', params.execution); loaded = await request(`invocations?${query}`, options); if (!current()) return null; setData((value) => ({ ...value, invocations: loaded.invocations || [], pagination: { ...value.pagination, invocations: responsePagination(loaded) } })) }
      else if (target === 'chains') { const params = overrideParams || listParamsRef.current.chains; const query = new URLSearchParams({ page: String(params.page || 1), page_size: '10', projection: 'summary' }); if (params.q) query.set('q', params.q); loaded = await request(`insights?${query}`, options); if (!current()) return null; setData((value) => ({ ...value, chains: loaded.insights || loaded.items || [], pagination: { ...value.pagination, chains: responsePagination(loaded) } })) }
      else if (target === 'indicators') { const params = overrideParams || listParamsRef.current.indicators; const query = new URLSearchParams({ page: String(params.page || 1), page_size: '10' }); if (params.q) query.set('q', params.q); if (params.risk_level) query.set('risk_level', params.risk_level); if (params.sort) query.set('sort', params.sort); if (params.min_score !== '' && params.min_score != null) query.set('min_score', String(params.min_score)); loaded = await request(`indicators?${query}`, options); if (!current()) return null; setData((value) => ({ ...value, indicators: loaded.items || [], pagination: { ...value.pagination, indicators: responsePagination(loaded) } })) }
      else if (target === 'instances') { const result = await request('instances', options); if (!current()) return null; setData((value) => ({ ...value, instances: result.instances || [] })) }
      else if (target === 'packs') { const [packs, policies] = await Promise.all([request('packs', options), request('identity-policies', options)]); if (!current()) return null; setData((value) => ({ ...value, packs, policies })) }
      else if (target === 'settings') { const [ipinfo, frontendDetection] = await Promise.all([request('ipinfo-lite', options), request('frontend-detection', options)]); if (!current()) return null; setData((value) => ({ ...value, ipinfo, frontendDetection })) }
      if (!current()) return null
      setLastUpdated(new Date()); return loaded
    } catch (error) { if (isAbortError(error) || !current()) return null; if (error.status === 401) { setAuth('login'); navigateTo('login', true) } else setLoadError(error.message || '数据读取失败'); return null } finally { if (current()) routeRequestsRef.current.delete(key); if (!quiet && busyRequestRef.current === requestState) { busyRequestRef.current = null; setBusy(false) } if (!quiet && listLoadingRef.current?.requestState === requestState) { listLoadingRef.current = null; setListLoading(null) } }
  }, [auth, route])
  const loadList = useCallback(async (target, changes = {}, quiet = false) => {
    const previous = listParamsRef.current[target] || { page: 1 }
    const next = { ...previous, ...changes }
    const nextState = { ...listParamsRef.current, [target]: next }
    listParamsRef.current = nextState
    setListParams(nextState)
    if (!quiet) {
      const dataKey = target === 'observations' ? 'events' : target
      setData((value) => ({ ...value, [dataKey]: [], pagination: { ...value.pagination, [target]: null } }))
    }
    return loadRoute(target, quiet, next)
  }, [loadRoute])
  const deleteListItem = useCallback(async (target, identifier) => {
    if (!identifier || !window.confirm('确认逻辑删除这条记录吗？原始事件不会被物理修改。')) return
    const endpoints = { observations: 'events', invocations: 'invocations', chains: 'insights', indicators: 'indicators' }
    const endpoint = endpoints[target]
    if (!endpoint) return
    try {
      await request(`${endpoint}/${encodeURIComponent(identifier)}`, { method: 'DELETE' })
      const params = { ...(listParamsRef.current[target] || { page: 1 }) }
      const result = await loadRoute(target, false, params)
      const resultKey = target === 'observations' ? 'events' : target === 'invocations' ? 'invocations' : target === 'chains' ? 'insights' : 'items'
      if (params.page > 1 && result && Array.isArray(result[resultKey]) && result[resultKey].length === 0 && Number(result.total || 0) > 0) await loadList(target, { page: params.page - 1 })
      showToast('已逻辑删除，原始事件仍保留在追加式存储中。')
    } catch (error) { showToast(error.message || '删除失败', 'error') }
  }, [loadList, loadRoute, showToast])
  useEffect(() => {
    let active = true
    const controller = new AbortController()
    const initialize = async () => {
      try {
        const status = await request('setup/status', { signal: controller.signal }); if (!active) return
        if (!status.initialized) { setAuth('setup'); navigateTo('setup', true); return }
        try { const session = await request('auth/session', { signal: controller.signal }); if (!active) return; setUsername(session.username || ''); setAuth('app'); if (route === 'login' || route === 'setup') navigateTo('dashboard', true) }
        catch (error) { if (!active || isAbortError(error)) return; if (error.status === 401) { setAuth('login'); if (route !== 'login') navigateTo('login', true) } else { setLoadError(error.message || '控制平面不可用'); setAuth('login') } }
      } catch (error) { if (active && !isAbortError(error)) { setLoadError(error.message || '无法读取初始化状态'); setAuth('login') } }
    }
    initialize(); return () => { active = false; controller.abort() }
  }, [])
  useEffect(() => { if (auth === 'app') loadRoute(route) }, [auth, route])
  useEffect(() => { if (auth !== 'app') return undefined; const timer = window.setInterval(() => loadRoute(route, true), 30000); return () => window.clearInterval(timer) }, [auth, route, loadRoute])
  useEffect(() => {
    if (auth !== 'app' || route !== 'dashboard') return undefined
    const activity = data.dashboard?.risk_activity || {}
    const nextRefresh = Object.keys(activity)
      .map((key) => Date.parse(activity[key]?.next_refresh_at || ''))
      .filter((value) => Number.isFinite(value) && value > Date.now())
      .sort((left, right) => left - right)[0]
    if (!nextRefresh) return undefined
    const delay = Math.max(1000, nextRefresh - Date.now() + 250)
    const timer = window.setTimeout(() => loadRoute('dashboard', true), delay)
    return () => window.clearTimeout(timer)
  }, [auth, route, data.dashboard, loadRoute])
  const saveIPInfo = useCallback(async (provider, token, includeToken = false) => {
    const payload = { provider }
    if (includeToken) payload.token = token
    const ipinfo = await request('ipinfo-lite', { method: 'PUT', body: JSON.stringify(payload) })
    setData((current) => ({ ...current, ipinfo }))
    showToast(provider === 'maxmind' ? 'MaxMind GeoLite2 查询已启用' : provider === 'ipinfo_mmdb' ? 'IPinfo MMDB 查询已启用' : provider === 'ipinfo_api' ? 'IPinfo API 配置已保存' : (includeToken && token ? 'IPinfo Lite 配置已保存' : 'IPinfo Lite 设置已更新'))
    if (route === 'dashboard') await loadRoute('dashboard', true)
  }, [loadRoute, route, showToast])
  const saveFrontendDetection = useCallback(async (next) => {
    const frontendDetection = await request('frontend-detection', { method: 'PUT', body: JSON.stringify(next) })
    setData((current) => ({ ...current, frontendDetection }))
    showToast('前端检测设置已更新')
  }, [showToast])
  const login = async (name, password) => { const result = await request('auth/login', { method: 'POST', body: JSON.stringify({ username: name, password }) }); setDashboardAnimationKey((value) => value + 1); setUsername(result.username || name); setAuth('app'); navigateTo('dashboard', true); showToast('已安全登录控制平面') }
  const setup = async (name, password) => { if (name === 'continue') { setAuth('login'); navigateTo('login', true); return {} } const result = await request('setup/create-owner', { method: 'POST', body: JSON.stringify({ username: name, password }) }); setUsername(name); showToast('owner 已创建，请先保存恢复码'); return result }
  const forgotPassword = async (name) => request('auth/forgot-password', { method: 'POST', body: JSON.stringify({ username: name }) })
  const recoveryReset = async (name, code, password) => { await request('auth/recovery-code/reset', { method: 'POST', body: JSON.stringify({ username: name, recovery_code: code, new_password: password }) }); showToast('密码已重置，请使用新密码登录') }
  const logout = async () => { for (const requestState of routeRequestsRef.current.values()) requestState.controller.abort(); routeRequestsRef.current.clear(); listLoadingRef.current = null; setListLoading(null); busyRequestRef.current = null; setBusy(false); detailRequestRef.current?.controller?.abort(); detailRequestRef.current = null; try { await request('auth/logout', { method: 'POST' }) } catch (_) {} setAuth('login'); setUsername(''); setSelectedActor(null); setSelectedEvent(null); setListParams(LIST_DEFAULTS); listParamsRef.current = LIST_DEFAULTS; setData({ dashboard: null, instances: [], events: [], invocations: [], chains: [], indicators: [], packs: null, policies: null, ipinfo: null, frontendDetection: null, pagination: { observations: null, invocations: null, chains: null, indicators: null } }); navigateTo('login', true) }
  const rotateEntry = async () => { try { const result = await request('admin-entry:rotate', { method: 'POST' }); if (result.new_path) { window.location.assign(`${result.new_path}login`); return } setAuth('login'); navigateTo('login', true); showToast('入口已轮换，请从配置文件获取新路径') } catch (error) { showToast(error.message || '入口轮换失败', 'error') } }
  const instanceAction = async (instance, action) => {
    if (action === 'start-all') { setBusy(true); try { for (const item of data.instances) if (item.state !== 'running') await request(`instances/${item.product}/start`, { method: 'POST' }); await loadRoute('instances', true); showToast('启动指令已应用') } catch (error) { showToast(error.message || '启动实例失败', 'error') } finally { setBusy(false) }; return }
    setBusy(true); try { const result = await request(`instances/${instance.product}/${action}`, { method: 'POST' }); setData((current) => ({ ...current, instances: result.instances || current.instances })); showToast(`${profileLabel(instance.product)} ${action === 'restart' ? '已重启' : action === 'start' ? '已启动' : '已停止'}`); if (route === 'dashboard') await loadRoute('dashboard', true) } catch (error) { showToast(error.message || '实例操作失败', 'error') } finally { setBusy(false) }
  }
  if (auth === 'checking') return html`<${AuthLoading} />`
  if (auth === 'setup') return html`<${SetupPage} onSetup=${setup} />`
  if (auth === 'login') return html`<${LoginPage} onLogin=${login} onForgot=${forgotPassword} onRecovery=${recoveryReset} />`
  const page = route === 'observations' ? html`<${ObservationsPage} events=${data.events} pagination=${data.pagination.observations} onRefresh=${() => loadRoute('observations')} onSearch=${(changes) => loadList('observations', changes)} onPageChange=${(page) => loadList('observations', { page })} onDelete=${(id) => deleteListItem('observations', id)} onOpenEvent=${openEvent} loading=${listLoading?.target === 'observations' && (listLoading.query || data.events.length === 0)} />` : route === 'invocations' ? html`<${InvocationsPage} invocations=${data.invocations} pagination=${data.pagination.invocations} onRefresh=${() => loadRoute('invocations')} onSearch=${(changes) => loadList('invocations', changes)} onPageChange=${(page) => loadList('invocations', { page })} onDelete=${(id) => deleteListItem('invocations', id)} onOpenEvent=${openEvent} loading=${listLoading?.target === 'invocations' && (listLoading.query || data.invocations.length === 0)} />` : route === 'chains' ? html`<${ChainsPage} chains=${data.chains} pagination=${data.pagination.chains} onRefresh=${() => loadRoute('chains')} onSearch=${(changes) => loadList('chains', changes)} onPageChange=${(page) => loadList('chains', { page })} onDelete=${(id) => deleteListItem('chains', id)} onOpenEvent=${openEvent} loading=${listLoading?.target === 'chains' && (listLoading.query || data.chains.length === 0)} />` : route === 'indicators' ? html`<${IndicatorsPage} indicators=${data.indicators} pagination=${data.pagination.indicators} onRefresh=${() => loadRoute('indicators')} onSearch=${(changes) => loadList('indicators', changes)} onPageChange=${(page) => loadList('indicators', { page })} onDelete=${(id) => deleteListItem('indicators', id)} onOpenIndicator=${openActor} loading=${listLoading?.target === 'indicators' && (listLoading.query || data.indicators.length === 0)} />` : route === 'instances' ? html`<${InstancesPage} instances=${data.instances} onRefresh=${() => loadRoute('instances')} onAction=${instanceAction} busy=${busy} />` : route === 'packs' ? html`<${PacksPage} packs=${data.packs} policies=${data.policies} onRefresh=${() => loadRoute('packs')} />` : route === 'settings' ? html`<${SettingsPage} username=${username} ipinfo=${data.ipinfo} frontendDetection=${data.frontendDetection} onRotateEntry=${rotateEntry} onSaveIPInfo=${saveIPInfo} onSaveFrontendDetection=${saveFrontendDetection} />` : html`<${DashboardControlPage} dashboard=${data.dashboard} instances=${data.instances} onNavigate=${onNavigate} onRefresh=${() => loadRoute('dashboard')} onOpenEvent=${openEvent} animationKey=${dashboardAnimationKey} />`
  return html`<${AppShell} route=${route} onNavigate=${onNavigate} onLogout=${logout} username=${username} lastUpdated=${lastUpdated}><div key=${route} class=${cn(loadError && 'has-page-error')}>${loadError ? html`<div class="page-error">${icon('warning', 17)}<span>${loadError}</span><button class="text-button" type="button" onClick=${() => loadRoute(route)}>重试</button></div>` : null}${page}</div><//>${selectedActor ? html`<${ActorDetailModal} actor=${selectedActor} onClose=${closeDetail} onOpenEvent=${openEvent} />` : null}${selectedEvent ? html`<${EventDetails} event=${{ ...selectedEvent, onClose: closeDetail }} />` : null}<${Toast} toast=${toast} onClose=${() => setToast(null)} />`
}

render(html`<${App} />`, document.getElementById('app'))
