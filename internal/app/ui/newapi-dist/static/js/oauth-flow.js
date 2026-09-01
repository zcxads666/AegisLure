(() => {
  'use strict'

  const ERROR_KEY = 'newapi_oauth_error'
  const REGISTER_PATH = '/sign-up'
  const AUTH_PATHS = new Set(['/login', '/sign-in', '/register', '/sign-up'])

  function isAuthPage() {
    return AUTH_PATHS.has(window.location.pathname.replace(/\/$/, '') || '/')
  }

  function providerFor(button) {
    const label = String(button.textContent || '')
    if (/\bGitHub\b/i.test(label)) return 'github'
    if (/\bLinuxDO\b/i.test(label)) return 'linuxdo'
    if (/\bDiscord\b/i.test(label)) return 'discord'
    return ''
  }

  function showError() {
    const existing = document.getElementById('newapi-oauth-error')
    if (existing) existing.remove()
    const notice = document.createElement('div')
    notice.id = 'newapi-oauth-error'
    notice.setAttribute('role', 'alert')
    notice.setAttribute('aria-live', 'assertive')
    notice.textContent = 'OAuth authentication failed. Please try again or use account registration.'
    Object.assign(notice.style, {
      position: 'fixed',
      top: '1rem',
      right: '1rem',
      zIndex: '2147483647',
      maxWidth: 'min(90vw, 28rem)',
      padding: '0.75rem 1rem',
      border: '1px solid #e11d48',
      borderRadius: '0.5rem',
      background: '#fff1f2',
      color: '#9f1239',
      boxShadow: '0 0.75rem 2rem rgba(15, 23, 42, 0.18)',
      font: '500 0.875rem/1.35 system-ui, sans-serif',
    })
    document.body.appendChild(notice)
    window.setTimeout(() => notice.remove(), 6000)
  }

  function showPendingError() {
    try {
      if (window.sessionStorage.getItem(ERROR_KEY) !== '1') return
      window.sessionStorage.removeItem(ERROR_KEY)
      showError()
    } catch (_) {
      // A restricted storage context should not make the auth page fail.
    }
  }

  function rememberError() {
    try { window.sessionStorage.setItem(ERROR_KEY, '1') } catch (_) {}
  }

  async function notifyAndReturn(provider) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null
    const timeout = window.setTimeout(() => controller?.abort(), 1500)
    try {
      await fetch('/api/oauth/state', {
        method: 'POST',
        credentials: 'same-origin',
        signal: controller?.signal,
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          intent: 'login',
          surface: window.location.pathname === '/login' || window.location.pathname === '/sign-in' ? 'login' : 'register',
        }),
      })
    } catch (_) {
      // The return path remains deterministic even when the local endpoint is unavailable.
    } finally {
      window.clearTimeout(timeout)
    }
    rememberError()
    window.location.assign(REGISTER_PATH)
  }

  function interceptOAuthClick(event) {
    if (!isAuthPage()) return
    const target = event.target
    const button = target && typeof target.closest === 'function' ? target.closest('button') : null
    const provider = button ? providerFor(button) : ''
    if (!button || !provider || button.disabled) return
    event.preventDefault()
    event.stopPropagation()
    event.stopImmediatePropagation()
    button.disabled = true
    button.setAttribute('aria-busy', 'true')
    void notifyAndReturn(provider)
  }

  function install() {
    showPendingError()
    document.addEventListener('click', interceptOAuthClick, true)
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', install, { once: true })
  } else {
    install()
  }
})()
