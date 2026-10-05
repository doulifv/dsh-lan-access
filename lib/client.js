// dsh-lan-access — client half (v0.1.11).
//
// Adds a "LAN Access" section to the DeepSeek Harness desktop settings dialog
// that links to the plugin's loopback management panel
// (http://127.0.0.1:<loopbackPort>/__lan-access).
//
// HOW THIS WORKS
// The module is a classic client bundle (the "client-modules" protocol used by
// every DSH desktop client plugin): it registers a factory with
// window.__ModuleLoader__.load({ id, factory }) and the factory returns a
// module exposing `apply` (and `inject`). The host loads this file because
// package.json declares `dsh.client` and maps `exports["./client"]` here.
//
// WHY `inject: ['slots']` IS A SERVICE LIST, NOT A PACKAGE LIST
// `inject` names cordis SERVICES resolved on the client fiber, not npm packages.
// Verified against working plugins in the desktop profile:
//   * @liustack/modlens/dsh/client.js:1135  ctx.inject(['slots'], …), and its
//     package.json:80-82 declares dsh.client.inject as [] — the manifest list is
//     NOT the mechanism.
//   * billion-context/dist/agent/dsh-native-client.js:32  var inject = ["slots","locale"]
//   * dsh-workbuddy-connect/lib/client.js:2858-2875 documents that DSH 0.1.2
//     REMOVED @deepseek-ai/dsh-client-runtime; the slots registry now lives in
//     @deepseek-ai/dsh-client-ui-renderer, so naming that old package would not
//     resolve. `inject` is therefore ["slots"] and nothing else.
//
// WHY THE RENDERER RETURNS A REACT ELEMENT
// The host invokes a settings-section renderer as a React function component.
// Proof: every working renderer uses hooks at its top level —
// billion-context …/dsh-native-client.js:98-99 (useState/useEffect) and
// dsh-deepseek-web-login/lib/client.js:575-577 (useRef/useEffect). A renderer
// that returns a raw DOM node would be reconciled as a component and throw,
// which is exactly the "blank the whole settings dialog" failure that
// dshmarket/client/client.js:14536-14538 guards against. So: return a React
// element, and attach the imperative DOM inside a ref via useEffect.
// React is taken from the loader's module table (`require('react')`) — it is
// host-provided, so this package still has ZERO npm dependencies.
//
// DEGRADATION
// Every step is guarded twice: once for the eager call and once inside the
// deferred slot callback, which runs after apply() has returned where no
// enclosing try/catch could still reach it. A failure logs and the settings
// dialog is left exactly as it was.
window.__ModuleLoader__.load({
  id: 'dsh-lan-access',
  // `require` is the loader's module table, handed in as a factory PARAMETER.
  // It is not a lexical global in a classic bundle: every bundle in the desktop
  // profile that calls require() declares it here (modlens :18, billion-context
  // :1, dshmarket :1, dsh-workbuddy-connect :3, dsh-deepseek-web-login :3),
  // while the one bundle that omits the parameter (dsh-delete-session :19)
  // never calls require(). Omitting it made require('react') a ReferenceError
  // that the guard below swallowed — the section silently never appeared.
  factory: (require) => {
    const NS = 'dsh-lan-access'
    // The loopback web surface is the host's own port. 19387 is the DSH desktop
    // default and matches this plugin's README; the management route is what the
    // host half registers via ctx.webServer.register('/__lan-access').
    const LOOPBACK_PORT = 19387
    const PANEL_URL = 'http://127.0.0.1:' + LOOPBACK_PORT + '/__lan-access'
    const LOG_PREFIX = '[dsh-lan-access] settings section skipped:'

    const zh = {
      nav: '局域网访问',
      title: '局域网访问',
      desc: '在局域网内用手机访问本机 DeepSeek Harness，或打开管理面板。',
      open: '打开管理面板',
      hint: '面板仅在 127.0.0.1 上可用；LAN 客户端会被代理返回 404。',
    }
    const en = {
      nav: 'LAN Access',
      title: 'LAN Access',
      desc: 'Reach this DeepSeek Harness from a phone on your LAN, or open the management panel.',
      open: 'Open management panel',
      hint: 'The panel is loopback-only; LAN clients get a 404 from the proxy.',
    }

    /** Best-effort locale sniff; every step guarded because locale is optional. */
    function pickText() {
      let lang = ''
      try {
        lang = String((typeof navigator !== 'undefined' && navigator.language) || '')
      } catch {
        /* ignore */
      }
      return /^zh/i.test(lang) ? zh : en
    }

    /**
     * The panel body, built with DOM APIs only. Built per call so live locale
     * changes are picked up; a cached node would freeze the first caller's text.
     */
    function buildPanel() {
      const t = pickText()

      const root = document.createElement('div')
      root.style.cssText = 'display:flex;flex-direction:column;gap:10px;padding:4px 2px;font:inherit;color:var(--dsw-alias-label-primary,#1f2328)'

      const title = document.createElement('h3')
      title.textContent = t.title
      title.style.cssText = 'margin:0;font-size:16px;font-weight:500;line-height:24px'
      root.appendChild(title)

      const desc = document.createElement('p')
      desc.textContent = t.desc
      desc.style.cssText = 'margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#6b7280)'
      root.appendChild(desc)

      const link = document.createElement('a')
      link.href = PANEL_URL
      link.target = '_blank'
      link.rel = 'noopener noreferrer'
      link.textContent = t.open
      link.style.cssText = 'align-self:flex-start;font-size:13px;line-height:20px;padding:6px 12px;border-radius:8px;text-decoration:none;color:var(--dsw-alias-brand-primary,#4f6ef7);border:1px solid var(--dsw-alias-border-l2,#e5e7eb)'
      root.appendChild(link)

      const url = document.createElement('code')
      url.textContent = PANEL_URL
      url.style.cssText = 'font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary,#6b7280);word-break:break-all'
      root.appendChild(url)

      const hint = document.createElement('p')
      hint.textContent = t.hint
      hint.style.cssText = 'margin:0;font-size:11px;line-height:16px;color:var(--dsw-alias-label-tertiary,#8b93a1)'
      root.appendChild(hint)

      return root
    }

    /**
     * Build the section component. React comes from the host module table; if it
     * is unavailable we degrade to no section rather than throwing into the host.
     */
    function makeSection(react) {
      return function LanAccessSection() {
        const hostRef = react.useRef(null)
        react.useEffect(() => {
          const host = hostRef.current
          if (!host) return undefined
          let node = null
          try {
            node = buildPanel()
            host.appendChild(node)
          } catch (error) {
            try {
              console.error(LOG_PREFIX + ' ' + error)
            } catch {
              /* ignore */
            }
            return undefined
          }
          return () => {
            try {
              node.remove()
            } catch {
              /* ignore */
            }
          }
        }, [])
        return react.createElement('div', { ref: hostRef })
      }
    }

    /**
     * Register one settings section. `ctx.inject(['slots'], cb)` is the scoped
     * narrowing the ecosystem uses: cb runs where the `slots` service exists and
     * never runs where it does not, so an absent service is not an error.
     */
    function registerSection(ctx) {
      ctx.inject(['slots'], (scope) => {
        let react = null
        try {
          react = require('react')
        } catch (error) {
          try {
            console.error(LOG_PREFIX + ' react unavailable — ' + error)
          } catch {
            /* ignore */
          }
          return
        }
        try {
          scope.slots.inject('settings.section', () => {
            try {
              scope.slots.register({
                name: 'settings.section',
                id: NS,
                order: 45,
                label: () => pickText().nav,
              }, makeSection(react))
            } catch (error) {
              try {
                console.error(LOG_PREFIX + ' ' + error)
              } catch {
                /* ignore */
              }
            }
          })
        } catch (error) {
          try {
            console.error(LOG_PREFIX + ' settings.section unavailable — ' + error)
          } catch {
            /* ignore */
          }
        }
      })
    }

    function apply(ctx) {
      try {
        registerSection(ctx)
      } catch (error) {
        try {
          console.error(LOG_PREFIX + ' ' + error)
        } catch {
          /* ignore */
        }
      }
    }

    return { name: NS, inject: ['slots'], apply }
  },
})
