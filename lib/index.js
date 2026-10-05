// dsh-lan-access — Host half.
//
// Reverse-proxies the DeepSeek Harness loopback web surface (served by the
// built-in `webServer`, normally 127.0.0.1:19387) to 0.0.0.0 so a phone on the
// LAN can reach the GUI.
//
// Security model (see app.asar architecture notes, src/api-request-trust.ts):
//   * The built-in server refuses `--host 0.0.0.0`; plugins are NOT subject to
//     that CLI guard, so we open our own listener on 0.0.0.0.
//   * We rewrite the inbound `Host` header to `127.0.0.1:<loopbackPort>` before
//     forwarding. The backend trust fence (`isTrustedApiRequest`) treats a
//     loopback Host as trusted and skips the DNS-rebinding / cross-site checks,
//     so the request is accepted. Because we rewrite on every request, the
//     authority-bound sign-in cookie validates with the same Host the server
//     computes, so an authenticated phone session survives.
//   * Access is gated by a single shared secret (`accessToken`). The loopback
//     `webServer` has no transport-layer auth of its own, so exposing the proxy
//     to the network MUST require this token. An unauthenticated client (no
//     valid `?lt=` and no valid signed session cookie) gets a 401 pointing it at
//     the local management page, which mints a one-tap phone sign-in link.
//   * The management routes (`/__lanapi/*`, `/__lan-access`) are registered on
//     the SAME webServer we proxy to, so they would otherwise be reachable from
//     the LAN. The proxy therefore hard-404s the control plane at its own entry
//     point (see CONTROL_PATHS / isControlPlane) instead of trusting the
//     backend to separate them.
//
// v0.1.1 fixes: listen() is now awaited by the /start route and every bind
// failure (EADDRINUSE / EACCES / …) is surfaced in the management UI instead of
// only the host console; the phone-link card works for GET and lists one
// sign-in URL per LAN IP.
//
// v0.1.10 changes:
//   * The runtime "Apply port" feature was REMOVED. It was unreliable (it could
//     report success while the listener never moved) and the port is a
//     start-time setting anyway, so it is now configured ONLY via `lanPort` in
//     cordis.patch.yml + a plugin reload. There is no /__lanapi/port route and
//     no port input in the management page.
//   * The management page now shows the FULL access token instead of a masked
//     d7ea52…08c4 form, so it can be copied and typed by hand on a phone.
//
// v0.1.8 fixes:
//   * The token gate used to accept ANY non-empty `Cookie` header, which
//     collapsed the whole security model. It now requires an HMAC-SHA256 signed
//     session cookie (`dsh_lan`) whose key is derived from `accessToken`, so
//     rotating the token logs every authorized device out.
//   * `?lt=` now exchanges for that cookie via a 302 that strips BOTH one-time
//     credentials (`lt` and the backend's `token`) from the URL (address bar /
//     history no longer carries either secret). The exchange is a real upstream
//     round trip, because only the backend can consume `token=` and set its own
//     cookie; short-circuiting the 302 here is what made a tapped phone link
//     fail with "dsh web authentication required" while pasting it worked.
//   * The control plane is 404'd at the proxy, so the LAN can no longer reach
//     the management page, the control API, or the plaintext token.
//   * `stopProxy()` now truly releases the port (tracked sockets +
//     closeAllConnections), and a `startAborted` flag makes an in-flight
//     listen() abandon itself instead of resurrecting an orphan listener.
//   * No-restart: the instance slot is a takeover record (a new apply() disposes
//     the previous instance instead of silently no-op'ing), auto-start waits for
//     `ctx.webServer.port` instead of giving up, and the backend port is
//     resolved per request instead of being snapshotted at start.
//
// v0.1.12 fixes — the REAL "tap fails, paste works" root cause:
//   * The management panel is served from http://127.0.0.1:<loopback>/__lan-access,
//     but the phone link points at http://<lanIP>:<lanPort>/. Following that link
//     is a CROSS-ORIGIN top-level navigation, so the browser attaches
//     `sec-fetch-site: cross-site` (usually with `origin`); pasting the identical
//     URL into the address bar is a user-initiated navigation with NEITHER header.
//     The backend fence rejects `cross-site` outright and passes when `origin` is
//     absent — so one URL produced two opposite outcomes.
//     rewriteBrowserTrustHeaders() now normalises UNCONDITIONALLY instead of only
//     when a header happens to be present: `sec-fetch-site` is always pinned to
//     `same-origin` and a foreign `origin` is dropped.
//   * A failed launch-token exchange is no longer silently turned into a 302 that
//     leaves the phone authenticated to this proxy but NOT to the backend (which
//     is what kept re-surfacing the same symptom after the first fix). If the
//     backend returns >=400 or sends no Set-Cookie, the phone gets an explained
//     401 page and the host log gets a token-free warning.
//   * The panel re-mints the link at CLICK time via /phone-url, because the dsh
//     launch token is single-use and a rendered link goes stale (chat-app link
//     previews, a second tap, a long-open page).
//   * /__lanapi/status now sets `cache-control: no-store` (it carries the
//     plaintext access token).
//
// v0.1.13 fix — the ACTUAL "tap fails, paste works" cause (all of the above was
//   necessary but not sufficient):
//   The backend mints its own session cookie with `SameSite=Strict` and no
//   `Secure` (app.asar:371222, `... HttpOnly; SameSite=Strict`). A tapped phone
//   link is a CROSS-SITE-INITIATED navigation (panel on 127.0.0.1:<loopback>,
//   link on <lanIP>:<lanPort>), and browsers attach SameSite=Strict cookies only
//   to same-site requests — NOT to any request in a redirect chain that a
//   cross-site initiator started. So the phone DID complete the token exchange
//   and DID store the cookie, but the follow-up GET / arrived with no cookie and
//   `isAuthenticated` failed at app.asar:371361 (`rawCookie === void 0`) ->
//   "dsh web authentication required". Pasting into the address bar is
//   user-initiated, so Strict IS attached and it works.
//   No request-header rewriting can fix this: the discrepancy is in how the
//   BROWSER stores and replays the RESPONSE cookie. Fix: relax `SameSite=Strict`
//   to `SameSite=Lax` on every Set-Cookie we relay back to the phone (mint
//   exchange AND the normal proxy path). Lax is still sent on top-level
//   navigations, so it widens exactly the login case and nothing else.
import { createServer, request as httpRequest } from 'node:http';
import { connect } from 'node:net';
import os from 'node:os';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// The Host the proxy presents to the backend. A loopback Host makes the backend
// trust the connection and skip the DNS-rebinding / cross-site fence.
const TRUSTED_HOST = '127.0.0.1';

// ---- Session cookie (signed) ------------------------------------------------
const SESSION_COOKIE = 'dsh_lan';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// The LAN listener's bind address. Also used by the port-free probe, which MUST
// match it exactly (see waitForPortFree).
const LISTEN_HOST = '0.0.0.0';

// ---- Control plane (must never be reachable from the LAN) -------------------
const CONTROL_PATHS = ['/__lanapi', '/__lan-access'];

function isControlPlane(pathname) {
  // Case-insensitive: `/__LANAPI/status` must not slip past the LAN gate on a
  // backend whose own router happens to be case-insensitive.
  const lower = String(pathname || '').toLowerCase();
  return CONTROL_PATHS.some((p) => lower === p || lower.startsWith(p + '/'));
}

// ---- Hop-by-hop headers that must not be forwarded --------------------------
const HOP_HEADERS = new Set([
  'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding',
  'te', 'trailer', 'upgrade', 'proxy-authenticate', 'proxy-authorization',
]);

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

// The signing key is derived from the access token, so rotating the token
// invalidates every session cookie minted under the previous one.
function deriveSessionKey(token) {
  return createHmac('sha256', String(token)).update('dsh-lan-access/session/v1').digest();
}

// Assigned in apply(); read by mintSessionCookie / verifySessionCookie.
let sessionKey = null;

// Promise that releases the PREVIOUS instance's listener, set by stopProxy().
// A new instance taking over the slot (plugin reload / config change) must
// await this before it binds the same port — `server.close()` needs at least
// one event-loop turn to free the handle, so binding immediately races it and
// yields EADDRINUSE (or two live listeners), which is exactly the "must
// restart DeepSeek Harness to make it work" symptom. Module-scoped on purpose:
// it must survive across instances.
let pendingRelease = null;

function timingSafeStringEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// NICs that are almost never reachable from a phone: VPN tunnels, container /
// hypervisor bridges, and APIPA (169.254/16, "no DHCP server answered").
// Showing them produced a wall of links where most simply did not connect.
const VIRTUAL_NIC = /docker|veth|br-|virbr|vmware|virtualbox|vbox|hyper-v|wsl|tailscale|zerotier|hamachi|tap-|tun|ppp|radmin|npcap|loopback/i;

function isUsableLanAddr(ip) {
  if (typeof ip !== 'string') return false;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 169 && b === 254) return false;   // APIPA
  if (a === 127) return false;                // loopback
  if (a >= 224) return false;                 // multicast / reserved
  return true;
}

function lanAddrs() {
  const out = [];
  let list;
  try {
    list = os.networkInterfaces() || {};
  } catch {
    return out;
  }
  for (const name of Object.keys(list)) {
    if (VIRTUAL_NIC.test(name)) continue;
    for (const ni of list[name] || []) {
      if (ni.family === 'IPv4' && !ni.internal && isUsableLanAddr(ni.address)) out.push(ni.address);
    }
  }
  // De-duplicate: a machine can report the same address on several aliases.
  const filtered = Array.from(new Set(out));
  if (filtered.length) return filtered;
  // Fallback: filtering left us with nothing (unusual NIC names), so show the
  // unfiltered list rather than an empty card — a wrong hint beats no hint.
  const all = [];
  for (const name of Object.keys(list)) {
    for (const ni of list[name] || []) {
      if (ni.family === 'IPv4' && !ni.internal) all.push(ni.address);
    }
  }
  return Array.from(new Set(all));
}

export const name = 'dsh-lan-access';
export const inject = ['webServer', 'connection'];

export function apply(ctx, config) {
  if (!config || typeof config !== 'object') config = {};

  // ---- Instance slot with takeover (this is the "must restart DSH" bug) -----
  // The old guard stored `true` in the slot and deleted it on dispose. When a
  // NEW instance applied BEFORE the old one disposed (plugin reload / config
  // change), the new instance saw the slot taken and became a silent no-op —
  // and then the old instance's dispose deleted the slot anyway, so the plugin
  // was dead until the host restarted. Now the slot holds a record: the new
  // instance explicitly disposes the previous one and takes over, and dispose
  // only clears the slot if it still owns it.
  const SLOT = Symbol.for('dsh-lan-access#instance');
  const prev = globalThis[SLOT];
  const mine = { id: Symbol('dsh-lan-access'), disposed: false, dispose: null };
  if (prev && prev !== mine && !prev.disposed) {
    let release = null;
    try {
      if (typeof prev.dispose === 'function') release = prev.dispose();
      ctx.logger?.info?.('[dsh-lan-access] took over the previous instance slot.');
    } catch (e) {
      // Even if tearing the old instance down failed, we MUST still claim the
      // slot: returning here left the slot owned by a disposed record, so every
      // later apply() hit the same dead branch and the plugin stayed broken
      // until the host was restarted.
      ctx.logger?.warn?.('[dsh-lan-access] takeover cleanup failed: ' + (e && e.message));
    }
    // Hand the previous instance's port release to the module scope so OUR
    // startProxy() awaits it instead of racing into EADDRINUSE.
    if (release && typeof release.then === 'function') pendingRelease = release;
  }
  globalThis[SLOT] = mine;

  // Disposers from ctx.webServer.register(...) / tapIndex(...), collected so
  // `mine.dispose` can also unregister them during a takeover.
  const disposers = [];

  // ---- Config validation ----------------------------------------------------
  // A user-supplied token is USED AS GIVEN once it is long enough. The previous
  // behaviour (drop anything <16 chars and silently re-randomize on every
  // apply()) was a destructive change: an existing short token was replaced on
  // every host start, so all phone links and session cookies died with no
  // explanation. Warn instead, and only generate when there is nothing to keep.
  let accessToken = config.accessToken;
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    accessToken = randomBytes(24).toString('hex');
  } else if (accessToken.length < 16) {
    ctx.logger?.warn?.(
      '[dsh-lan-access] 配置的 accessToken 长度不足 16 位，安全性较弱；已按原值保留（可在管理页点“轮换令牌”生成强令牌）。'
    );
  }

  let lanPort = Number(config.lanPort);
  if (!Number.isInteger(lanPort) || lanPort < 1 || lanPort > 65535) {
    if (config.lanPort !== undefined && config.lanPort !== null && config.lanPort !== '') {
      ctx.logger?.warn?.(
        `[dsh-lan-access] 配置的 lanPort ${String(config.lanPort)} 不是 1-65535 的整数，已回退为 19193。`
      );
    }
    lanPort = 19193;
  }

  const cfg = {
    lanPort,
    requireToken: config.requireToken !== false,
    autoStart: !!config.autoStart,
    accessToken,
  };

  sessionKey = deriveSessionKey(cfg.accessToken);

  const state = {
    lanPort: cfg.lanPort,
    requireToken: cfg.requireToken,
    // May be undefined until webServer has actually listened; refreshLoopbackPort()
    // fills it in before every status/start response.
    loopbackPort: ctx.webServer?.port,
    proxyUp: false,
    lanAddrs: [],
    phoneUrl: '',
    error: '',
    // Full token is exposed here on purpose: this endpoint is only served on the
    // loopback webServer (the proxy 404s /__lanapi for LAN clients) and the
    // browser builds the one-tap phone sign-in links from it, removing the
    // dependency on the separate /phone-url helper (which was returning empty).
    accessToken: cfg.accessToken,
    // The dsh launch token lets the phone complete the one-time cookie exchange
    // on first hit. Minted from ctx.connection.authenticatedUrl; if that API is
    // unavailable we leave it empty and the link falls back to ?lt= only.
    dshToken: '',
  };

  function refreshLanAddrs() {
    state.lanAddrs = lanAddrs();
  }

  // Never let the UI show "127.0.0.1:undefined": refresh from the live webServer
  // port whenever we are about to answer, keeping the last known value if the
  // port is not available yet.
  function refreshLoopbackPort() {
    const p = ctx.webServer?.port;
    if (p) state.loopbackPort = p;
    return state.loopbackPort;
  }

  // One sign-in URL per LAN IP (a machine often has several NICs; the phone can
  // only reach the one on its own subnet). `lt` satisfies the proxy gate;
  // `token` is the live dsh launch token so the backend performs the one-time
  // cookie exchange.
  function buildPhoneUrls() {
    // Never let phone-link generation break the status/health endpoints: if
    // anything here throws (e.g. authenticatedUrl shape differs, or URL parse
    // fails), we fall back to a token-only link so the proxy status still shows.
    try {
      refreshLanAddrs();
      const base = `http://127.0.0.1:${String(ctx.webServer?.port)}`;
      let token = '';
      try {
        const authFn = ctx.connection && ctx.connection.authenticatedUrl;
        if (typeof authFn === 'function') {
          const authed = authFn.call(ctx.connection, base);
          if (typeof authed === 'string' && authed) {
            token = new URL(authed).searchParams.get('token') || '';
          }
        }
      } catch {
        token = '';
      }
      const suffix =
        `?lt=${encodeURIComponent(cfg.accessToken)}` +
        (token ? `&token=${encodeURIComponent(token)}` : '');
      const addrs = state.lanAddrs.length ? state.lanAddrs : lanAddrs();
      return addrs.map((ip) => ({ ip, url: `http://${ip}:${cfg.lanPort}/${suffix}` }));
    } catch (e) {
      ctx.logger?.warn?.('[dsh-lan-access] buildPhoneUrls failed: ' + (e && e.message));
      return [];
    }
  }

  function buildPhoneUrl() {
    return buildPhoneUrls()[0]?.url || '';
  }

  // Safely mint the dsh launch token (for the one-time phone cookie exchange).
  // Returns '' if the API is unavailable or throws — callers fall back to ?lt= only.
  function getDshToken() {
    try {
      const authFn = ctx.connection && ctx.connection.authenticatedUrl;
      if (typeof authFn !== 'function') return '';
      const authed = authFn.call(ctx.connection, `http://127.0.0.1:${String(ctx.webServer?.port)}`);
      if (typeof authed !== 'string' || !authed) return '';
      return new URL(authed).searchParams.get('token') || '';
    } catch (e) {
      ctx.logger?.warn?.('[dsh-lan-access] getDshToken failed: ' + (e && e.message));
      return '';
    }
  }

  // ---- Signed session cookie -----------------------------------------------
  function mintSessionCookie() {
    const payload = b64u(Buffer.from(JSON.stringify({ exp: Date.now() + SESSION_TTL_MS })));
    const sig = b64u(createHmac('sha256', sessionKey).update(payload).digest());
    // NOTE: no `Secure` — the proxy is plaintext HTTP by design. If you need
    // encryption, stop this proxy and use an SSH tunnel / TLS reverse proxy.
    return [
      `${SESSION_COOKIE}=${payload}.${sig}`,
      'Path=/',
      `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
      'HttpOnly',
      'SameSite=Lax',
    ].join('; ');
  }

  // The backend's own session cookie is minted with SameSite=Strict
  // (app.asar:371222). A phone link is followed as a CROSS-SITE-INITIATED
  // top-level navigation: the panel lives on http://127.0.0.1:<loopback>, while
  // the link points at http://<lanIP>:<lanPort>. Browsers do not attach
  // SameSite=Strict cookies anywhere in a navigation chain that a cross-site
  // initiator started — and that includes the redirect that follows the token
  // exchange.
  //
  // So the phone DID complete the exchange and DID store the cookie, but it then
  // arrives at GET / with no cookie at all, and `isAuthenticated` fails at
  // app.asar:371361 (`rawCookie === void 0`) -> "dsh web authentication
  // required". Pasting the very same URL into the address bar is user-initiated,
  // so the Strict cookie IS attached and it works. That asymmetry is the entire
  // "tap fails, paste works" bug — no header rewriting on the request side can
  // fix it, because the discrepancy is in how the BROWSER stores and replays the
  // response cookie, not in what we forward.
  //
  // SameSite=Lax is still sent on top-level navigations, so relaxing Strict to
  // Lax is both the minimal fix and safe: it widens only the navigation case,
  // never subresources and never cross-site POST.
  function relaxSameSite(value) {
    if (typeof value !== 'string' || !value) return value;
    return value.replace(/;\s*SameSite\s*=\s*Strict\b/gi, '; SameSite=Lax');
  }

  function verifySessionCookie(header) {
    try {
      const m = new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]+)`).exec(String(header || ''));
      if (!m) return false;
      const raw = String(m[1]);
      const idx = raw.lastIndexOf('.');
      if (idx <= 0) return false;
      const payload = raw.slice(0, idx);
      const got = Buffer.from(raw.slice(idx + 1), 'base64url');
      const want = createHmac('sha256', sessionKey).update(payload).digest();
      if (want.length !== got.length || !timingSafeEqual(want, got)) return false;
      const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      return Number(exp) > Date.now();
    } catch {
      return false;
    }
  }

  // Replaces the old `gatePasses`. Returns `{ ok, mint }`:
  //   ok   — the request may proceed
  //   mint — this request was authorized by `?lt=`, so the caller must exchange
  //          it for a signed session cookie and 302 to a token-free URL.
  // NOTE: a merely non-empty Cookie header is NOT authorization any more.
  function authorize(req) {
    if (!cfg.requireToken) return { ok: true, mint: false };
    try {
      const url = new URL(req.url || '/', 'http://x');
      const lt = url.searchParams.get('lt');
      if (lt && timingSafeStringEqual(lt, cfg.accessToken)) return { ok: true, mint: true };
    } catch {
      // Malformed request target — fall through to the cookie check.
    }
    if (verifySessionCookie(req.headers['cookie'])) return { ok: true, mint: false };
    return { ok: false, mint: false };
  }

  function describeListenError(err) {
    const code = String((err && err.code) || '').toUpperCase();
    if (code === 'EADDRINUSE') {
      return '端口 ' + cfg.lanPort + ' 已被其他程序占用（EADDRINUSE）。请停掉占用它的程序，' +
        '或修改插件配置里的 lanPort 后重载插件。';
    }
    if (code === 'EACCES' || code === 'EPERM') {
      return '端口 ' + cfg.lanPort + ' 被系统拒绝绑定（' + code + '）。Windows 常见原因：该端口落在系统保留段内' +
        '（可用 netsh interface ipv4 show excludedportrange protocol=tcp 查看保留段），' +
        '在插件配置里换一个 lanPort（如 19500）后重载插件通常即可解决。';
    }
    if (code === 'EADDRNOTAVAIL') {
      return '无法在 0.0.0.0:' + cfg.lanPort + ' 上监听（EADDRNOTAVAIL）：本机当前没有任何可用的局域网地址。' +
        '请连上 Wi-Fi / 有线网络后点 “启动代理” 重试。';
    }
    if (code === 'EBADF') {
      return '监听失败（EBADF）：句柄已被关闭，通常是刚发生过停止 / 端口切换。请再点一次 “启动代理”。';
    }
    return '代理启动失败：' + ((err && (err.code ? err.code + ' ' + err.message : err.message)) || String(err));
  }

  let proxyServer = null;
  // `startPromise` is assigned synchronously the moment a start begins, so a
  // second concurrent start() (e.g. auto-start on boot + a manual click in the
  // same tick) cannot open two servers on the same port. The previous guard only
  // checked `proxyServer`, which is still null during listen()'s async callback,
  // so duplicate starts could EADDRINUSE each other — the intermittent "works
  // once, fails other times" behaviour.
  let startPromise = null;
  // A per-attempt token, NOT a shared flag: `startAborted` used to be module-
  // scoped, so a LATE listen callback from attempt N could see `false` (because
  // attempt N+1 had just reset it) and then execute `proxyServer = srv`,
  // silently orphaning attempt N+1's server. A closure token makes each
  // attempt's callback unambiguously its own.
  let startToken = 0;
  let startAborted = null;
  // Set by stopProxy() when there is no server to close yet (i.e. a start is
  // waiting on pendingRelease). Without it, the wait would finish and bind
  // anyway — the user pressed Stop and the proxy came up regardless.
  let stopRequested = false;
  // Every accepted socket, so stopProxy() can destroy the keep-alive/idle ones
  // that would otherwise keep `server.close()`'s callback from ever firing and
  // keep the port bound.
  const sockets = new Set();

  // Browser-trust fence fix: the harness's /api fence (app.asar isTrustedApiRequest)
  // requires Host to be loopback AND any attached Origin to EQUAL that Host, and
  // it refuses sec-fetch-site: cross-site. Our proxy binds 0.0.0.0, so the browser
  // sends Origin/Referer = http://<lanIP>:lanPort and sec-fetch-site: cross-site.
  // We must rewrite those headers to the loopback authority before forwarding, or
  // every /api/* call (directory picker, plugin pages, RPC) gets a 403. The loopback
  // GUI is on the same machine, so spoofing the Origin to its own authority is safe.
  function rewriteBrowserTrustHeaders(headers, backendPort) {
    const lo = `http://${TRUSTED_HOST}:${backendPort}`;
    const out = { ...headers };
    out.host = `${TRUSTED_HOST}:${backendPort}`;
    // Normalise the browser's fetch metadata UNCONDITIONALLY.
    //
    // This is the "tap fails, paste works" fix. The management panel is served
    // from http://127.0.0.1:<loopback>/__lan-access, while the phone link points
    // at http://<lanIP>:<lanPort>/?lt=...&token=... . Following that link with a
    // real tap is a CROSS-ORIGIN top-level navigation, so the browser attaches
    // `sec-fetch-site: cross-site` (and usually `origin`). Pasting the very same
    // URL into the address bar is a user-initiated navigation with no initiator,
    // so the browser attaches NEITHER header.
    //
    // The backend fence (isTrustedRequest) hard-rejects
    // `sec-fetch-site: cross-site` and otherwise demands that `origin`, when
    // present, EQUAL the Host authority — which is loopback after our rewrite.
    // Hence the tap was refused while the paste sailed through, for a URL that
    // was byte-identical.
    //
    // Rewriting only "when the header is already present" (the old behaviour)
    // preserved exactly the cross-site signal that trips the fence. So: always
    // pin `sec-fetch-site` to same-origin, and never forward a foreign `origin`.
    // The loopback GUI is on this same machine, so asserting a loopback
    // self-origin is truthful, not a lie.
    out['sec-fetch-site'] = 'same-origin';
    if (typeof out.origin === 'string' && out.origin) out.origin = lo;
    else delete out.origin;
    if (typeof out.referer === 'string' && out.referer) out.referer = lo + '/';
    else delete out.referer;
    // `sec-fetch-mode: navigate` / `sec-fetch-dest: document` are what make the
    // backend treat this as a top-level page load rather than an RPC, and they
    // are what the launch-token exchange expects. A cross-origin tap may also
    // carry `sec-fetch-user: ?1`; both are preserved as-is, only the SITE is
    // normalised.
    return out;
  }

  function sanitizeRequestHeaders(headers, backendPort, remoteAddr) {
    const out = rewriteBrowserTrustHeaders(headers, backendPort);
    for (const k of Object.keys(out)) {
      if (HOP_HEADERS.has(k.toLowerCase())) delete out[k];
    }
    // Never trust a client-supplied XFF: a LAN client could prepend a spoofed
    // IP and, if the backend reads the left-most entry, poison its logs/ACLs.
    delete out['x-forwarded-for'];
    if (remoteAddr) out['x-forwarded-for'] = remoteAddr;
    return out;
  }

  function sanitizeResponseHeaders(headers) {
    const out = { ...headers };
    for (const k of Object.keys(out)) {
      const lower = k.toLowerCase();
      // Drop any pre-existing `Via` (any casing) so we never emit two.
      if (HOP_HEADERS.has(lower) || lower === 'via') delete out[k];
    }
    out.via = '1.1 dsh-lan-access';
    // Relax the backend's SameSite=Strict on ANY Set-Cookie it sends back, not
    // just on the mint exchange: the phone reaches every page through this proxy
    // as a cross-site-initiated navigation, so a Strict cookie would be dropped
    // on the next hop too and the session would die immediately after login.
    if (Array.isArray(out['set-cookie'])) {
      out['set-cookie'] = out['set-cookie'].map(relaxSameSite);
    } else if (typeof out['set-cookie'] === 'string' && out['set-cookie']) {
      out['set-cookie'] = relaxSameSite(out['set-cookie']);
    }
    return out;
  }

  function pathnameOf(target) {
    try {
      return new URL(target || '/', 'http://x').pathname || '/';
    } catch {
      return '/';
    }
  }

  // Returns a Promise that resolves AFTER the listen attempt settles, so the
  // management UI sees success or the real error. Never rejects.
  function startProxy() {
    // Cleared BEFORE the guard: it must never survive into a later start, or a
    // stop from ten minutes ago would silently cancel a perfectly good one.
    stopRequested = false;
    if (proxyServer || startPromise) return startPromise || Promise.resolve({ ...state });
    // Fallback only: the live port is re-resolved on every single request, so a
    // webServer that bound after us (or rebound later) still works.
    const fallbackPort = ctx.webServer?.port || 0;
    if (!fallbackPort) {
      state.error = 'Loopback web server port is not available yet.';
      ctx.logger?.warn?.('[dsh-lan-access] ' + state.error);
      // 'backend-port', not 'bind': the LAN port is fine, the loopback side
      // isn't. /port must not roll back a good port for someone else's failure.
      return Promise.resolve({ ...state, reason: 'backend-port' });
    }
    if (fallbackPort) state.loopbackPort = fallbackPort;

    // A takeover (or a previous stop) may still be tearing the port down. Wait
    // for it instead of racing it: this is the difference between "reload just
    // works" and "EADDRINUSE until you restart the host".
    if (pendingRelease) {
      const wait = pendingRelease;
      const waited = Promise.race([
        Promise.resolve(wait).catch(() => undefined),
        new Promise((r) => setTimeout(r, 3000)),
      ]);
      // Publish startPromise NOW: the wait itself belongs to this start, or a
      // concurrent /start would sail through the `proxyServer || startPromise`
      // guard and open a second listener on the same port.
      const gate = waited.then(() => {
        // `gate` is initialized by the time this runs (microtask).
        if (proxyServer) return { ...state };
        if (startPromise && startPromise !== gate) return { ...state };
        return beginListen(fallbackPort);
      });
      startPromise = gate;
      // Safety net: the early-return branches below (`proxyServer` already up,
      // superseded start, cancelled by stop) never reach finish(), so they would
      // otherwise leave `startPromise` stuck on a settled gate — and then every
      // later /start would short-circuit on the guard at the top and never bind
      // again, i.e. "must restart the host" all over.
      gate.then(() => { if (startPromise === gate) startPromise = null; },
                () => { if (startPromise === gate) startPromise = null; });
      return gate;
    }
    return beginListen(fallbackPort);
  }

  function beginListen(fallbackPort) {
    const token = ++startToken;
    startAborted = null;
    // Honour a Stop that arrived while we were waiting for the port to free up.
    if (stopRequested) {
      stopRequested = false;
      state.proxyUp = false;
      state.error = '代理启动已取消（收到停止请求）。';
      return Promise.resolve({ ...state, reason: 'cancelled' });
    }

    const srv = createServer((req, res) => {
      // Block the control plane FIRST: /__lan-access (management page) and
      // /__lanapi/* (control API, including the plaintext access token) are
      // registered on the very webServer we proxy to, so without this check a
      // LAN client could read the token and drive the proxy remotely.
      if (isControlPlane(pathnameOf(req.url))) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end('Not found');
        return;
      }

      const auth = authorize(req);
      if (!auth.ok) {
        res.writeHead(401, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end(
          'LAN access denied. Open the LAN Access panel in the DeepSeek Harness desktop GUI and tap the phone sign-in link (or pass ?lt=<token>).'
        );
        return;
      }
      if (auth.mint) {
        // ?lt= matched: the proxy's own gate is satisfied. Do NOT answer the 302
        // here yet — the phone link carries a SECOND one-time credential,
        // `?token=` (the dsh launch token minted by ctx.connection.authenticatedUrl),
        // which only the BACKEND can exchange for its own cookie. If we
        // short-circuit with a 302, the backend never sees `token=`, never sets
        // its cookie, and the post-redirect GET lands on a backend that is still
        // unauthenticated -> "dsh web authentication required; reopen the URL
        // printed by dsh web". That was the "click fails, paste works" bug.
        //
        // So: strip `lt` from the upstream request target (the backend has no use
        // for our gate token and it must not be logged upstream), forward the
        // request so the backend can consume `token=` and reply with its cookie,
        // and rewrite the backend's response into a 302 to the token-free URL.
        // Everything else about the hop is unchanged.
        const up = new URL(req.url || '/', 'http://x');
        up.searchParams.delete('lt');
        const upstreamPath = up.pathname + (up.search || '');
        const clean = new URL(up.toString());
        clean.searchParams.delete('token');
        const cleanQs = clean.searchParams.toString();
        const cleanPath = clean.pathname + (cleanQs ? `?${cleanQs}` : '');

        const backendPort = ctx.webServer?.port || fallbackPort;
        if (!backendPort) {
          res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
          res.end('LAN proxy: 本机 DeepSeek Harness 回环服务端口尚未就绪，请稍后重试。');
          return;
        }

        const mintOptions = {
          host: TRUSTED_HOST,
          port: backendPort,
          method: req.method,
          path: upstreamPath,
          headers: sanitizeRequestHeaders(req.headers, backendPort, req.socket?.remoteAddress),
        };
        const mintReq = httpRequest(mintOptions, (mintRes) => {
          // Pass through the backend's Set-Cookie (its launch-token cookie) AND
          // our own signed session cookie, then bounce the browser to the URL
          // with both one-time credentials removed.
          //
          // The backend's cookie is the whole point of this round trip: it is
          // what stops the follow-up GET from being rejected with "dsh web
          // authentication required". Without it there is nothing to hand the
          // phone, so treat that as a hard, EXPLAINED failure below.
          const status = Number(mintRes.statusCode) || 0;
          const sc = mintRes.headers['set-cookie'];
          const backendSetAnyCookie = Array.isArray(sc) ? sc.length > 0 : (typeof sc === 'string' && sc.length > 0);
          // The exchange only SUCCEEDED if the backend actually handed back its
          // launch-token cookie. Without it the follow-up GET is unauthenticated
          // and the phone sees "dsh web authentication required; reopen the URL
          // printed by dsh web" — the very symptom this branch exists to kill.
          //
          // Previously we 302'd anyway, handing the phone a session cookie for
          // OUR gate but no backend credential: the plugin looked healthy and
          // the user had no way to tell which hop broke. Losing the launch token
          // to an earlier request (link preview, a second tap, a re-render) is
          // the common cause, and it is recoverable — so say so plainly instead
          // of bouncing into an unexplained auth error.
          const exchangeOk = status > 0 && status < 400 && backendSetAnyCookie;
          if (!exchangeOk) {
            try {
              ctx.logger?.warn?.(
                `[dsh-lan-access] phone-link exchange did not yield a backend cookie ` +
                  `(HTTP ${status}, set-cookie: ${backendSetAnyCookie ? 'present' : 'absent'}). ` +
                  'The dsh launch token is single-use; it may have been spent by a link ' +
                  'preview, a second tap, or an earlier render. Reload the panel and tap a freshly minted link.'
              );
            } catch { /* ignore */ }
            if (!res.headersSent && !res.writableEnded) {
              res.writeHead(401, {
                'content-type': 'text/html; charset=utf-8',
                'cache-control': 'no-store',
              });
              res.end(
                '<!doctype html><meta charset="utf-8"><title>LAN Access — 登录令牌已失效</title>' +
                  '<body style="font:15px/1.7 system-ui;padding:32px;max-width:40em">' +
                  '<h1 style="font-size:18px">登录令牌已失效</h1>' +
                  '<p>这条手机登录链接里的 dsh 启动令牌是<b>一次性</b>的，且已经被使用过' +
                  `（后端返回 HTTP ${status || '无响应'}，未下发登录 Cookie）。</p>` +
                  '<p>常见原因：链接被聊天软件的预览抓取过、点过两次、或页面上显示的是旧链接。</p>' +
                  '<p><b>解决办法：</b>回到电脑上的 LAN Access 管理页，点一次“刷新”，' +
                  '然后点击新生成的手机登录链接（旧链接不要再用）。</p>' +
                  '</body>'
              );
            }
            try { mintRes.on('error', () => { /* drained */ }); } catch { /* ignore */ }
            mintRes.resume();
            return;
          }
          const setCookies = [];
          if (Array.isArray(sc)) setCookies.push(...sc.map(relaxSameSite));
          else if (typeof sc === 'string' && sc) setCookies.push(relaxSameSite(sc));
          setCookies.push(mintSessionCookie());
          if (!res.headersSent && !res.writableEnded) {
            res.writeHead(302, {
              'location': cleanPath,
              'set-cookie': setCookies,
              'cache-control': 'no-store',
            });
            res.end();
          }
          // A mid-stream error on the drained backend response must not surface
          // as an unhandled 'error' event now that we no longer pipe it onward.
          try { mintRes.on('error', () => { /* drained: nothing to forward */ }); } catch { /* ignore */ }
          mintRes.resume();
        });
        // A late error (aborted socket, backend reset) can arrive AFTER the
        // response callback already answered. writeHead would then throw
        // ERR_HTTP_HEADERS_SENT inside an 'error' listener, which is an
        // uncaught exception that can take the whole host process down — so the
        // headersSent/writableEnded guard is mandatory here, exactly as the
        // normal proxy path guards its own writeHead.
        mintReq.on('error', () => {
          if (res.headersSent || res.writableEnded) {
            try { res.end(); } catch { /* ignore */ }
            return;
          }
          // Backend unreachable: fall back so the user still gets a session
          // cookie and a usable URL instead of a hard failure.
          res.writeHead(302, {
            'location': cleanPath,
            'set-cookie': mintSessionCookie(),
            'cache-control': 'no-store',
          });
          res.end();
        });
        // Bound the exchange. The outbound socket is NOT tracked in `sockets`
        // (that set only holds accepted client sockets), and a client abort
        // mid-body would otherwise leave this request pending forever with no
        // response and no 'error'.
        const mintTimer = setTimeout(() => {
          try { mintReq.destroy(); } catch { /* ignore */ }
        }, 15000);
        mintReq.on('close', () => clearTimeout(mintTimer));
        req.on('error', () => mintReq.destroy());
        res.on('error', () => mintReq.destroy());
        req.pipe(mintReq);
        return;
      }

      const backendPort = ctx.webServer?.port || fallbackPort;
      if (!backendPort) {
        res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
        res.end('LAN proxy: 本机 DeepSeek Harness 回环服务端口尚未就绪，请稍后重试。');
        return;
      }

      const options = {
        host: TRUSTED_HOST,
        port: backendPort,
        method: req.method,
        path: req.url,
        headers: sanitizeRequestHeaders(req.headers, backendPort, req.socket?.remoteAddress),
      };
      const proxyReq = httpRequest(options, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, sanitizeResponseHeaders(proxyRes.headers));
        proxyRes.pipe(res);
      });
      proxyReq.on('error', () => {
        if (res.headersSent || res.writableEnded) {
          try { res.end(); } catch { /* ignore */ }
          return;
        }
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('Bad gateway: the local DeepSeek Harness GUI is not reachable.');
      });
      req.on('error', () => proxyReq.destroy());
      res.on('error', () => proxyReq.destroy());
      req.pipe(proxyReq);
    });

    srv.on('connection', (socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
    });

    // WebSocket / Upgrade bridging via raw socket piping.
    srv.on('upgrade', (req, clientSocket, head) => {
      if (isControlPlane(pathnameOf(req.url))) {
        try { clientSocket.write('HTTP/1.1 404 Not Found\r\n\r\n'); } catch { /* ignore */ }
        clientSocket.destroy();
        return;
      }
      // WS requests are only verified, never minted: a 302 cannot be expressed
      // on an upgrade, so the cookie must already have been obtained over HTTP.
      const auth = authorize(req);
      if (!auth.ok) {
        try { clientSocket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); } catch { /* ignore */ }
        clientSocket.destroy();
        return;
      }
      const port = ctx.webServer?.port || fallbackPort;
      if (!port) {
        clientSocket.destroy();
        return;
      }
      const upstream = connect(port, TRUSTED_HOST, () => {
        upstream.write(`${req.method} ${req.url} HTTP/1.1\r\n`);
        upstream.write(`Host: ${TRUSTED_HOST}:${port}\r\n`);
        for (const [key, value] of Object.entries(req.headers)) {
          const lower = key.toLowerCase();
          // `host` is rewritten above; `proxy-connection` and `connection` are
          // hop-by-hop and are replaced by our single `Connection: Upgrade`.
          // The rest of HOP_HEADERS is dropped too, matching the HTTP path —
          // but `upgrade` must survive or the handshake dies.
          if (lower === 'host' || lower === 'proxy-connection' || lower === 'connection') continue;
          if (lower !== 'upgrade' && HOP_HEADERS.has(lower)) continue;
          // Rewrite browser-trust markers to the loopback authority so the /api
          // fence treats this as same-origin (see rewriteBrowserTrustHeaders).
          let outKey = key, outVal = value;
          if (lower === 'origin' && typeof value === 'string') outVal = `http://${TRUSTED_HOST}:${port}`;
          else if (lower === 'referer' && typeof value === 'string') outVal = `http://${TRUSTED_HOST}:${port}/`;
          else if (lower === 'sec-fetch-site') outVal = 'same-origin';
          if (Array.isArray(outVal)) {
            for (const v of outVal) upstream.write(`${outKey}: ${v}\r\n`);
          } else {
            upstream.write(`${outKey}: ${outVal}\r\n`);
          }
        }
        upstream.write('Connection: Upgrade\r\n\r\n');
        if (head && head.length) upstream.write(head);
      });
      upstream.on('error', () => clientSocket.destroy());
      clientSocket.on('error', () => upstream.destroy());
      upstream.on('data', (c) => clientSocket.writable && clientSocket.write(c));
      clientSocket.on('data', (c) => upstream.writable && upstream.write(c));
      upstream.on('end', () => clientSocket.end());
      clientSocket.on('end', () => upstream.end());
      upstream.on('close', () => !clientSocket.destroyed && clientSocket.destroy());
      clientSocket.on('close', () => !upstream.destroyed && upstream.destroy());
    });

    const P = new Promise((resolve) => {
      let done = false;
      // Hard safety net: on some hosts listen() can hang (neither 'listening'
      // nor 'error'). Without this the /start request would never respond. If a
      // timeout fires we report a clear diagnostic instead of hanging forever.
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        // Abort first: if listen() lands after this, its callback gives up.
        startAborted = token;
        for (const sock of sockets) {
          try { sock.destroy(); } catch { /* ignore */ }
        }
        sockets.clear();
        try { srv.close(() => {}); } catch { /* ignore */ }
        state.error =
          '在 ' + cfg.lanPort + ' 端口上监听超时（系统既没确认也没报错，通常是 Windows 的网络栈或 VPN / 防火墙拦截）。' +
          '请尝试在插件配置里改用其他高位端口（如 19500、21000）后重载插件。' +
          '若仍失败，本机绑定可能被安全软件拦截，建议改用 SSH 端口转发。';
        ctx.logger?.warn?.('[dsh-lan-access] ' + state.error);
        finish({ ...state });
      }, 8000);
      // The single owner of the outcome. EVERY terminal path — success, listen
      // error, 8s timeout, and abort-by-stopProxy — must go through here.
      // Previously the abort branch just `return`ed without resolving, so the
      // /start HTTP request that was awaiting this promise hung forever (the
      // UI saw a 12s timeout) whenever a stop landed during listen().
      const finish = (st) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (st && !st.proxyUp) {
          proxyServer = null;
          state.proxyUp = false;
        }
        // Cleared unconditionally: keeping the resolved promise around would
        // make a later /start return THIS startup's state snapshot (stale
        // lanPort / phoneUrl) instead of doing real work. `proxyServer` is
        // enough to prevent re-entry.
        startPromise = null;
        resolve(st);
      };
      const onListenError = (err) => {
        state.error = describeListenError(err);
        ctx.logger?.warn?.('[dsh-lan-access] ' + state.error);
        finish({ ...state });
      };
      const onListening = () => {
        srv.removeListener('error', onListenError);
        // Aborted mid-flight (stopProxy / takeover / timeout): close and report
        // through finish() so the awaiting /start request is never orphaned.
        // Also compare the token so a LATE callback from an earlier attempt can
        // never assign itself over a newer attempt's server.
        if (startAborted === token || token !== startToken) {
          try { srv.close(() => {}); } catch { /* ignore */ }
          if (!state.proxyUp) {
            state.error = state.error || '代理启动已中止（停止或重载）。';
          }
          // `cancelled`, not `bind`: nothing was wrong with the port. /port keys
          // off this to decide whether to roll the port back.
          finish({ ...state, reason: 'cancelled' });
          return;
        }
        proxyServer = srv;
        state.proxyUp = true;
        state.loopbackPort = ctx.webServer?.port || fallbackPort;
        state.error = '';
        refreshLanAddrs();
        state.phoneUrl = buildPhoneUrl();
        // Runtime (post-listen) errors are logged, not fatal.
        srv.on('error', (err) => {
          ctx.logger?.warn?.(`[dsh-lan-access] proxy error: ${err && err.message}`);
        });
        ctx.logger?.info?.(
          `[dsh-lan-access] LAN proxy on ${LISTEN_HOST}:${cfg.lanPort} (token via ?lt=). Phone: ${state.phoneUrl}`
        );
        finish({ ...state });
      };
      srv.once('error', onListenError);
      // A synchronous throw here would reject the promise this code lives in —
      // and since finish() never runs, `startPromise` would stay pointing at a
      // rejected promise forever, short-circuiting every later /start at the
      // top guard. That is exactly the "must restart the host" symptom we are
      // fixing, so route synchronous failures through finish() too.
      try {
        srv.listen(cfg.lanPort, LISTEN_HOST, onListening);
      } catch (err) {
        onListenError(err);
      }
    });
    startPromise = P;
    // Belt and braces: if anything in here still threw its way into a rejection,
    // unstick `startPromise` rather than wedging every future /start.
    P.catch(() => { if (startPromise === P) startPromise = null; });
    return P;
  }

  // Truly releases the port: `server.close()` alone only stops accepting, so
  // idle keep-alive sockets (a phone browser tab) keep the handle open, the
  // close callback never fires and the next listen() gets EADDRINUSE. Returns a
  // Promise that settles once the listener is closed (or after 2s, whichever
  // comes first) — never rejects.
  function stopProxy() {
    // Must be set BEFORE touching the server, so a listen() still in flight
    // abandons itself instead of resurrecting after we return. It targets the
    // CURRENT attempt token only, so a later attempt is never cancelled by a
    // stale stop. The in-flight listen still resolves — through finish() — so
    // the /start request awaiting it is never orphaned.
    startAborted = startToken;
    stopRequested = true;
    const srv = proxyServer;
    proxyServer = null;
    state.proxyUp = false;
    state.phoneUrl = '';
    if (!srv) return Promise.resolve();
    if (typeof srv.closeAllConnections === 'function') {
      try { srv.closeAllConnections(); } catch { /* ignore */ }
    }
    for (const sock of sockets) {
      try { sock.destroy(); } catch { /* ignore */ }
    }
    sockets.clear();
    // Read the bound port BEFORE close(): afterwards `srv.address()` returns
    // null, leaving nothing but cfg.lanPort — which during a /port change has
    // already advanced to the new port, so we would probe the wrong socket.
    let bound = 0;
    try { bound = (srv.address() && srv.address().port) || 0; } catch { /* ignore */ }
    // Publish the release so a NEW instance that takes over the slot (or a
    // follow-up /start) can await the handle actually being freed instead of
    // racing it into EADDRINUSE.
    const release = new Promise((resolve) => {
      let settled = false;
      const fin = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(fin, 2000);
      try { srv.close(fin); } catch { fin(); }
    }).then(() => {
      // Best-effort: confirm the port is actually free before we tell anyone
      // it is. The 2s fallback can fire while the handle is still lingering.
      return waitForPortFree(bound || cfg.lanPort, 1500).catch(() => undefined);
    });
    pendingRelease = release;
    // Clear only if no newer stop has replaced us.
    release.then(() => { if (pendingRelease === release) pendingRelease = null; },
                 () => { if (pendingRelease === release) pendingRelease = null; });
    ctx.logger?.info?.('[dsh-lan-access] LAN proxy stopped.');
    return release;
  }

  // Probe-bind <port> until it is free (or the budget runs out). Used after
  // stopProxy() so a rebind right behind it cannot hit EADDRINUSE.
  //
  // The probe MUST bind the same address the real listener uses ('0.0.0.0') —
  // probing 127.0.0.1 instead is useless on Windows, where SO_REUSEADDR lets a
  // more specific bind coexist with a wildcard one, so the probe would "succeed"
  // while the port is still occupied and the real bind would then fail anyway.
  function waitForPortFree(port, budgetMs = 1200) {
    return new Promise((resolve) => {
      let answered = false;
      // Hard ceiling: never let a wedged probe hang the release chain (and
      // therefore mine.dispose()) forever.
      const guard = setTimeout(() => {
        if (answered) return;
        answered = true;
        resolve(false);
      }, budgetMs + 500);
      const settle = (v) => {
        if (answered) return;
        answered = true;
        clearTimeout(guard);
        resolve(v);
      };
      const deadline = Date.now() + budgetMs;
      // Chain attempts (never overlap) so we don't fight ourselves for the port.
      const step = () => {
        if (answered) return;
        const probe = createServer();
        // Keep a listener attached for the whole lifetime: `once('error')` would
        // remove itself, and a later emit with no listener is an uncaught
        // exception that can take the host process down.
        probe.on('error', () => {});
        const retry = () => {
          if (answered) return;
          if (Date.now() > deadline) { settle(false); return; }
          setTimeout(step, 250);
        };
        // Wait for close's callback before deciding: resolving while the probe
        // handle is still open would let the real bind race the probe's own
        // teardown — re-creating the very EADDRINUSE we are preventing.
        probe.once('error', () => {
          try { probe.close(() => retry()); } catch { retry(); }
        });
        probe.once('listening', () => {
          try { probe.close(() => settle(true)); } catch { settle(true); }
        });
        probe.listen(port, LISTEN_HOST);
      };
      step();
    });
  }

  // Stop fully, then start: guarantees a port change / reload takes effect
  // without restarting the host.
  function ensureStarted() {
    const portNow = () => ctx.webServer?.port || 0;
    return Promise.resolve(stopProxy())
      .then(() => (portNow() ? portNow() : waitForBackendPort(5000, 250)))
      .then((port) => {
        refreshLoopbackPort();
        if (!port) {
          state.error = 'Loopback web server port is not available yet.';
          ctx.logger?.warn?.('[dsh-lan-access] ' + state.error);
          return { ...state, reason: 'backend-port' };
        }
        return Promise.resolve(startProxy()).then((st) => {
          // `reason` tells /port whether this failure was about the port it
          // just applied (roll back) or about something else entirely. A reason
          // already set deeper (e.g. 'cancelled') is more specific — keep it.
          if (st.proxyUp || st.reason) return st;
          return { ...st, reason: st.error ? 'bind' : 'unknown' };
        });
      });
  }

  function rotateToken() {
    cfg.accessToken = randomBytes(24).toString('hex');
    // Key line: deriving a new session key invalidates every cookie minted
    // under the old token, so "rotate" really logs every device out.
    sessionKey = deriveSessionKey(cfg.accessToken);
    state.accessToken = cfg.accessToken;
    // Unconditional: the phone URL must reflect the NEW token even while the
    // proxy is down, otherwise the UI can hand out a link with a dead token.
    state.phoneUrl = buildPhoneUrl();
  }

  // The backend port is not known at apply() time — the webServer usually binds
  // AFTER plugins load. Poll instead of giving up; without this, autoStart (the
  // default) could never succeed and the user had to click Start by hand.
  function waitForBackendPort(timeoutMs = 60000, stepMs = 500) {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve) => {
      const tick = () => {
        const p = ctx.webServer?.port;
        if (p) return resolve(p);
        if (Date.now() > deadline) return resolve(0);
        setTimeout(tick, stepMs);
      };
      tick();
    });
  }

  // ---- Management endpoints (registered on the built-in webServer) ----------
  // These live on the SAME server the LAN proxy forwards to. They are NOT
  // "127.0.0.1 only" by construction any more: the proxy is gated separately and
  // hard-404s CONTROL_PATHS at its own entry point (see isControlPlane). Treat
  // that 404 as the real boundary, and never put a secret here that you would
  // mind a LAN client reading (the plaintext token here is exactly why the
  // proxy 404s /__lanapi).
  //
  // PREFIX routes, not exact: the SPA dist server owns the fallback seat and
  // returns an EMPTY 404 for any non-file path that no exact route claims. An
  // exact route can fall through to that empty 404, which makes
  // `fetch().json()` throw "unexpected end of data". A prefix route matches
  // independently of the SPA fallback and is never served as an empty 404.
  const json = (res, code, obj) => {
    const body = JSON.stringify(obj == null ? {} : obj);
    // Every control-API reply is no-store. /status carries the plaintext access
    // token (shown in full by request) and a fresh launch token; letting a
    // browser or intermediary cache it would leak the secret to disk and could
    // hand a STALE one-time link back to the user.
    res.writeHead(code, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    res.end(body);
  };

  // Run a host disposer at most once, so calling it from both
  // `ctx.on('dispose', …)` and `mine.dispose()` (takeover) is harmless.
  const once = (fn) => {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      try { fn(); } catch (e) { ctx.logger?.warn?.('[dsh-lan-access] dispose: ' + (e && e.message)); }
    };
  };

  // `ctx.webServer.register(route)` is evaluated eagerly (registering the route
  // now) and returns a disposer, which `ctx.on('dispose', …)` then runs on
  // teardown. A correct Cordis idiom for effect-scoped registrations — but only
  // if the disposer really is a function (a non-function would make ctx.on
  // throw and fail plugin activation).
  const reg = (route) => {
    const d = ctx.webServer.register(route);
    if (typeof d === 'function') {
      const w = once(d);
      disposers.push(w);
      ctx.on('dispose', w);
    }
    return d;
  };

  // Always respond with a non-empty JSON body, even if a handler throws, and
  // surface the real error reason (not just "handler-error") so it is debuggable.
  const fail = (res, e) => {
    try {
      if (res.headersSent || res.writableEnded) { res.end(); return; }
      json(res, 500, { error: 'handler-error', detail: String((e && (e.stack || e.message)) || e) });
    } catch { /* nothing left to do */ }
  };
  const guard = (res, fn) => {
    try { fn(); } catch (e) { fail(res, e); }
  };
  // Async variant: `guard` only catches synchronous throws, so anything thrown
  // inside `req.on('end')` or a `.then()` escaped as an unhandled rejection and
  // could take the host down. Every async path uses this instead.
  const guardAsync = (res, fn) => {
    let p;
    try { p = fn(); } catch (e) { fail(res, e); return; }
    Promise.resolve(p).catch((e) => fail(res, e));
  };

  // CSRF guard for the state-changing control endpoints. Any web page the user
  // visits can fire a cross-site simple POST (text/plain needs no preflight);
  // the response is unreadable but the SIDE EFFECT lands — token rotated,
  // proxy stopped, port changed. Absent Origin/Sec-Fetch-Site is allowed so
  // local tooling (curl, the host's own fetch) keeps working; we only reject
  // positively-cross-site evidence.
  const crossSite = (req) => {
    const origin = req.headers.origin;
    if (typeof origin === 'string' && origin.length) {
      return !/^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i.test(origin.trim());
    }
    const site = req.headers['sec-fetch-site'];
    if (typeof site === 'string' && site.length) {
      return !['same-origin', 'same-site', 'none'].includes(site.toLowerCase());
    }
    return false;
  };

  reg({ kind: 'prefix', path: '/__lanapi', handler: (req, res) => {
    const sub = (req.url || '/').split('?')[0].replace(/^\/__lanapi/, '') || '/';
    const method = (req.method || 'GET').toUpperCase();
    if (sub === '/status') {
      return guard(res, () => {
        refreshLoopbackPort();
        refreshLanAddrs();
        if (state.proxyUp) {
          state.dshToken = getDshToken();
          state.phoneUrl = buildPhoneUrl();
        }
        json(res, 200, { ...state });
      });
    }
    if (sub === '/phone-url') {
      return guard(res, () => {
        refreshLoopbackPort();
        refreshLanAddrs();
        const urls = state.proxyUp ? buildPhoneUrls() : [];
        json(res, urls.length ? 200 : 500, { phoneUrl: urls[0]?.url || '', urls });
      });
    }
    if (sub === '/start') {
      if (method !== 'POST') return json(res, 405, { error: 'method' });
      if (crossSite(req)) return json(res, 403, { error: 'cross-site-denied' });
      return guardAsync(res, () => {
        // Stop fully first, then await the listen attempt so the UI sees
        // success OR the real bind error. No host restart needed.
        return ensureStarted().then((st) => json(res, st.proxyUp ? 200 : 500, st));
      });
    }
    if (sub === '/stop') {
      if (method !== 'POST') return json(res, 405, { error: 'method' });
      if (crossSite(req)) return json(res, 403, { error: 'cross-site-denied' });
      return guardAsync(res, () => Promise.resolve(stopProxy()).then(() => json(res, 200, { ...state })));
    }
    if (sub === '/rotate') {
      if (method !== 'POST') return json(res, 405, { error: 'method' });
      if (crossSite(req)) return json(res, 403, { error: 'cross-site-denied' });
      return guard(res, () => {
        rotateToken();
        json(res, 200, { accessToken: state.accessToken, phoneUrl: state.phoneUrl });
      });
    }
    json(res, 404, { error: 'unknown-api-path', sub });
  } });

  reg({ kind: 'prefix', path: '/__lan-access', handler: (req, res) => {
    const p = (req.url || '/').split('?')[0] || '/';
    if (p !== '/__lan-access' && p !== '/__lan-access/') {
      return guard(res, () => json(res, 404, { error: 'not-found', path: p }));
    }
    return guard(res, () => {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(managementHtml());
    });
  } });

  // Floating entry badge in the GUI itself (host-side HTML injection).
  const tapDisposer = ctx.webServer.tapIndex((html) => {
    const badge =
      '<div id="dsh-lan-access-badge" style="position:fixed;right:12px;bottom:12px;z-index:2147483647;font:13px system-ui,sans-serif">' +
      '<a href="/__lan-access" target="_blank" rel="noreferrer" ' +
      'style="background:#2f6df6;color:#fff;padding:8px 12px;border-radius:8px;text-decoration:none;box-shadow:0 2px 8px rgba(0,0,0,.25)">' +
      'LAN Access</a></div>';
    if (/<\/body>/i.test(html)) return html.replace(/<\/body>/i, badge + '</body>');
    return html + badge;
  });
  if (typeof tapDisposer === 'function') {
    const w = once(tapDisposer);
    disposers.push(w);
    ctx.on('dispose', w);
  }

  function managementHtml() {
    return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LAN Access — DeepSeek Harness</title>
<style>
 body{font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#1f2330}
 h1{font-size:20px}code{background:#eef1f6;padding:2px 6px;border-radius:6px}
 .card{border:1px solid #d8dde8;border-radius:12px;padding:16px;margin:14px 0}
 .warn{border-color:#f0b429;background:#fff8e6}
 .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0}
 button{font:inherit;border:1px solid #2f6df6;background:#2f6df6;color:#fff;border-radius:8px;padding:8px 14px;cursor:pointer}
 button.ghost{background:#fff;color:#2f6df6}
 button:disabled{opacity:.5;cursor:wait}
 input{font:inherit;padding:6px 8px;border:1px solid #cdd3df;border-radius:8px;width:120px}
 .muted{color:#6b7280}
 #phone{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:10px;word-break:break-all}
 #phone a{color:#93c5fd}
 #phone .u{display:flex;gap:8px;align-items:flex-start;margin:4px 0}
 .err{color:#dc2626}
 a{color:#2f6df6}
</style></head><body>
<h1>LAN Access</h1>
<p class="muted">把本机 DeepSeek Harness GUI 反向代理到局域网，供手机访问。
管理页与控制接口由代理层拦截（局域网访问返回 404），不会从网络侧打开。</p>
<div class="card warn"><b>明文警告。</b>手机与电脑之间的流量是<b>未加密的 HTTP</b>，
同一 Wi-Fi/局域网内的任何人都可能读到。请只在可信网络使用，并把访问令牌当作密码保管。
需要加密时请停用本代理，改用 SSH 隧道或带 TLS 的反向代理。</div>
<div class="card" id="status">加载中…（若长时间不动，点右侧“刷新”）</div>
<div class="card">
 <div class="row"><button id="start">启动代理</button><button id="stop" class="ghost">停止代理</button>
 <button id="rotate" class="ghost">轮换令牌</button>
 <button id="refresh" class="ghost">刷新</button></div>
 <div class="row muted" id="msg"></div>
</div>
<div class="card">
 <div class="row"><b>手机登录链接（每个局域网 IP 一条）</b></div>
 <p class="muted">手机浏览器打开其中一条即可完成一次性登录（选手机同一网段的那个 IP），
 登录后令牌会从地址栏消失（302 换成签名会话 Cookie，12 小时有效）；
 点“轮换令牌”可让所有已登录设备立即失效。<br>
 链接里的 dsh 启动令牌是<b>一次性</b>的：请用下面的“打开/复制”按钮，
 不要直接用聊天软件转发（预览会提前消耗掉令牌）。</p>
 <div id="phone">—</div>
</div>
<script>
 const api=(p,o)=>new Promise((res,rej)=>{
   const c=new AbortController();
   const t=setTimeout(()=>c.abort(),12000);
   fetch('/__lanapi'+p,Object.assign({signal:c.signal},o||{}))
     .then(r=>r.text())
     .then(v=>{clearTimeout(t); if(!v){rej(new Error('empty body'));return;} try{res(JSON.parse(v));}catch(e){rej(new Error('not JSON: '+String(v).slice(0,200)));}})
     .catch(e=>{clearTimeout(t);rej(e);});
 });
 function esc(s){const d=document.createElement('div');d.textContent=String(s??'');return d.innerHTML;}
 function setMsg(m){const e=document.getElementById('msg');if(e)e.textContent=m||'';}
 async function load(){
   try{
     const s=await api('/status');
     document.getElementById('status').innerHTML=
       '<div class="row"><b>状态:</b> '+(s.proxyUp?'<span style="color:#16a34a">运行中</span>':'<span class="err">已停止</span>')+'</div>'+
       '<div class="row"><b>LAN 监听:</b> <code>0.0.0.0:'+esc(s.lanPort)+'</code></div>'+
       '<div class="row"><b>回环后端:</b> <code>127.0.0.1:'+esc(s.loopbackPort)+'</code></div>'+
       '<div class="row"><b>令牌门:</b> '+(s.requireToken?'开启（需要 ?lt= 或签名会话 Cookie）':'关闭（对局域网完全开放！）')+'</div>'+
       '<div class="row"><b>访问令牌:</b> <code>'+esc(s.accessToken)+'</code></div>'+
       '<div class="row"><b>局域网 IP:</b> '+esc((s.lanAddrs||[]).join(', ')||'(未找到)')+'</div>'+
       (s.error?'<div class="row err"><b>错误:</b> '+esc(s.error)+'</div>':'');
     const box=document.getElementById('phone');
     box.innerHTML='';
     const urls=(()=>{ if(!s.proxyUp) return []; const tk=encodeURIComponent(s.accessToken||''); const dt=s.dshToken?('&token='+encodeURIComponent(s.dshToken)):''; const pr=encodeURIComponent(s.lanPort||''); return (s.lanAddrs||[]).map(ip=>({ip,url:'http://'+ip+':'+pr+'/?lt='+tk+dt})); })();
     if(!urls.length){box.textContent='(代理未运行——请先点启动代理)';}
     for(const u of urls){
       const row=document.createElement('div');row.className='u';
       // Re-mint the link at click time: the dsh launch token is single-use, so a
       // link rendered minutes ago (or already fetched by a preview bot) is dead.
       const fresh=async()=>{try{const r=await api('/phone-url');const hit=(r.urls||[]).find(x=>x.ip===u.ip)||(r.urls&&r.urls[0]);if(hit&&hit.url)return hit.url;}catch(e){}return u.url;};
       const a=document.createElement('a');a.href=u.url;a.target='_blank';a.rel='noreferrer';a.textContent=u.url;
       a.onclick=async(ev)=>{if(a.dataset.fresh)return;ev.preventDefault();a.dataset.fresh='1';const url=await fresh();window.open(url,'_blank','noopener');};
       const b=document.createElement('button');b.className='ghost';b.textContent='复制';
       b.onclick=async()=>{const t=await fresh();let ok=false;try{if(navigator.clipboard&&navigator.clipboard.writeText){await navigator.clipboard.writeText(t);ok=true;}}catch(err){}if(!ok){window.prompt('复制下面这条链接：',t);b.textContent='请手动复制';}else{b.textContent='已复制';}};
       row.appendChild(a);row.appendChild(b);box.appendChild(row);
     }
   }catch(e){document.getElementById('status').innerHTML='<div class="err">加载失败（请求超时或后端无响应）：'+esc(e&&e.message)+'</div>';}
 }
 const run=(id,p,o,ok)=>{const b=document.getElementById(id);b.onclick=async()=>{b.disabled=true;setMsg('处理中…');try{const st=await api(p,o);ok&&ok(st);}catch(e){setMsg('请求失败：'+(e&&e.message));}finally{b.disabled=false;await load();setMsg('');}};};
 run('start','/start',{method:'POST'},(st)=>{setMsg(st&&st.proxyUp?'已启动。':'启动未成功，请见上方“错误”。');});
 run('stop','/stop',{method:'POST'},()=>setMsg('已停止。'));
 run('rotate','/rotate',{method:'POST'},()=>setMsg('已轮换令牌，所有手机需重新登录。'));
 document.getElementById('refresh').onclick=()=>load();
 load();
</script></body></html>`;
  }

  // Idempotent teardown for THIS instance. Also invoked by a newer instance
  // taking over the slot, which is what makes a config reload take effect
  // without restarting DeepSeek Harness.
  mine.dispose = () => {
    if (mine.disposed) return pendingRelease || Promise.resolve();
    mine.disposed = true;
    for (const d of disposers.splice(0)) {
      try { d(); } catch (e) { ctx.logger?.warn?.('[dsh-lan-access] dispose: ' + (e && e.message)); }
    }
    // RETURN the release promise: the caller (a takeover) must await it, or the
    // new instance binds while the old handle is still open.
    let release;
    try { release = Promise.resolve(stopProxy()).catch(() => undefined); }
    catch (e) {
      ctx.logger?.warn?.('[dsh-lan-access] dispose stopProxy: ' + (e && e.message));
      release = Promise.resolve();
    }
    // Only clear the slot if we still own it — otherwise we would delete the
    // slot of the instance that just took over from us.
    if (globalThis[SLOT] === mine) delete globalThis[SLOT];
    return release;
  };
  ctx.on('dispose', () => mine.dispose());

  if (cfg.autoStart) {
    // Never silently give up because the backend port was not ready yet: wait
    // for it (up to 60s) and only then start.
    waitForBackendPort()
      .then((port) => {
        refreshLoopbackPort();
        if (!port) {
          state.error = 'Loopback web server port is not available yet (waited 60s).';
          ctx.logger?.warn?.('[dsh-lan-access] auto-start: ' + state.error + ' 请在管理页点“启动代理”。');
          return undefined;
        }
        return Promise.resolve(startProxy()).then((st) => {
          if (st.error) ctx.logger?.warn?.('[dsh-lan-access] auto-start: ' + st.error);
          return undefined;
        });
      })
      .catch((e) => {
        ctx.logger?.warn?.('[dsh-lan-access] auto-start failed: ' + (e && (e.stack || e.message)));
      });
  }
}
