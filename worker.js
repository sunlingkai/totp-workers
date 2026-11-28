addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

// TOTP 核心计算引擎（遵循 RFC 6238，支持 SHA-1 / SHA-256 / SHA-512）
class TOTP {
  static normalizeAlgorithm(algo = 'SHA-1') {
    const clean = String(algo || 'SHA-1').toUpperCase().replace(/[^A-Z0-9]/g, '')
    if (clean === 'SHA256') return 'SHA-256'
    if (clean === 'SHA512') return 'SHA-512'
    return 'SHA-1'
  }

  static cleanBase32(secret) {
    return String(secret || '')
      .toUpperCase()
      .replace(/[\s-]+/g, '')
      .replace(/=+$/g, '')
  }

  static base32Decode(secret) {
    const cleaned = this.cleanBase32(secret)
    if (!cleaned) return null
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    let bits = ''
    for (let i = 0; i < cleaned.length; i++) {
      const idx = chars.indexOf(cleaned[i])
      if (idx === -1) return null
      bits += idx.toString(2).padStart(5, '0')
    }
    const bytes = []
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2))
    }
    return bytes.length > 0 ? new Uint8Array(bytes) : null
  }

  static async hmac(key, data, algorithm = 'SHA-1') {
    const hash = this.normalizeAlgorithm(algorithm)
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash },
      false,
      ['sign']
    )
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, data)
    return new Uint8Array(signature)
  }

  static async generate(secret, digits = 6, period = 30, timestamp = Date.now(), algorithm = 'SHA-1') {
    const key = this.base32Decode(secret)
    if (!key) return null

    const safeDigits = [6, 8].includes(Number(digits)) ? Number(digits) : 6
    const safePeriod = Number(period) > 0 ? Number(period) : 30
    const counter = Math.floor(timestamp / 1000 / safePeriod)

    const buffer = new ArrayBuffer(8)
    const view = new DataView(buffer)
    view.setUint32(0, Math.floor(counter / 0x100000000), false)
    view.setUint32(4, counter >>> 0, false)

    const hmac = await this.hmac(key, new Uint8Array(buffer), algorithm)
    const offset = hmac[hmac.length - 1] & 0x0f
    const truncated =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)

    const code = (truncated >>> 0) % (10 ** safeDigits)
    return code.toString().padStart(safeDigits, '0')
  }
}

async function handleRequest(request) {
  // 保留 POST / 接口以兼容既有脚本或 API 调用
  if (request.method === 'POST') {
    try {
      const contentType = request.headers.get('content-type') || ''
      let secret = ''
      let digits = 6
      let period = 30
      let algorithm = 'SHA-1'

      if (contentType.includes('application/json')) {
        const body = await request.json()
        secret = body.secret || ''
        digits = parseInt(body.digits || '6', 10)
        period = parseInt(body.period || '30', 10)
        algorithm = body.algorithm || 'SHA-1'
      } else {
        const formData = await request.formData()
        secret = formData.get('secret') || ''
        digits = parseInt(formData.get('digits') || '6', 10)
        period = parseInt(formData.get('period') || '30', 10)
        algorithm = formData.get('algorithm') || 'SHA-1'
      }

      const safePeriod = Number.isFinite(period) && period > 0 ? period : 30
      const token = await TOTP.generate(secret, digits, safePeriod, Date.now(), algorithm)
      if (!token) {
        return new Response(JSON.stringify({
          error: 'Invalid secret key. Please use valid Base32 format.',
          success: false
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' }
        })
      }

      const timeLeft = safePeriod - (Math.floor(Date.now() / 1000) % safePeriod)
      return new Response(JSON.stringify({
        token,
        timeLeft,
        success: true
      }), {
        headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' }
      })
    } catch (error) {
      return new Response(JSON.stringify({
        error: 'Invalid request payload.',
        success: false
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json; charset=UTF-8', 'Cache-Control': 'no-store' }
      })
    }
  }

  return new Response(renderHTML(), {
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    }
  })
}

function renderHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>2FA 验证码生成器</title>
  <script>
    (function () {
      try {
        var saved = localStorage.getItem('totp-theme');
        var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        var theme = saved || (prefersDark ? 'dark' : 'light');
        document.documentElement.setAttribute('data-theme', theme);
      } catch (e) {}
    })();
  </script>
  <style>
    :root {
      --bg: #f3f6fb;
      --bg-glow-1: rgba(59, 130, 246, 0.12);
      --bg-glow-2: rgba(16, 185, 129, 0.08);
      --card: #ffffff;
      --card-border: rgba(15, 23, 42, 0.08);
      --card-shadow: 0 20px 50px -20px rgba(15, 23, 42, 0.16), 0 4px 14px -4px rgba(15, 23, 42, 0.06);
      --text: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --surface-subtle: #f8fafc;
      --surface-hover: #f1f5f9;
      --input-bg: #f8fafc;
      --input-border: #cbd5e1;
      --input-focus: #3b82f6;
      --segment-bg: #eef2f7;
      --segment-active: #ffffff;
      --segment-shadow: 0 1px 3px rgba(15, 23, 42, 0.1);
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --accent-soft: rgba(37, 99, 235, 0.1);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.12);
      --warning: #f59e0b;
      --danger: #f43f5e;
      --danger-bg: rgba(244, 63, 94, 0.1);
      --hero-bg: linear-gradient(150deg, #0f172a 0%, #17233b 55%, #111c33 100%);
      --hero-border: rgba(148, 163, 184, 0.18);
      --hero-text: #f8fafc;
      --hero-muted: #94a3b8;
      --hero-ring-track: rgba(148, 163, 184, 0.22);
      --hero-chip-bg: rgba(255, 255, 255, 0.08);
      --hero-chip-hover: rgba(255, 255, 255, 0.14);
      --radius-xl: 22px;
      --radius-lg: 16px;
      --radius-md: 12px;
      --radius-sm: 9px;
      --mono: ui-monospace, 'SFMono-Regular', 'JetBrains Mono', 'Cascadia Mono', Consolas, Menlo, monospace;
      --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
    }

    [data-theme="dark"] {
      --bg: #080d17;
      --bg-glow-1: rgba(56, 189, 248, 0.12);
      --bg-glow-2: rgba(99, 102, 241, 0.12);
      --card: #111827;
      --card-border: rgba(148, 163, 184, 0.14);
      --card-shadow: 0 24px 60px -20px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.03);
      --text: #f1f5f9;
      --text-secondary: #cbd5e1;
      --text-muted: #94a3b8;
      --surface-subtle: #0f172a;
      --surface-hover: #1e293b;
      --input-bg: #0b1220;
      --input-border: rgba(148, 163, 184, 0.22);
      --input-focus: #60a5fa;
      --segment-bg: #0b1220;
      --segment-active: #1e293b;
      --segment-shadow: 0 1px 4px rgba(0, 0, 0, 0.45);
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --accent-soft: rgba(59, 130, 246, 0.16);
      --hero-bg: linear-gradient(150deg, #090f1d 0%, #111c33 55%, #0c1528 100%);
      --hero-border: rgba(148, 163, 184, 0.16);
    }

    *, *::before, *::after { box-sizing: border-box; }

    html, body {
      margin: 0;
      padding: 0;
      min-height: 100%;
    }

    body {
      font-family: var(--sans);
      background-color: var(--bg);
      background-image:
        radial-gradient(640px 340px at 15% -10%, var(--bg-glow-1), transparent 70%),
        radial-gradient(560px 320px at 88% 0%, var(--bg-glow-2), transparent 70%);
      color: var(--text);
      line-height: 1.5;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 20px 16px 32px;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.2s ease, color 0.2s ease;
    }

    .shell {
      width: 100%;
      max-width: 500px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    /* 顶部栏 */
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 4px 2px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 11px;
      min-width: 0;
    }

    .logo-wrap {
      height: 36px;
      min-width: 36px;
      border-radius: 10px;
      background: #ffffff;
      border: 1px solid var(--card-border);
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      box-shadow: 0 2px 8px rgba(15, 23, 42, 0.07);
      overflow: hidden;
      padding: 5px 8px;
    }

    .logo-wrap img {
      height: 22px;
      width: auto;
      max-width: 84px;
      object-fit: contain;
      display: block;
    }

    .logo-fallback {
      display: none;
      width: 20px;
      height: 20px;
      color: #2563eb;
    }

    .brand-title {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .brand-title h1 {
      margin: 0;
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text);
    }

    .privacy-pill {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 999px;
      color: #059669;
      background: var(--success-bg);
      white-space: nowrap;
    }

    [data-theme="dark"] .privacy-pill {
      color: #34d399;
    }

    .theme-btn {
      width: 38px;
      height: 38px;
      border-radius: 11px;
      border: 1px solid var(--card-border);
      background: var(--card);
      color: var(--text-secondary);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      flex-shrink: 0;
      transition: transform 0.15s ease, background-color 0.15s ease, color 0.15s ease, border-color 0.15s ease;
    }

    .theme-btn:hover {
      background: var(--surface-hover);
      color: var(--text);
    }

    .theme-btn:active {
      transform: scale(0.95);
    }

    .icon-sun { display: none; }
    .icon-moon { display: block; }
    [data-theme="dark"] .icon-sun { display: block; }
    [data-theme="dark"] .icon-moon { display: none; }

    /* 主卡片 */
    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: var(--radius-xl);
      box-shadow: var(--card-shadow);
      overflow: hidden;
    }

    /* 顶部验证码展示区 (Hero Stage) */
    .hero {
      position: relative;
      background: var(--hero-bg);
      color: var(--hero-text);
      padding: 22px 22px 20px;
      border-bottom: 1px solid var(--hero-border);
      --timer-color: #38bdf8;
    }

    .hero.state-warn { --timer-color: #f59e0b; }
    .hero.state-danger { --timer-color: #f43f5e; }
    .hero.state-idle { --timer-color: #475569; }

    .top-progress {
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 3px;
      background: rgba(148, 163, 184, 0.18);
      overflow: hidden;
    }

    .top-progress-fill {
      height: 100%;
      width: 100%;
      background: var(--timer-color);
      transform-origin: left center;
      transform: scaleX(0);
      transition: background-color 0.25s ease;
      will-change: transform;
    }

    .hero-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 14px;
    }

    .hero-label-group {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }

    .hero-label {
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--hero-muted);
      white-space: nowrap;
    }

    .account-tag {
      display: none;
      max-width: 210px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-size: 0.74rem;
      font-weight: 500;
      color: #bae6fd;
      background: rgba(56, 189, 248, 0.14);
      border: 1px solid rgba(56, 189, 248, 0.25);
      padding: 2px 8px;
      border-radius: 999px;
    }

    .account-tag.visible { display: inline-block; }

    /* 环形倒计时 */
    .countdown-pill {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 4px 10px 4px 6px;
      border-radius: 999px;
      background: var(--hero-chip-bg);
      font-family: var(--mono);
      font-size: 0.84rem;
      font-weight: 600;
      font-variant-numeric: tabular-nums;
      color: var(--hero-text);
      flex-shrink: 0;
    }

    .ring-svg {
      width: 22px;
      height: 22px;
      transform: rotate(-90deg);
      display: block;
    }

    .ring-track {
      fill: none;
      stroke: var(--hero-ring-track);
      stroke-width: 3;
    }

    .ring-fill {
      fill: none;
      stroke: var(--timer-color);
      stroke-width: 3;
      stroke-linecap: round;
      transition: stroke 0.25s ease;
    }

    /* 可直接点击复制的验证码区域 */
    .code-hitbox {
      position: relative;
      border-radius: var(--radius-lg);
      padding: 18px 14px 14px;
      text-align: center;
      border: 1px solid rgba(148, 163, 184, 0.16);
      background: rgba(255, 255, 255, 0.03);
      transition: border-color 0.2s ease, background-color 0.2s ease, transform 0.12s ease, box-shadow 0.2s ease;
      user-select: none;
      outline: none;
    }

    .code-hitbox.ready {
      cursor: pointer;
    }

    .code-hitbox.ready:hover,
    .code-hitbox.ready:focus-visible {
      border-color: rgba(96, 165, 250, 0.55);
      background: rgba(59, 130, 246, 0.09);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
    }

    .code-hitbox.ready:active {
      transform: scale(0.99);
    }

    .code-hitbox.copied {
      border-color: rgba(16, 185, 129, 0.85) !important;
      background: rgba(16, 185, 129, 0.14) !important;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.22) !important;
    }

    .token-value {
      font-family: var(--mono);
      font-size: clamp(2.55rem, 10vw, 3.55rem);
      font-weight: 700;
      letter-spacing: 0.12em;
      line-height: 1.15;
      font-variant-numeric: tabular-nums;
      color: var(--hero-text);
      padding-left: 0.12em;
      white-space: nowrap;
      transition: color 0.2s ease, opacity 0.2s ease;
    }

    .token-value.is-8digit {
      font-size: clamp(2.05rem, 8.2vw, 2.95rem);
      letter-spacing: 0.08em;
      padding-left: 0.08em;
    }

    .token-value.is-empty {
      color: rgba(148, 163, 184, 0.42);
      letter-spacing: 0.18em;
    }

    .token-value.is-empty.is-8digit {
      letter-spacing: 0.12em;
      padding-left: 0.12em;
    }

    .token-value.is-error {
      color: #fda4af;
      font-size: clamp(1.2rem, 4.5vw, 1.45rem);
      letter-spacing: 0.02em;
      padding: 12px 0;
    }

    .click-hint {
      margin-top: 8px;
      font-size: 0.78rem;
      color: var(--hero-muted);
      display: inline-flex;
      align-items: center;
      gap: 5px;
      transition: color 0.2s ease;
    }

    .code-hitbox.ready:hover .click-hint {
      color: #bfdbfe;
    }

    .code-hitbox.copied .click-hint {
      color: #6ee7b7;
    }

    /* 主复制按钮 + 下一组预览 */
    .hero-actions {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-top: 14px;
    }

    .copy-btn {
      flex: 1;
      height: 46px;
      border: none;
      border-radius: var(--radius-md);
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      color: #ffffff;
      font-family: var(--sans);
      font-size: 0.96rem;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      cursor: pointer;
      box-shadow: 0 8px 20px -6px rgba(37, 99, 235, 0.55);
      transition: transform 0.12s ease, filter 0.15s ease, background 0.2s ease, box-shadow 0.2s ease, opacity 0.2s ease;
    }

    .copy-btn:hover:not(:disabled) {
      filter: brightness(1.08);
      box-shadow: 0 10px 24px -6px rgba(59, 130, 246, 0.65);
    }

    .copy-btn:active:not(:disabled) {
      transform: scale(0.985);
    }

    .copy-btn:disabled {
      opacity: 0.42;
      cursor: not-allowed;
      box-shadow: none;
      background: rgba(148, 163, 184, 0.24);
    }

    .copy-btn.copied {
      background: linear-gradient(135deg, #10b981, #059669);
      box-shadow: 0 8px 20px -6px rgba(16, 185, 129, 0.55);
    }

    .next-chip {
      display: none;
      align-items: center;
      gap: 6px;
      height: 46px;
      padding: 0 13px;
      border-radius: var(--radius-md);
      border: 1px solid rgba(245, 158, 11, 0.35);
      background: rgba(245, 158, 11, 0.12);
      color: #fde68a;
      font-family: var(--mono);
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      flex-shrink: 0;
      transition: background-color 0.15s ease, transform 0.12s ease;
    }

    .next-chip.visible { display: inline-flex; }
    .next-chip:hover { background: rgba(245, 158, 11, 0.2); }
    .next-chip:active { transform: scale(0.97); }
    .next-chip span.next-label {
      font-family: var(--sans);
      font-size: 0.72rem;
      font-weight: 500;
      color: rgba(253, 230, 138, 0.82);
    }

    /* 表单区 */
    .panel-body {
      padding: 20px 22px 22px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }

    .field-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
    }

    .field-label {
      font-size: 0.86rem;
      font-weight: 600;
      color: var(--text);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .status-badge {
      font-size: 0.75rem;
      font-weight: 600;
      padding: 2px 9px;
      border-radius: 999px;
      color: var(--text-muted);
      background: var(--segment-bg);
      transition: all 0.2s ease;
    }

    .status-badge.ok {
      color: #059669;
      background: var(--success-bg);
    }
    [data-theme="dark"] .status-badge.ok { color: #34d399; }

    .status-badge.err {
      color: #e11d48;
      background: var(--danger-bg);
    }
    [data-theme="dark"] .status-badge.err { color: #fb7185; }

    .input-shell {
      position: relative;
      display: flex;
      align-items: center;
      background: var(--input-bg);
      border: 1.5px solid var(--input-border);
      border-radius: var(--radius-md);
      transition: border-color 0.18s ease, box-shadow 0.18s ease, background-color 0.18s ease;
    }

    .input-shell:focus-within {
      border-color: var(--input-focus);
      box-shadow: 0 0 0 3.5px var(--accent-soft);
    }

    .input-shell.invalid {
      border-color: var(--danger);
      box-shadow: 0 0 0 3.5px var(--danger-bg);
    }

    .secret-input {
      flex: 1;
      min-width: 0;
      border: none;
      background: transparent;
      color: var(--text);
      font-family: var(--mono);
      font-size: 0.96rem;
      letter-spacing: 0.04em;
      padding: 13px 8px 13px 14px;
      outline: none;
    }

    .secret-input::placeholder {
      font-family: var(--sans);
      letter-spacing: 0;
      color: var(--text-muted);
      opacity: 0.78;
    }

    .input-tools {
      display: flex;
      align-items: center;
      gap: 2px;
      padding-right: 6px;
      flex-shrink: 0;
    }

    .icon-tool {
      height: 32px;
      padding: 0 8px;
      border: none;
      border-radius: 8px;
      background: transparent;
      color: var(--text-muted);
      font-family: var(--sans);
      font-size: 0.78rem;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 4px;
      cursor: pointer;
      transition: background-color 0.15s ease, color 0.15s ease;
    }

    .icon-tool:hover {
      background: var(--surface-hover);
      color: var(--text);
    }

    .icon-tool.hidden { display: none; }

    .field-hint {
      margin: 7px 0 0;
      font-size: 0.77rem;
      color: var(--text-muted);
    }

    .field-hint.err {
      color: #e11d48;
    }
    [data-theme="dark"] .field-hint.err { color: #fb7185; }

    /* 参数分段切换 */
    .options-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }

    .option-box {
      display: flex;
      flex-direction: column;
      gap: 7px;
    }

    .option-label {
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-secondary);
    }

    .segmented {
      display: grid;
      grid-template-columns: 1fr 1fr;
      padding: 3px;
      border-radius: 11px;
      background: var(--segment-bg);
      gap: 3px;
    }

    .seg-btn {
      height: 34px;
      border: none;
      border-radius: var(--radius-sm);
      background: transparent;
      color: var(--text-muted);
      font-family: var(--sans);
      font-size: 0.84rem;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.15s ease, color 0.15s ease, box-shadow 0.15s ease;
    }

    .seg-btn:hover:not(.active) {
      color: var(--text);
    }

    .seg-btn.active {
      background: var(--segment-active);
      color: var(--text);
      box-shadow: var(--segment-shadow);
    }

    /* 底部安全说明 */
    .meta-strip {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      padding-top: 14px;
      border-top: 1px solid var(--card-border);
      font-size: 0.76rem;
      color: var(--text-muted);
    }

    .meta-item {
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }

    .kbd {
      font-family: var(--mono);
      font-size: 0.7rem;
      padding: 1px 5px;
      border-radius: 5px;
      border: 1px solid var(--card-border);
      background: var(--surface-subtle);
      color: var(--text-secondary);
    }

    .footer {
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
      opacity: 0.85;
    }

    /* 轻量 Toast */
    .toast {
      position: fixed;
      left: 50%;
      bottom: 26px;
      transform: translateX(-50%) translateY(16px);
      background: #0f172a;
      color: #f8fafc;
      border: 1px solid rgba(148, 163, 184, 0.25);
      padding: 10px 16px;
      border-radius: 999px;
      font-size: 0.86rem;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      box-shadow: 0 14px 36px rgba(0, 0, 0, 0.35);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease, transform 0.22s ease;
      z-index: 99;
    }

    .toast.show {
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }

    .toast-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
    }

    @media (max-width: 440px) {
      body { padding: 14px 12px 28px; }
      .hero { padding: 18px 16px 16px; }
      .panel-body { padding: 16px; }
      .hero-actions { flex-direction: column; }
      .copy-btn, .next-chip { width: 100%; justify-content: center; }
      .options-grid { grid-template-columns: 1fr; }
    }

    /* 平板与中等视口：放宽画幅并垂直居中，保持舒展比例 */
    @media (min-width: 768px) {
      body {
        min-height: 100vh;
        min-height: 100dvh;
        justify-content: center;
        padding: 32px 24px 40px;
        background-image:
          radial-gradient(960px 480px at 14% -8%, var(--bg-glow-1), transparent 70%),
          radial-gradient(860px 440px at 88% 4%, var(--bg-glow-2), transparent 70%);
      }

      .shell {
        max-width: 640px;
        gap: 20px;
      }

      .topbar {
        padding: 4px;
      }

      .logo-wrap {
        height: 42px;
        min-width: 42px;
        border-radius: 12px;
        padding: 6px 10px;
      }

      .logo-wrap img {
        height: 26px;
        max-width: 100px;
      }

      .brand-title h1 {
        font-size: 1.38rem;
      }

      .privacy-pill {
        font-size: 0.8rem;
        padding: 3px 10px;
        gap: 5px;
      }

      .theme-btn {
        width: 42px;
        height: 42px;
        border-radius: 12px;
      }

      .card {
        border-radius: 26px;
      }

      .hero {
        padding: 28px 30px 26px;
      }

      .panel-body {
        padding: 26px 30px 28px;
        gap: 22px;
      }

      .field-label {
        font-size: 0.94rem;
      }

      .status-badge {
        font-size: 0.8rem;
        padding: 3px 11px;
      }

      .secret-input {
        font-size: 1.02rem;
        padding: 15px 10px 15px 16px;
      }

      .icon-tool {
        height: 36px;
        padding: 0 10px;
        font-size: 0.83rem;
      }

      .field-hint {
        font-size: 0.82rem;
        margin-top: 9px;
      }

      .option-label {
        font-size: 0.85rem;
      }

      .segmented {
        padding: 4px;
        border-radius: 12px;
        gap: 4px;
      }

      .seg-btn {
        height: 40px;
        font-size: 0.9rem;
      }

      .copy-btn,
      .next-chip {
        height: 52px;
        font-size: 1rem;
        border-radius: 14px;
      }

      .meta-strip {
        padding-top: 18px;
        font-size: 0.82rem;
      }

      .kbd {
        font-size: 0.76rem;
        padding: 2px 7px;
      }

      .footer {
        font-size: 0.82rem;
      }
    }

    /* 桌面浏览器：宽幅左右双栏工作台（左输入配置，右大屏验证码舞台） */
    @media (min-width: 960px) {
      body {
        padding: 40px 36px 48px;
      }

      .shell {
        max-width: 980px;
        gap: 22px;
      }

      .brand {
        gap: 14px;
      }

      .brand-title {
        gap: 10px;
      }

      .brand-title h1 {
        font-size: 1.5rem;
      }

      .card {
        display: grid;
        grid-template-columns: minmax(0, 1.04fr) minmax(0, 1fr);
        grid-template-areas: "panel hero";
        align-items: stretch;
        min-height: 420px;
      }

      .panel-body {
        grid-area: panel;
        padding: 36px 38px 34px;
        gap: 24px;
        justify-content: flex-start;
      }

      .hero {
        grid-area: hero;
        padding: 34px 36px 34px;
        border-bottom: none;
        border-left: 1px solid var(--hero-border);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
      }

      .top-progress {
        height: 4px;
      }

      .hero-head {
        margin-bottom: 18px;
      }

      .hero-label {
        font-size: 0.85rem;
      }

      .account-tag {
        max-width: 240px;
        font-size: 0.8rem;
        padding: 3px 10px;
      }

      .countdown-pill {
        padding: 5px 12px 5px 8px;
        gap: 8px;
        font-size: 0.92rem;
      }

      .ring-svg {
        width: 25px;
        height: 25px;
      }

      .code-hitbox {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        min-height: 188px;
        padding: 28px 20px 24px;
        border-radius: 18px;
      }

      .token-value {
        font-size: clamp(3rem, 3.8vw, 3.95rem);
        letter-spacing: 0.12em;
      }

      .token-value.is-8digit {
        font-size: clamp(2.3rem, 2.95vw, 3rem);
        letter-spacing: 0.08em;
        padding-left: 0.08em;
      }

      .token-value.is-error {
        font-size: 1.5rem;
        padding: 16px 0;
      }

      .click-hint {
        margin-top: 14px;
        font-size: 0.84rem;
      }

      .hero-actions {
        margin-top: 20px;
        gap: 12px;
      }

      .copy-btn {
        height: 54px;
        font-size: 1.02rem;
      }

      .next-chip {
        height: 54px;
        padding: 0 16px;
        font-size: 0.92rem;
      }

      .next-chip span.next-label {
        font-size: 0.76rem;
      }

      .field-head {
        margin-bottom: 10px;
      }

      .field-label {
        font-size: 0.98rem;
      }

      .input-shell {
        border-radius: 14px;
      }

      .secret-input {
        font-size: 1.05rem;
        padding: 16px 10px 16px 18px;
      }

      .input-tools {
        padding-right: 8px;
        gap: 4px;
      }

      .icon-tool {
        height: 38px;
        padding: 0 11px;
        font-size: 0.84rem;
        border-radius: 9px;
      }

      .field-hint {
        font-size: 0.84rem;
        line-height: 1.55;
      }

      .options-grid {
        gap: 16px;
      }

      .option-box {
        gap: 9px;
      }

      .option-label {
        font-size: 0.88rem;
      }

      .seg-btn {
        height: 42px;
        font-size: 0.92rem;
      }

      .meta-strip {
        margin-top: auto;
        padding-top: 20px;
        font-size: 0.84rem;
      }

      .footer {
        font-size: 0.84rem;
      }

      .toast {
        bottom: 34px;
        padding: 12px 20px;
        font-size: 0.92rem;
      }
    }

    /* 宽屏显示器进一步舒展画幅与数字尺寸 */
    @media (min-width: 1280px) {
      .shell {
        max-width: 1080px;
      }

      .card {
        min-height: 452px;
        grid-template-columns: minmax(0, 1.06fr) minmax(0, 1fr);
      }

      .panel-body {
        padding: 42px 44px 38px;
        gap: 28px;
      }

      .hero {
        padding: 40px 42px 38px;
      }

      .code-hitbox {
        min-height: 208px;
        padding: 32px 24px 28px;
      }

      .token-value {
        font-size: 4.1rem;
      }

      .token-value.is-8digit {
        font-size: 3.15rem;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="logo-wrap" aria-hidden="true">
          <img
            src="https://proxy.mako.fun/cnabc.svg"
            alt="Logo"
            onerror="this.style.display='none';this.nextElementSibling.style.display='block';"
          >
          <svg class="logo-fallback" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
        </div>
        <div class="brand-title">
          <h1>2FA 验证码</h1>
          <span class="privacy-pill">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            纯本地计算
          </span>
        </div>
      </div>

      <button id="themeToggle" type="button" class="theme-btn" title="切换浅色/深色主题" aria-label="切换浅色/深色主题">
        <svg class="icon-sun" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="4"/>
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
        </svg>
        <svg class="icon-moon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      </button>
    </header>

    <main class="card">
      <!-- 动态验证码展示区 -->
      <section id="heroPanel" class="hero state-idle" aria-live="polite">
        <div class="top-progress">
          <div id="topProgressFill" class="top-progress-fill"></div>
        </div>

        <div class="hero-head">
          <div class="hero-label-group">
            <span class="hero-label">当前验证码</span>
            <span id="accountTag" class="account-tag"></span>
          </div>

          <div class="countdown-pill" title="当前周期剩余秒数">
            <svg class="ring-svg" viewBox="0 0 24 24" aria-hidden="true">
              <circle class="ring-track" cx="12" cy="12" r="9"></circle>
              <circle id="ringFill" class="ring-fill" cx="12" cy="12" r="9"></circle>
            </svg>
            <span id="timeLeftText">--s</span>
          </div>
        </div>

        <div
          id="codeHitbox"
          class="code-hitbox"
          role="button"
          tabindex="0"
          aria-label="点击复制当前验证码"
          title="点击直接复制验证码"
        >
          <div id="tokenDisplay" class="token-value is-empty">••• •••</div>
          <div id="clickHint" class="click-hint">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            <span>输入密钥后自动生成，点击此处直接复制</span>
          </div>
        </div>

        <div class="hero-actions">
          <button id="copyBtn" type="button" class="copy-btn" disabled>
            <svg id="copyBtnIcon" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
            </svg>
            <span id="copyBtnText">复制验证码</span>
          </button>

          <button id="nextChip" type="button" class="next-chip" title="点击复制下一组验证码">
            <span class="next-label">下一组</span>
            <span id="nextCodeText">--- ---</span>
          </button>
        </div>
      </section>

      <!-- 密钥输入与配置区 -->
      <section class="panel-body">
        <div>
          <div class="field-head">
            <label for="secretInput" class="field-label">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
              2FA 密钥
            </label>
            <span id="statusBadge" class="status-badge">等待输入</span>
          </div>

          <div id="inputShell" class="input-shell">
            <input
              id="secretInput"
              class="secret-input"
              type="text"
              autocomplete="off"
              autocapitalize="characters"
              autocorrect="off"
              spellcheck="false"
              placeholder="输入 Base32 密钥或粘贴 otpauth:// 链接"
            >
            <div class="input-tools">
              <button id="pasteBtn" type="button" class="icon-tool" title="从剪贴板粘贴">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>
                  <rect x="8" y="2" width="8" height="4" rx="1" ry="1"/>
                </svg>
                粘贴
              </button>
              <button id="toggleVisBtn" type="button" class="icon-tool" title="隐藏/显示密钥" aria-label="隐藏或显示密钥">
                <svg id="eyeIcon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
              <button id="clearBtn" type="button" class="icon-tool hidden" title="清空输入" aria-label="清空输入">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18"/>
                  <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
          </div>

          <p id="fieldHint" class="field-hint">
            自动忽略空格、横杠与末尾 =，输入即刻本地计算，密钥绝不上传
          </p>
        </div>

        <div class="options-grid">
          <div class="option-box">
            <span class="option-label">验证码位数</span>
            <div class="segmented" role="group" aria-label="验证码位数">
              <button type="button" class="seg-btn active" data-digits="6">6 位</button>
              <button type="button" class="seg-btn" data-digits="8">8 位</button>
            </div>
          </div>

          <div class="option-box">
            <span class="option-label">刷新周期</span>
            <div class="segmented" role="group" aria-label="刷新周期">
              <button type="button" class="seg-btn active" data-period="30">30 秒</button>
              <button type="button" class="seg-btn" data-period="60">60 秒</button>
            </div>
          </div>
        </div>

        <div class="meta-strip">
          <span class="meta-item">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Web Crypto 本地算码 · 不留存密钥
          </span>
          <span class="meta-item">快捷复制 <span class="kbd">Enter</span></span>
        </div>
      </section>
    </main>

    <footer class="footer">
      遵循 RFC 6238 TOTP 标准 · Powered by Cloudflare Workers
    </footer>
  </div>

  <div id="toast" class="toast" role="status" aria-live="polite">
    <span class="toast-dot"></span>
    <span id="toastText">已复制验证码</span>
  </div>

  <script>
    (() => {
      const RING_CIRCUMFERENCE = 2 * Math.PI * 9;

      // DOM 引用
      const heroPanel = document.getElementById('heroPanel');
      const topProgressFill = document.getElementById('topProgressFill');
      const ringFill = document.getElementById('ringFill');
      const timeLeftText = document.getElementById('timeLeftText');
      const accountTag = document.getElementById('accountTag');
      const codeHitbox = document.getElementById('codeHitbox');
      const tokenDisplay = document.getElementById('tokenDisplay');
      const clickHint = document.getElementById('clickHint');
      const copyBtn = document.getElementById('copyBtn');
      const copyBtnText = document.getElementById('copyBtnText');
      const copyBtnIcon = document.getElementById('copyBtnIcon');
      const nextChip = document.getElementById('nextChip');
      const nextCodeText = document.getElementById('nextCodeText');

      const secretInput = document.getElementById('secretInput');
      const inputShell = document.getElementById('inputShell');
      const statusBadge = document.getElementById('statusBadge');
      const fieldHint = document.getElementById('fieldHint');
      const pasteBtn = document.getElementById('pasteBtn');
      const toggleVisBtn = document.getElementById('toggleVisBtn');
      const eyeIcon = document.getElementById('eyeIcon');
      const clearBtn = document.getElementById('clearBtn');
      const themeToggle = document.getElementById('themeToggle');
      const toastEl = document.getElementById('toast');
      const toastText = document.getElementById('toastText');

      const digitBtns = Array.from(document.querySelectorAll('[data-digits]'));
      const periodBtns = Array.from(document.querySelectorAll('[data-period]'));

      ringFill.style.strokeDasharray = String(RING_CIRCUMFERENCE);
      ringFill.style.strokeDashoffset = String(RING_CIRCUMFERENCE);

      // 运行态
      const state = {
        rawInput: '',
        secret: '',
        digits: 6,
        period: 30,
        algorithm: 'SHA-1',
        label: '',
        keyBytes: null,
        cryptoKey: null,
        currentCode: '',
        nextCode: '',
        lastCounter: -1,
        masked: false,
        rafId: 0,
        copyResetTimer: 0,
        toastTimer: 0
      };

      // 纯前端 RFC 6238 Base32 解码
      function cleanBase32(str) {
        return String(str || '')
          .toUpperCase()
          .replace(/[\\s-]+/g, '')
          .replace(/=+$/g, '');
      }

      function decodeBase32(str) {
        const cleaned = cleanBase32(str);
        if (!cleaned) return { ok: false, reason: 'empty', bytes: null };
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let bits = '';
        for (let i = 0; i < cleaned.length; i++) {
          const ch = cleaned[i];
          const idx = alphabet.indexOf(ch);
          if (idx === -1) {
            return { ok: false, reason: 'invalid_char', badChar: ch, bytes: null };
          }
          bits += idx.toString(2).padStart(5, '0');
        }
        const bytes = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
          bytes.push(parseInt(bits.slice(i, i + 8), 2));
        }
        if (bytes.length === 0) {
          return { ok: false, reason: 'too_short', bytes: null };
        }
        return { ok: true, bytes: new Uint8Array(bytes), cleaned };
      }

      function normalizeAlgo(algo) {
        const c = String(algo || 'SHA-1').toUpperCase().replace(/[^A-Z0-9]/g, '');
        if (c === 'SHA256') return 'SHA-256';
        if (c === 'SHA512') return 'SHA-512';
        return 'SHA-1';
      }

      function parseInput(raw) {
        const trimmed = String(raw || '').trim();
        if (!trimmed) {
          return { empty: true };
        }
        if (/^otpauth:\\/\\//i.test(trimmed)) {
          try {
            const u = new URL(trimmed);
            const secret = u.searchParams.get('secret') || '';
            const digitsParam = parseInt(u.searchParams.get('digits') || '', 10);
            const periodParam = parseInt(u.searchParams.get('period') || '', 10);
            const algoParam = u.searchParams.get('algorithm') || 'SHA-1';
            const issuer = u.searchParams.get('issuer') || '';
            const rawPath = decodeURIComponent(u.pathname.replace(/^\\/+/, ''));
            const label = issuer && !rawPath.startsWith(issuer)
              ? (rawPath ? issuer + ' · ' + rawPath : issuer)
              : rawPath || issuer;
            return {
              empty: false,
              isUri: true,
              secret,
              digits: (digitsParam === 6 || digitsParam === 8) ? digitsParam : null,
              period: (periodParam === 30 || periodParam === 60) ? periodParam : null,
              algorithm: normalizeAlgo(algoParam),
              label
            };
          } catch (e) {
            return { empty: false, isUri: true, secret: '', parseError: true };
          }
        }
        return {
          empty: false,
          isUri: false,
          secret: trimmed,
          digits: null,
          period: null,
          algorithm: 'SHA-1',
          label: ''
        };
      }

      async function computeTotp(cryptoKey, counter, digits) {
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        view.setUint32(0, Math.floor(counter / 0x100000000), false);
        view.setUint32(4, counter >>> 0, false);
        const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buffer));
        const offset = sig[sig.length - 1] & 0x0f;
        const bin =
          ((sig[offset] & 0x7f) << 24) |
          ((sig[offset + 1] & 0xff) << 16) |
          ((sig[offset + 2] & 0xff) << 8) |
          (sig[offset + 3] & 0xff);
        const code = (bin >>> 0) % (10 ** digits);
        return code.toString().padStart(digits, '0');
      }

      function formatCode(code, digits) {
        if (!code) {
          return digits === 8 ? '•••• ••••' : '••• •••';
        }
        const mid = Math.floor(code.length / 2);
        return code.slice(0, mid) + ' ' + code.slice(mid);
      }

      function syncSegmentedUI() {
        digitBtns.forEach(btn => {
          btn.classList.toggle('active', Number(btn.dataset.digits) === state.digits);
        });
        periodBtns.forEach(btn => {
          btn.classList.toggle('active', Number(btn.dataset.period) === state.period);
        });
      }

      function setIdleUI() {
        state.currentCode = '';
        state.nextCode = '';
        state.lastCounter = -1;
        heroPanel.className = 'hero state-idle';
        topProgressFill.style.transform = 'scaleX(0)';
        ringFill.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
        timeLeftText.textContent = '--s';
        accountTag.textContent = '';
        accountTag.classList.remove('visible');
        codeHitbox.classList.remove('ready', 'copied');
        tokenDisplay.className = 'token-value is-empty' + (state.digits === 8 ? ' is-8digit' : '');
        tokenDisplay.textContent = formatCode('', state.digits);
        clickHint.querySelector('span').textContent = '输入密钥后自动生成，点击此处直接复制';
        copyBtn.disabled = true;
        copyBtn.classList.remove('copied');
        copyBtnText.textContent = '复制验证码';
        nextChip.classList.remove('visible');
        inputShell.classList.remove('invalid');
        statusBadge.className = 'status-badge';
        statusBadge.textContent = '等待输入';
        fieldHint.className = 'field-hint';
        fieldHint.textContent = '自动忽略空格、横杠与末尾 =，输入即刻本地计算，密钥绝不上传';
      }

      function setErrorUI(message) {
        state.currentCode = '';
        state.nextCode = '';
        state.lastCounter = -1;
        heroPanel.className = 'hero state-idle';
        topProgressFill.style.transform = 'scaleX(0)';
        ringFill.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
        timeLeftText.textContent = '--s';
        codeHitbox.classList.remove('ready', 'copied');
        tokenDisplay.className = 'token-value is-error';
        tokenDisplay.textContent = '密钥格式无效';
        clickHint.querySelector('span').textContent = '请检查 Base32 字符（仅允许 A-Z 与 2-7）';
        copyBtn.disabled = true;
        copyBtn.classList.remove('copied');
        copyBtnText.textContent = '复制验证码';
        nextChip.classList.remove('visible');
        inputShell.classList.add('invalid');
        statusBadge.className = 'status-badge err';
        statusBadge.textContent = '格式错误';
        fieldHint.className = 'field-hint err';
        fieldHint.textContent = message;
      }

      async function refreshCodesForCounter(counter) {
        if (!state.cryptoKey) return;
        const myKey = state.cryptoKey;
        const myDigits = state.digits;
        try {
          const [cur, nxt] = await Promise.all([
            computeTotp(myKey, counter, myDigits),
            computeTotp(myKey, counter + 1, myDigits)
          ]);
          if (state.cryptoKey !== myKey || state.digits !== myDigits) return;
          state.currentCode = cur;
          state.nextCode = nxt;
          state.lastCounter = counter;

          tokenDisplay.className = 'token-value' + (myDigits === 8 ? ' is-8digit' : '');
          tokenDisplay.textContent = formatCode(cur, myDigits);
          nextCodeText.textContent = formatCode(nxt, myDigits);
          codeHitbox.classList.add('ready');
          copyBtn.disabled = false;
          if (!codeHitbox.classList.contains('copied')) {
            clickHint.querySelector('span').textContent = '点击验证码区域即可直接复制';
          }
        } catch (err) {
          setErrorUI('本地加密引擎计算失败，请确认使用现代浏览器 HTTPS 访问');
        }
      }

      function tick() {
        if (!state.cryptoKey) {
          state.rafId = 0;
          return;
        }
        const now = Date.now();
        const periodMs = state.period * 1000;
        const counter = Math.floor(now / periodMs);
        const elapsedMs = now % periodMs;
        const remainMs = periodMs - elapsedMs;
        const ratio = Math.max(0, Math.min(1, remainMs / periodMs));
        const remainSec = Math.ceil(remainMs / 1000);

        topProgressFill.style.transform = 'scaleX(' + ratio.toFixed(4) + ')';
        ringFill.style.strokeDashoffset = (RING_CIRCUMFERENCE * (1 - ratio)).toFixed(2);
        timeLeftText.textContent = remainSec + 's';

        if (remainSec <= 3) {
          heroPanel.className = 'hero state-danger';
        } else if (remainSec <= 7) {
          heroPanel.className = 'hero state-warn';
        } else {
          heroPanel.className = 'hero';
        }

        // 最后 5 秒淡入“下一组”预览，方便卡点复制
        if (remainSec <= 5 && state.nextCode) {
          nextChip.classList.add('visible');
        } else {
          nextChip.classList.remove('visible');
        }

        if (counter !== state.lastCounter) {
          state.lastCounter = counter;
          refreshCodesForCounter(counter);
        }

        state.rafId = requestAnimationFrame(tick);
      }

      function ensureLoopRunning() {
        if (!state.rafId && state.cryptoKey) {
          state.rafId = requestAnimationFrame(tick);
        }
      }

      let activeGenerationSeq = 0;

      async function handleSecretChange() {
        const seq = ++activeGenerationSeq;
        const raw = secretInput.value;
        state.rawInput = raw;
        clearBtn.classList.toggle('hidden', raw.length === 0);

        const parsed = parseInput(raw);
        if (parsed.empty) {
          state.cryptoKey = null;
          state.keyBytes = null;
          setIdleUI();
          return;
        }

        if (parsed.parseError) {
          state.cryptoKey = null;
          state.keyBytes = null;
          setErrorUI('otpauth:// 链接格式无法解析，请确认链接完整');
          return;
        }

        if (parsed.digits) state.digits = parsed.digits;
        if (parsed.period) state.period = parsed.period;
        state.algorithm = parsed.algorithm || 'SHA-1';
        state.label = parsed.label || '';
        syncSegmentedUI();

        const decoded = decodeBase32(parsed.secret);
        if (!decoded.ok) {
          state.cryptoKey = null;
          state.keyBytes = null;
          if (decoded.reason === 'invalid_char') {
            setErrorUI('包含非法 Base32 字符 "' + decoded.badChar + '"（标准密钥仅含 A-Z 和 2-7）');
          } else {
            setErrorUI('密钥长度不足，请继续输入完整的 Base32 密钥');
          }
          return;
        }

        try {
          const imported = await crypto.subtle.importKey(
            'raw',
            decoded.bytes,
            { name: 'HMAC', hash: state.algorithm },
            false,
            ['sign']
          );
          if (seq !== activeGenerationSeq) return;

          state.secret = decoded.cleaned;
          state.keyBytes = decoded.bytes;
          state.cryptoKey = imported;
          state.lastCounter = -1;

          inputShell.classList.remove('invalid');
          statusBadge.className = 'status-badge ok';
          statusBadge.textContent = '实时计算中 · ' + state.algorithm;
          fieldHint.className = 'field-hint';
          fieldHint.textContent = parsed.isUri
            ? '已自动识别 otpauth:// 参数并在本地实时算码'
            : '密钥有效（' + decoded.bytes.length + ' 字节），每 ' + state.period + ' 秒自动刷新';

          if (state.label) {
            accountTag.textContent = state.label;
            accountTag.classList.add('visible');
          } else {
            accountTag.textContent = '';
            accountTag.classList.remove('visible');
          }

          const nowCounter = Math.floor(Date.now() / (state.period * 1000));
          await refreshCodesForCounter(nowCounter);
          if (seq !== activeGenerationSeq) return;
          ensureLoopRunning();
        } catch (err) {
          if (seq !== activeGenerationSeq) return;
          state.cryptoKey = null;
          setErrorUI('浏览器不支持 Web Crypto 本地计算，请使用 HTTPS 打开页面');
        }
      }

      // 复制与反馈
      function showToast(msg) {
        toastText.textContent = msg;
        toastEl.classList.add('show');
        clearTimeout(state.toastTimer);
        state.toastTimer = setTimeout(() => {
          toastEl.classList.remove('show');
        }, 1800);
      }

      async function writeClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          try {
            await navigator.clipboard.writeText(text);
            return true;
          } catch (e) {}
        }
        try {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.setAttribute('readonly', '');
          ta.style.position = 'fixed';
          ta.style.opacity = '0';
          ta.style.pointerEvents = 'none';
          document.body.appendChild(ta);
          ta.select();
          ta.setSelectionRange(0, text.length);
          const ok = document.execCommand('copy');
          document.body.removeChild(ta);
          return ok;
        } catch (e) {
          return false;
        }
      }

      async function copyCode(code, isNext = false) {
        if (!code) return;
        const ok = await writeClipboard(code);
        if (!ok) {
          showToast('复制失败，请手动选中复制');
          return;
        }

        showToast((isNext ? '已复制下一组验证码 ' : '已复制验证码 ') + code);

        if (!isNext) {
          codeHitbox.classList.add('copied');
          copyBtn.classList.add('copied');
          copyBtnText.textContent = '已复制到剪贴板';
          copyBtnIcon.innerHTML = '<polyline points="20 6 9 17 4 12"/>';
          clickHint.querySelector('span').textContent = '已复制纯数字 ' + code;

          clearTimeout(state.copyResetTimer);
          state.copyResetTimer = setTimeout(() => {
            codeHitbox.classList.remove('copied');
            copyBtn.classList.remove('copied');
            copyBtnText.textContent = '复制验证码';
            copyBtnIcon.innerHTML = '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>';
            if (state.currentCode) {
              clickHint.querySelector('span').textContent = '点击验证码区域即可直接复制';
            }
          }, 1600);
        }
      }

      // 事件绑定
      secretInput.addEventListener('input', handleSecretChange);

      codeHitbox.addEventListener('click', () => copyCode(state.currentCode));
      codeHitbox.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          copyCode(state.currentCode);
        }
      });

      copyBtn.addEventListener('click', () => copyCode(state.currentCode));
      nextChip.addEventListener('click', () => copyCode(state.nextCode, true));

      pasteBtn.addEventListener('click', async () => {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
          secretInput.focus();
          showToast('浏览器限制剪贴板读取，请直接 Ctrl+V 粘贴');
          return;
        }
        try {
          const text = await navigator.clipboard.readText();
          if (text && text.trim()) {
            secretInput.value = text.trim();
            await handleSecretChange();
            showToast('已粘贴并计算验证码');
          } else {
            showToast('剪贴板为空');
          }
        } catch (e) {
          secretInput.focus();
          showToast('未获剪贴板权限，请直接 Ctrl+V 粘贴');
        }
      });

      toggleVisBtn.addEventListener('click', () => {
        state.masked = !state.masked;
        secretInput.type = state.masked ? 'password' : 'text';
        eyeIcon.innerHTML = state.masked
          ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
          : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
      });

      clearBtn.addEventListener('click', () => {
        secretInput.value = '';
        handleSecretChange();
        secretInput.focus();
      });

      digitBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const val = Number(btn.dataset.digits);
          if (val === state.digits) return;
          state.digits = val;
          syncSegmentedUI();
          if (state.cryptoKey) {
            state.lastCounter = -1;
            refreshCodesForCounter(Math.floor(Date.now() / (state.period * 1000)));
          } else if (!state.rawInput.trim()) {
            tokenDisplay.className = 'token-value is-empty' + (state.digits === 8 ? ' is-8digit' : '');
            tokenDisplay.textContent = formatCode('', state.digits);
          }
        });
      });

      periodBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const val = Number(btn.dataset.period);
          if (val === state.period) return;
          state.period = val;
          syncSegmentedUI();
          if (state.cryptoKey) {
            state.lastCounter = -1;
            fieldHint.textContent = '密钥有效（' + state.keyBytes.length + ' 字节），每 ' + state.period + ' 秒自动刷新';
            refreshCodesForCounter(Math.floor(Date.now() / (state.period * 1000)));
          }
        });
      });

      themeToggle.addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme') || 'light';
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem('totp-theme', next); } catch (e) {}
      });

      // 全局快捷键：按 Enter 复制当前验证码（未选中其他文本时）
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && state.currentCode && document.activeElement !== copyBtn && document.activeElement !== codeHitbox) {
          e.preventDefault();
          copyCode(state.currentCode);
        }
      });

      // 页面切回前台时立即同步
      document.addEventListener('visibilitychange', () => {
        if (!document.hidden && state.cryptoKey) {
          state.lastCounter = -1;
          ensureLoopRunning();
        }
      });

      // 初始化
      syncSegmentedUI();
      setIdleUI();
      secretInput.focus();
    })();
  </script>
</body>
</html>`
}
