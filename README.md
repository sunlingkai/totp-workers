# TOTP Workers — 2FA 验证码生成器 / 2FA TOTP Authenticator

[中文](#中文说明) | [English](#english)

一个部署在 **Cloudflare Workers** 上的轻量、单文件、零外部 CDN 依赖的 **RFC 6238 TOTP (2FA) 验证码生成器**。前端基于浏览器原生 **Web Crypto API** 实现真正的纯本地算码，密钥绝不离开浏览器；同时保留向后兼容的 `POST /` API 接口。

A lightweight, single-file, zero-external-CDN **RFC 6238 TOTP (2FA) authenticator** deployed on **Cloudflare Workers**. TOTP codes are computed 100% locally in the browser using the native **Web Crypto API** so secrets never leave your device, while preserving a backward-compatible `POST /` JSON/Form API.

---

## 中文说明

### 核心特性

* **纯本地计算，隐私优先**：网页端使用浏览器原生 `crypto.subtle`（Web Crypto API）本地计算 HMAC-SHA1/SHA256/SHA512，密钥不上传至任何服务器，也不会写入 `localStorage`。
* **输入即刻出码，无需点击提交**：输入或粘贴密钥后毫秒级自动计算并持续刷新；内置 **粘贴**、**显示/隐藏（防窥屏）**、**清空** 快捷按钮。
* **智能格式容错**：
  * 自动清理 Base32 密钥中的空格、连字符 `-`、大小写及尾部 `=` 填充；
  * 支持直接粘贴完整的 `otpauth://totp/...` 链接，自动识别并应用 `secret`、`digits`、`period`、`algorithm` 与账号标签。
* **双触发一键复制**：
  * 点击上方**整个验证码显示区域**即可直接复制；
  * 下方配有高对比度**「复制验证码」主按钮**，支持 `Enter` 快捷键复制；
  * 界面按 `123 456` / `1234 5678` 分组显示便于核对，复制到剪贴板时自动去除空格输出纯数字，并伴随变绿反馈与轻量 Toast 提示。
* **平滑倒计时与下一组预览**：基于真实时间戳 `Date.now()` 与 `requestAnimationFrame` 驱动，后台切回零时间漂移；配备顶部平滑进度条 + 环形倒计时（剩余 ≤7 秒变琥珀黄、≤3 秒变红），最后 5 秒自动展示**下一组验证码预览**（点击可直接复制下一组）。
* **零外部 CDN & 自适应主题**：纯内联 CSS 与内联 SVG 图标，任意网络环境下秒开；支持浅色 / 深色模式跟随系统与手动一键切换，桌面与移动端自适应。
* **向后兼容 API**：保留 `POST /` 接口（同时支持 `application/json` 与 `multipart/form-data` / `application/x-www-form-urlencoded`），便于脚本自动化调用。

### 快速部署到 Cloudflare Workers

#### 方式一：Cloudflare Dashboard 直接粘贴（最简单）
1. 登录 Cloudflare Dashboard，进入 **Workers & Pages** → **Create Worker**。
2. 将本仓库中的 `worker.js` 完整内容粘贴覆盖默认代码。
3. 点击 **Deploy** 部署即可使用，按需在 Settings 中绑定自定义域名。

#### 方式二：使用 Wrangler CLI 部署
```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

### API 调用说明（可选）

虽然网页端完全在浏览器本地算码，Worker 仍保留了 `POST /` 接口以兼容既有脚本调用：

```bash
# JSON 请求
curl -X POST https://your-worker.workers.dev/ \
  -H "Content-Type: application/json" \
  -d '{"secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30,"algorithm":"SHA-1"}'

# 表单请求
curl -X POST https://your-worker.workers.dev/ \
  -F "secret=JBSWY3DPEHPK3PXP" \
  -F "digits=6" \
  -F "period=30"
```

返回示例：
```json
{
  "token": "123456",
  "timeLeft": 24,
  "success": true
}
```

### 目录结构

```text
totp-workers/
├── worker.js       # 单文件 Cloudflare Worker（完整 TOTP 引擎 + 现代自适应前端 UI）
├── wrangler.toml   # Wrangler 部署配置模板
├── LICENSE         # MIT 开源协议
└── README.md       # 中英文说明文档
```

---

## English

### Features

* **100% Client-Side Computation**: Web UI computes HMAC-SHA1/SHA256/SHA512 locally via the browser's native **Web Crypto API** (`crypto.subtle`). Your 2FA secrets never leave your browser and are never persisted in `localStorage`.
* **Instant Real-Time Generation**: Codes are computed immediately as you type or paste — no submit button required. Includes inline **Paste**, **Mask/Unmask**, and **Clear** controls.
* **Smart Input Parsing**:
  * Automatically strips spaces, hyphens (`-`), trailing `=` padding, and normalizes case for Base32 secrets.
  * Accepts full `otpauth://totp/...` URIs and automatically extracts `secret`, `digits`, `period`, `algorithm`, and account/issuer labels.
* **Frictionless One-Click Copy**:
  * Click **anywhere on the code display card** or the prominent **Copy** button (or press `Enter`) to copy instantly.
  * Digits are visually grouped (`123 456` / `1234 5678`) for readability while copying clean unspaced digits to the clipboard, with emerald confirmation state and toast feedback.
* **Drift-Free Countdown & Next-Code Preview**: Driven by `Date.now()` and `requestAnimationFrame` (stays accurate even after tab sleep). Features a smooth top progress bar and circular countdown ring with color alerts (≤7s amber, ≤3s red) plus a clickable **Next Code** chip during the final 5 seconds.
* **Zero External CDN & Adaptive Theme**: Self-contained inline CSS and inline SVGs for instant loading everywhere. Automatically follows system Light/Dark preference with a manual theme toggle, responsive across desktop and mobile.
* **Backward-Compatible API**: Keeps `POST /` (supporting both JSON and FormData) for scripting or legacy integrations.

### Quick Deployment to Cloudflare Workers

#### Option 1: Cloudflare Dashboard
1. Open **Workers & Pages** → **Create Worker** in your Cloudflare Dashboard.
2. Replace the default code with the contents of `worker.js`.
3. Click **Deploy** and optionally attach a Custom Domain.

#### Option 2: Wrangler CLI
```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

### API Usage (Optional)

While the web UI performs all calculations locally in the browser, `POST /` remains available for programmatic use:

```bash
# JSON payload
curl -X POST https://your-worker.workers.dev/ \
  -H "Content-Type: application/json" \
  -d '{"secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30,"algorithm":"SHA-1"}'

# FormData payload
curl -X POST https://your-worker.workers.dev/ \
  -F "secret=JBSWY3DPEHPK3PXP" \
  -F "digits=6" \
  -F "period=30"
```

Response:
```json
{
  "token": "123456",
  "timeLeft": 24,
  "success": true
}
```

### Repository Structure

```text
totp-workers/
├── worker.js       # Single-file Cloudflare Worker (RFC 6238 TOTP engine + responsive UI)
├── wrangler.toml   # Wrangler deployment config
├── LICENSE         # MIT License
└── README.md       # Bilingual documentation (Chinese / English)
```

### License

MIT License. See [LICENSE](./LICENSE) for details.
