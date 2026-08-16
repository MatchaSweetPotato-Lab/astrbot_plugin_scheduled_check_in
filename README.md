# AstrBot Scheduled Check-In Plugin

![AstrBot Plugin](https://img.shields.io/badge/AstrBot-Plugin-blue)
![Vanilla JS](https://img.shields.io/badge/Frontend-Vanilla%20JS%20(0KB%20Ext)-green)
![Framework](https://img.shields.io/badge/Support-New--API%20%7C%20One--API%20%7C%20REST-orange)

自动定时签到各种 LLM API 中转站（如 New-API、One-API 等）的 AstrBot 插件。配备基于 Vanilla JS 的轻量级 Pages 可视化管理面板，支持实时连通性测试、定时/区间随机打卡、代理跳转与额度汇总。

---

## 🌟 特性亮点

- **⚡ 原生 Vanilla JS 可视化 Dashboard**
  - **零外部依赖**（0 KB 依赖，不加载 Vue/React、FontAwesome 或远程 CDN），页面加载极其迅速。
  - 内置符合 AstrBot 主题风的 UI 样式与自定义 Modal/Toast 交互，完美适配 iframe 沙盒环境。

- **⏰ 智能定时与区间随机打卡**
  - 支持固定时间打卡，或在设定时间区间（如 `08:00` - `10:30`）内生成随机触发时刻。
  - **智能时区/过期校验**：若重设的时间区间在当天已过，自动识别跳过；若设在当前时间内部，自动在剩余时间内随机分配。

- **🔄 避免重复打卡（今日打卡跳过）**
  - 自动记录各站点当天的打卡状态与时间。对于今天已成功打卡的站点，触发时自动跳过 HTTP 请求，防止重复签到被限制。

- **🛠️ 灵活鉴权与自定义 Header**
  - 支持 `Bearer Token`（API Key `sk-xxx`）、`Cookie` 等多种鉴权方式。
  - 内置动态 **Key-Value 编辑器**，可自定义配置任意 Header（如 `new-api-user: 2257` 等），彻底交给用户自由定制。

- **🌐 全局 / 单站代理 (Proxy)**
  - **自动继承 AstrBot / 系统代理**（`trust_env=True`），轻松请求境外中转站。
  - 支持为单个站点单独配置独立的代理服务器地址（如 `http://127.0.0.1:7890`）。

- **🛡️ 精准 WAF 拦截与备用探测**
  - 能精准识别阿里云 ESA / Tengine 等 WAF 返回的 HTML 验证页（`acw_sc`），杜绝“200 OK 假成功”误报。
  - 管理接口被拦截时，会自动尝试探测 `/v1/models` 模型接口，明确区分“API Key 有效”与“WAF 拦截”。

- **🖥️ 浏览器指纹请求**
  - 网络请求使用 `curl_cffi>=0.14.0,<1.0.0`，可在 Web「全局设置」中选择当前库支持的指纹，默认使用 `chrome131`。

- **🧩 可选 acw_sc__v2 纯 Python 解算 (Beta)**
  - 在站点编辑页勾选 **`解算acw_sc__v2(Beta)`** 后，可把响应中的 JavaScript 重排与 XOR 算法转换成 Python 代码并自动重试原请求。
  - 转换结果按算法指纹缓存，动态 `arg1` 变化不会重复写入；仅在重排表或 XOR 密钥变化时新增缓存。
  - 运行时不依赖浏览器、Node.js 或远程 JavaScript 执行服务。

- **📜 日志明细与抽屉面板**
  - 支持侧边抽屉拉出查看，内置**滚动自动下滑翻页**加载更多历史记录，精准区分 `单站连通性测试`、`手动一键签到` 与 `自动定时签到`。
  - 支持一键清空日志，并支持在全局设置中自定义日志保留条数（默认 0 为不设上限）。

---

## 🤖 聊天指令

在支持 AstrBot 的聊天平台中，可以直接使用以下指令：

| 指令 | 说明 |
| :--- | :--- |
| `/签到` | 立即触发全量中转站打卡，并向当前聊天返回简报结果 |
| `/签到状态` | 查询各中转站当前连通性与额度汇总 |
| `/清空签到日志` | 一键清空历史签到日志记录 |

---

## 🖥️ Pages Dashboard 使用方法

1. 在 AstrBot 管理后台中进入 **插件管理** 页面；
2. 找到 `astrbot_plugin_scheduled_check_in` 插件；
3. 点击 **「管理面板」** 按钮，即可直接打开可视化 Dashboard 进行中转站配置维护、一键打卡与日志查看。

---

## 📂 数据持久化

插件数据存储在 AstrBot 统一的数据目录中：
`data/plugin_data/astrbot_plugin_scheduled_check_in/`

- `data.db`：SQLite 本地数据库（采用 WAL 高并发模式），统一持久化中转站配置（`sites` 表）、全局设置（`settings` 表）与历史打卡/测试日志（`history_logs` 表，支持游标分页与自定义保留上限，默认 0 为不设上限）。
- `acw_sc_v2_cache.json`：保存已验证算法转换生成的 Python 源码，仅在启用 Aliyun WAF 解算后按需创建。
- `*.json.bak`：若从旧版升级，初次启动时会自动将历史 JSON 文件导入 SQLite 数据库，并将原文件自动备份为 `.json.bak`。

*插件代码更新、重载或重启 Bot 不会丢失用户配置与数据。*

---

## 📄 开源协议

MIT License
