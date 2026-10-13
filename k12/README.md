# Standalone Codex K12

这是基于 reg-factory 公共能力重新开发的独立 K12 适配器，不复用旧 `codex_k12/` 应用代码。

## 启动

```powershell
python -m uvicorn k12.server:app --host 127.0.0.1 --port 8806
```

打开 <http://127.0.0.1:8806/>。运行数据写入 `runtime/k12/`，任务通过主项目的邮箱解析、浏览器、OAuth 和 Sub2API 能力执行。

控制台提供摘要、主邮箱池同步、邮箱删除/拆分、数据备份恢复、Workspace 操作、AT 测活、任务重试/取消/清理和日志查看。

## 协议重登、转换与兑换

在同一工作台的「协议重登与文件转换」面板操作，使用现有 K12 端口，无需启动额外服务。

- **协议重登**：提交 `邮箱----密码----2fa`，兼容 `|` 分隔、`otpauth://` 密钥及额外列；本地生成 TOTP，完成 PKCE OAuth，显示逐账号步骤和 free / plus / pro / team 套餐。
- **本地转格式**：粘贴或读取一个或多个 Sub2API JSON 文件，兼容合并文件、单账号对象、裸账号数组；转换过程不访问网络。
- **下载**：CPA、Sub2 合并 JSON、Sub2 单独文件、Cockpit。单账号输出 JSON，多账号的单独文件自动打包 ZIP。
- **卡密兑换**：在面板设置中填写兼容上游的地址和 `X-CPA-Server-Key` 密钥，按上游库存兑换成品。上游须实现 `GET /api/admin/account-lookup` 和 `POST /api/admin/recovery-export`。
- **匿名访问统计**：今日访客、今日访问、近 10 分钟及最近 7 天数据，仅存匿名标识的哈希。

重登默认使用 K12 网络出口和并发数。可在面板设置重登专用代理，支持 HTTP(S) / SOCKS5 URL 和 `host:port:user:pass`。修改配置只影响新任务，已提交任务保留提交时的网络及上游配置。清除专用代理后恢复跟随 K12 网络出口。

重登账号、2FA 密钥、会话缓存和输出只在内存中保存，不加入邮箱池或 K12 数据备份。结果默认完成后保留 6 小时，定期自动清理；服务重启后失效。访问统计位于 `runtime/k12/reauth/visits.json`，专用代理及上游密钥保存在现有 K12 配置中，API 只返回是否已配置。

首次启动可用 `REAUTH_PROXY`、`REAUTH_UPSTREAM_BASE`、`REAUTH_UPSTREAM_KEY` 初始化配置；`REAUTH_MAX_ACCOUNTS`（最多 200）、`REAUTH_JOB_TTL_SECONDS`、`REAUTH_RESULT_TTL_SECONDS`、`REAUTH_SESSION_CACHE_TTL_SECONDS` 等沿用上游设置。重登并发及超时使用 K12 的 `concurrency` 和 `timeout`；遇到额外邮箱或手机号验证会报告失败，可使用工作台原有浏览器任务继续处理。

接口前缀为 `/api/reauth`，提供 `meta`、`session`、`submit`、`convert`、`job/{id}`、`job/{id}/download/{kind}` 和 `visit`。提交时先获取 `session`，再携带 `X-REAUTH-TOKEN`。任务状态不返回密码、2FA 密钥或 token，下载响应禁止缓存。

集成来源：[boji1334/reauth-web](https://github.com/boji1334/reauth-web)，版本 `db8251817fd1baefc83c14c851135fb6078bc001`。MIT 许可和本地修改说明保留在 `vendor/reauth_web/LICENSE`、`vendor/reauth_web/NOTICE`，Windows 便携包同时包含该模块。

验证：

```powershell
python -m unittest tests.test_k12_service tests.test_k12_reauth
python -m unittest discover -s tests/reauth_web -t .
node --check k12/static/reauth.js
```
