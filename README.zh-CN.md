# dsh-gateway

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4c1.svg" alt="MIT license"></a>
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-Web%20profile-0ea5e9.svg" alt="DSH Web-profile bundle"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%E2%89%A520-339933.svg" alt="Node.js 20 or later"></a>
</p>

<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a></p>

<p align="center"><strong>只把 DSH Web 交给你指定的人——而不是整个网络。</strong></p>

这是 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH)
Web 的通用、私有、零信任网关插件。网关和 DSH 都只监听回环地址。受支持的
provider 只负责私有入口。加入该私有网络**从来不是**授权决定：任何请求在转发到
DSH 之前，都必须解析出一个明确的、在允许名单中的主体。

```text
允许名单中的浏览器 ─ HTTPS ─> provider 入口（Serve 或 Access）
                                      │
                                      └─ 带身份的网关 ─> 本地 DSH
                                         127.0.0.1:3088    127.0.0.1:3080
```

**它提供：** DSH 前面的精确主体允许名单、仅回环的 HTTP/WebSocket 代理，以及一条
会预览计划并拒绝公开/匿名默认值的引导命令。只安装包不会做任何事。

## 和同类插件的差别

其他 DSH 网关常常监听局域网、在 DSH 前面放登录页，或包一层公开隧道。本插件是另一套约定：

1. **我们不信任局域网。** 监听 `0.0.0.0`、把 RFC1918 当成放行，都不在范围内。监听只在回环。同一 Wi-Fi、同一 tailnet 或同一 mesh，都不是授权。
2. **我们不把登录页当作信任根。** 密码表单、共享令牌、会话 cookie 门是很大的认证面，也是常见出 bug 的地方。v1 身份来自 provider：Serve 的 `Tailscale-User-Login`，或本地校验的 Access JWT。我们核允许名单，不让你自设密码。
3. **我们用一个插件统一多家私有网络 provider。** 一条引导命令、一个回环网关、一份允许名单。v1 是 Tailscale Serve 和带 Access 的 Cloudflare Tunnel。新的 provider 是再加一个适配器，不是再做一个产品。

## 明确不做

- 让 DSH 本身变成多租户，或降低允许名单用户的权限（每个被允许的主体都是完整的
  DSH 管理员）。
- 把设备、节点或 mesh 成员身份当成人类身份。
- 提供可配置的通用反向代理，或任意可信任头名称。
- 支持公开匿名隧道、Funnel 或 Cloudflare quick tunnel。
- 管理 provider 级 ACL、DNS 区或账号策略。
- 卸载时自动删除持久化的 provider 路由。
- 接受用户自选密码。
- 在一个网关实例中同时运行多个入口 provider。
- 防御恶意的本机管理员，或已经能读取 DSH 内存/配置、或能直连 DSH 回环的进程。

## Provider 与认证兼容性

| Provider | 认证模式 | 它证明的身份 | 生命周期 | v1 成熟度 |
| --- | --- | --- | --- | --- |
| Tailscale Serve | `trusted-header` | Serve 注入的精确 `Tailscale-User-Login`（会覆盖调用方自带值）。不是“tailnet 上的任何人”。 | `ensure`（只创建一条缺失的私有路由）或 `verify-only` | **v1，可托管** |
| 带 Access 的 Cloudflare Tunnel | `signed-jwt` | 本地校验的 Access 身份 JWT（`Cf-Access-Jwt-Assertion`、RS256、issuer、audience、`email`、非空 `sub`）。不是方便邮箱头，不是 service token，也不是“主机名是私有的”。 | `verify-only` | **v1，仅校验** |
| EasyTier | `gateway-credential` | 持有为该操作员签发的高熵网关凭证。EasyTier 只提供传输。 | 无 | **不是 v1** |

私有可达性不是授权。tailnet 成员、可从互联网路由到的 Cloudflare 主机名、或
mesh 对等节点都可以碰到端点，但若允许名单不匹配，仍会得到 403。

Cloudflare 细节：Access 保护的应用常常可以从互联网访问。未认证的包可以到达边
缘。受支持的形态是“身份门控的应用 + 网关强制本地 JWT 校验”，绝不是匿名公开隧
道。v1 无法在没有宽权限账号凭证的情况下机器证明 Access 仍附着在该主机名上；
setup 会如实说明，并且仍然拒绝缺失或无效的 JWT。

## 快速开始

需要可用的本地 DSH Web profile，以及 Node.js 20+（通常由 DSH 提供）。

1. **安装惰性包。** 这不会启动监听，也不会改 provider 状态。

   ```sh
   dsh plugin --profile web add -w /path/to/dsh-gateway
   ```

2. **运行引导 setup，并确认显示的计划。**

   Tailscale Serve：

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider tailscale-serve
   ```

   Cloudflare Access（仅校验；你必须已经有一个只转发到 `127.0.0.1:3088` 的
   Access 应用）：

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider cloudflare-access \
     --external-origin 'https://dsh.example.invalid' \
     --team-origin 'https://team.example.invalid' \
     --application-audience 'replace-with-access-application-audience' \
     --trusted-principal 'email:operator@example.invalid'
   ```

   确认后才会写入启用的 profile 条目。setup 不会猜测、杀死或重启你的
   supervisor。请自行重启你已经在用的 DSH Web 进程。

3. **以允许名单中的主体打开配置的 HTTPS origin。** 3088 端口本身从局域网和
   provider 网络都不可达。

用 `--print` 只预览不写入。非交互 `--yes` 必须显式提供所有安全敏感值。

## 每种认证模式证明什么

- **`trusted-header`（仅 Tailscale）。** Serve 恰好注入一个
  `Tailscale-User-Login`，且该值在允许名单中，形式为 `login:<exact-login>`。
  头名称写死在代码里，不能配置成通用头。
- **`signed-jwt`（仅 Cloudflare Access）。** 请求恰好携带一个
  `Cf-Access-Jwt-Assertion`，能对团队 JWKS 验签，并匹配配置的 issuer 与应用
  audience，具备必需的 `exp`/`iat`/`nbf`、身份 `type`、标量 `email` 和非空
  `sub`。允许名单使用 `email:<exact-email>`。永远不信任 `CF_Authorization`
  cookie。
- **`gateway-credential`（已实现，v1 无 provider）。** 持有为每个操作员签发的
  ≥256 bit 凭证，在保留登录端点换成短时 `__Host-` 会话 cookie。供未来
  `identityCapability: none` 的 provider 使用（EasyTier 推迟）。Tailscale 与
  Cloudflare 不会选择该模式。

## 安装之后

```sh
dsh-gateway doctor
dsh-gateway credential issue --store /path/to/dsh-gateway/credentials.json --name operator-1
dsh-gateway credential list --store /path/to/dsh-gateway/credentials.json
dsh-gateway credential revoke --store /path/to/dsh-gateway/credentials.json --name operator-1
```

把生成条目的 `enabled: false` 并重启 DSH 即可停用。卸载**不会**删除 Tailscale
Serve 路由、Cloudflare tunnel、Access 应用或凭证文件，需要你自己删。

## 威胁模型与本机信任边界

网关防御伪造身份头、公开模式的 provider 配置、Host/Origin/请求目标走私、
provider 令牌泄漏进 DSH、过期 JWT 密钥，以及会扩大暴露面的配置笔误。详见
`SECURITY.md`。

它**不**防御本机上能连接 `127.0.0.1:3080` 或 `127.0.0.1:3088`、能读 DSH
profile、或拥有本地 root 的进程。回环 TCP 无法证明是哪个本地可执行文件打开的
连接。本机沦陷不在范围内。

## TLS、密钥与凭证

- Profile YAML 从不包含私钥、JWT 或已签发的凭证明文。
- Cloudflare 签名密钥从团队 origin 的 JWKS 路径按有界 HTTPS 拉取，不写入
  profile。
- 网关凭证（若使用）只在操作员提供的绝对路径存储校验器，并要求严格权限。明文
  只显示一次。
- 像对待其他密钥文件一样备份凭证库；撤销按主体进行。会话在内存中，sidecar
  重启即失效。

## 排障

**不要**为了“先跑起来”而关闭认证、Origin 检查、TLS 或 provider 校验。

| 现象 | 检查 |
| --- | --- |
| sidecar 一直未就绪 | `dsh-gateway doctor`；Tailscale Serve 冲突/Funnel；Cloudflare JWKS；缺少允许名单 |
| 预期用户 403 | 精确、区分大小写的主体（`login:` / `email:`）；重复身份头；POST/API/WebSocket 缺少 Origin |
| setup 拒绝写入 | 已有 `dsh-gateway` 或旧版 `dsh-tailscale-gateway` 条目；非列表 YAML；`--yes` 缺值 |
| 配了 Access 仍 403 | 身份 token 缺失/过期；audience 错误；service token（无 `email`）；Access 未附着（探测可能报告 `unprotected`） |

## 明确不是 v1

它们以后可能映射到同一套契约。“它是 VPN”不够。

- **EasyTier** — 没有 L7 身份（正确映射是 `gateway-credential`），但 overlay
  绑定、转发与事后校验尚未取证。
- **Headscale** — 没有原生 Serve 等价物；用户自建反向代理不会继承 Tailscale
  固定的头来源保证。
- **ZeroTier / 仅 WireGuard** — 没有 L7 身份；需要 `gateway-credential`、mTLS
  或身份代理，外加私有绑定/TLS 证据。
- **NetBird** — 声称的身份头在没有引用过的覆盖配置文件和集成测试前不受支持。
- **Twingate / Pangolin** — 没有冻结的 JWT/头校验配置文件。
- **通用反向代理 / 任意 trusted-header** — 太容易配成可伪造的头。
- **裸 LAN、SSH 隧道、公开隧道** — 超出私有入口契约。

旧的 `dsh-tailscale-gateway` 包仍是仅 Tailscale 的参考产品。两个 sidecar 不能
同时绑定同一个固定网关端口。setup 若发现旧条目会拒绝再追加。

## 配置

启用配置是封闭的判别联合。未知键是错误。不存在 `listenHost`、`listenPort`、
`upstream`、`headerName`、`jwksUrl`、`allowAnonymous`、`trustPrivateNetwork`、
`public` 或 `funnel` 键。

Tailscale：

```yaml
enabled: true
externalOrigin: 'https://gateway.example-tailnet.ts.net:8443'
provider:
  type: tailscale-serve
  routeManagement: ensure
auth:
  mode: trusted-header
  trustedPrincipals:
    - 'login:operator@example.invalid'
```

Cloudflare：

```yaml
enabled: true
externalOrigin: 'https://dsh.example.invalid'
provider:
  type: cloudflare-access
  routeManagement: verify-only
  teamOrigin: 'https://team.example.invalid'
  applicationAudience: 'replace-with-access-application-audience'
auth:
  mode: signed-jwt
  trustedPrincipals:
    - 'email:operator@example.invalid'
```

## 许可证

MIT。见 `LICENSE`。
