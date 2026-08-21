# DSH One Gateway

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4c1.svg" alt="MIT license"></a>
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-Web%20profile-0ea5e9.svg" alt="DSH Web-profile bundle"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%E2%89%A520-339933.svg" alt="Node.js 20 or later"></a>
</p>

<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a></p>

<p align="center"><strong>把 DSH Web 分享给指定的人——而不是整个网络。</strong></p>

这是一个 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(DSH) 插件：在 DSH Web 前面放一层私有的零信任网关。调用方通过 Tailscale Serve、
Cloudflare Access，或（在 Headscale 上）私有 TCP Serve 前面的系统生成网关凭证
完成认证；一份私有允许名单决定谁能进来。没有用户自选密码要你管。

它**不是**内网穿透工具，也不替代 Tailscale / Cloudflare。它为你已有的
Tailscale / Cloudflare 内网穿透方案加上身份校验——自托管的访问控制，面向零信任
家庭实验室：能连上不等于被允许。

回环网关和 DSH 都只监听回环地址。受支持的入口（Tailscale Serve，带
Cloudflare Access 的 Cloudflare Tunnel，或 Headscale 上的 Tailscale TCP Serve）
只负责把请求送到本机。加入该私有网络 **从来不是**授权决定。任何请求在转发到
DSH 之前，都必须解析出一个明确的、在允许名单中的主体。

```text
允许名单中的浏览器 ─ HTTPS ─> 入口（Tailscale Serve、Cloudflare Access，
                                      │           或 Headscale TCP Serve）
                                      └─ 回环网关 ─> 本地 DSH
                                         127.0.0.1:3088  127.0.0.1:3080
```

**你得到的是：** DSH 前面的精确主体允许名单、仅回环的 HTTP/WebSocket 代理，以及
一条会预览计划并拒绝公开/匿名默认值的引导命令。只安装插件不会做任何事，直到你
运行 setup。

完整命令是 `dsh-one-gateway`；同时安装较短的 `dsh-gateway` 别名，方便输入。

## 和同类插件的差别

其他 DSH 网关常常监听局域网、在 DSH 前面放登录页，或包一层公开隧道。本插件是
另一套约定：

1. **私有网络成员身份从来不是授权。** 监听 `0.0.0.0`、把 RFC1918 当成放行，都
   不在范围内。监听只在回环。同一 Wi-Fi、同一 tailnet 或同一 mesh，都不会让你
   进来。
2. **对 Tailscale Serve 和 Cloudflare Access，身份来自入口本身——不是登录页、
   密码或共享令牌。** 密码表单、共享令牌、会话 cookie 门是很大的认证面，也是
   常见出 bug 的地方。这两种已交付模式使用 Serve 注入的
   `Tailscale-User-Login`，或本地校验的 Cloudflare Access JWT。我们核对允许名单，
   不让你自设密码。`gateway-credential` 是给没有原生身份的传输准备的、更小的
   专用登录：系统生成的每主体凭证（不是用户自选密码）、只存校验值、有界的
   `HttpOnly`/`Secure`/`SameSite=Strict` 会话、可单独吊销、限速但不永久锁定。
   相对于典型的用户自选或共享密码，它在可猜测性、存储泄露和吊销范围上更强；
    这不是“无密码”或“没有登录”，也不是宣称优于每一种密码或通行密钥。Headscale
    TCP Serve 是已交付、使用该模式的传输入口。
3. **一个插件、一条引导命令、一份允许名单。** 不必为每个入口单独搭一套。
    Tailscale Serve、带 Access 的 Cloudflare Tunnel，以及 Headscale TCP Serve
    共用同一个回环网关。新的入口是再加一个适配器，不是再做一个产品。

## 明确不做

- 让 DSH 本身变成多租户，或降低允许名单用户的权限（每个被允许的主体都是完整的
  DSH 管理员）。
- 把设备、节点或 mesh 成员身份当成人类身份。
- 提供可配置的通用反向代理，或任意可信任头名称。
- 支持公开匿名隧道、Funnel 或 Cloudflare quick tunnel。
- 管理入口级 ACL、DNS 区或账号策略。
- 卸载时自动删除持久化的入口路由。
- 接受用户自选密码。
- 在一个网关实例中同时运行多个入口。
- 防御恶意的本机管理员，或已经能读取 DSH 内存/配置、或能直连 DSH 回环的进程。

## 受支持的入口

| 入口 | 认证模式 | 它证明的身份 | setup 实际做什么 |
| --- | --- | --- | --- |
| Tailscale Serve | `trusted-header` — Serve 注入登录头 | Serve 注入的精确 `Tailscale-User-Login`（会覆盖调用方自带值）。不是“tailnet 上的任何人”。 | 可以为你创建一条缺失的私有 Serve 路由（`routeManagement: ensure`），或只检查路由已经存在（`verify-only`）。 |
| 带 Access 的 Cloudflare Tunnel | `signed-jwt` — 本地校验 Access 身份令牌 | 本地校验的 Access 身份 JWT（`Cf-Access-Jwt-Assertion`、RS256、issuer、audience、`email`、非空 `sub`）。不是方便邮箱头，不是 service token，也不是“主机名是私有的”。 | 你自己配置 Access 应用，并只转发到网关。setup 校验本地 JWT 设置（`routeManagement: verify-only`）；它无法独立证明 Access 仍附着在隧道上。 |
| Headscale（经 Tailscale TCP Serve） | `gateway-credential` — 持有网关密钥 | 持有为该操作员签发的高熵网关凭证。TCP Serve 只提供私有可达性，没有 HTTP 身份头，也不能证明你是谁。 | 可以为你创建一条指向 `127.0.0.1:3088` 的缺失私有 TCP Serve 转发（`ensure`），或只检查它已经存在（`verify-only`）。证书和私钥由你提供。在 Tailscale.com 上，setup 会引导你走有身份的 Tailscale Serve，而不是这条更弱的路径。 |
| EasyTier | `gateway-credential` — 持有网关密钥 | 持有为该操作员签发的高熵网关凭证。EasyTier 只提供传输。 | **尚未提供。** |

私有可达性不是授权。tailnet 成员、可从互联网路由到的 Cloudflare 主机名、或
mesh 对等节点都可以碰到端点，但若允许名单不匹配，仍会得到 403。

Cloudflare 细节：Access 保护的应用常常可以从互联网访问。未认证的包可以到达边
缘。受支持的形态是“身份门控的应用 + 网关强制本地 JWT 校验”，绝不是匿名公开隧
道。本地令牌校验是扎实的。网关无法在没有宽权限账号凭证的情况下机器证明
Access 仍附着在该隧道上；setup 会如实说明，并且仍然拒绝缺失或无效的 JWT。

## 快速开始

需要可用的本地 DSH Web profile，以及 Node.js 20+（通常由 DSH 提供）。

1. **安装插件。** 这不会启动监听，也不会改入口状态。在你运行 setup 之前，什么
   都不会暴露出去。

   ```sh
   dsh plugin --profile web add -w /path/to/dsh-one-gateway
   ```

2. **运行引导 setup，并确认显示的计划。**

   在终端里省略 `--provider` 会打开菜单。Tailscale.com 上的操作员会被引导到
   有身份的 Tailscale Serve；当现场节点在 Headscale 上时，才会列出 Headscale
   TCP Serve。检测到本地可执行文件只是提示；当恰好检测到一个入口时，它会成为
   默认值——不是配置校验。传入 `--provider` 可跳过菜单。非交互 setup 在恰好
   检测到一个入口可执行文件时仍会自动选择，否则必须提供 `--provider`。

   Tailscale Serve：

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider tailscale-serve
   ```

   Cloudflare Access（你自己配置 Access；网关只在本地校验令牌）。你必须已经有
   一个只转发到 `127.0.0.1:3088` 的 Access 应用：

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider cloudflare-access \
     --external-origin 'https://dsh.example.invalid' \
     --team-origin 'https://team.example.invalid' \
     --application-audience 'replace-with-access-application-audience' \
     --trusted-principal 'email:operator@example.invalid'
   ```

   在 TTY 中，未提供的 Cloudflare 值会按此顺序交互收集：已有 Access origin、
   团队 origin、应用 audience、受信任邮箱。无人值守的 `--yes` 仍必须提供全部
   四个标志。setup 不会创建隧道、DNS 记录或 Access 应用。

   Headscale TCP Serve（私有可达性加上系统生成的网关凭证；证书由你提供）。
   在 Tailscale.com 上，setup 不会把它当作同等权重的菜单项：

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider headscale-tcp-serve \
     --tls-cert /path/to/dsh-one-gateway/cert.pem \
     --tls-key /path/to/dsh-one-gateway/key.pem \
     --credential-store /path/to/dsh-one-gateway/credentials.json \
     --trusted-principal operator-1
   ```

   TCP Serve 不终止 HTTPS，也不证明身份。网关在 `127.0.0.1:3088` 上用你提供的
   证书终止 TLS。客户端必须信任该证书；本轮不生成私有 CA。确认后，setup 签发
   一份凭证，明文只显示一次，绝不写入 profile。`--print` 不会签发任何凭证。

   确认后才会写入启用的 profile 条目。setup 不会猜测、杀死或重启你的
   supervisor。请自行重启你已经在用的 DSH Web 进程。

3. **以允许名单中的主体打开配置的 HTTPS origin。** 3088 端口本身从局域网和
   入口网络都不可达。

用 `--print` 只预览不写入。在 TTY 中，`--print` 仍可能询问入口和缺失值，但
绝不会写入 profile、入口资源或凭证。非交互 `--yes` 必须显式提供所有安全敏感
值。`--yes` 只跳过最后的写入确认，不会替你发明入口或 Cloudflare 参数。

## 每种认证模式证明什么

这些 `auth.mode` 值就是 YAML 里的字面键。每一种都和固定的入口绑定，不能混用。

- **`trusted-header`（仅 Tailscale）。** Serve 恰好注入一个
  `Tailscale-User-Login`，且该值在允许名单中，形式为 `login:<exact-login>`。
  头名称写死在代码里，不能配置成通用头。
- **`signed-jwt`（仅 Cloudflare Access）。** 请求恰好携带一个
  `Cf-Access-Jwt-Assertion`，能对团队 JWKS 验签，并匹配配置的 issuer 与应用
  audience，具备必需的 `exp`/`iat`/`nbf`、身份 `type`、标量 `email` 和非空
  `sub`。允许名单使用 `email:<exact-email>`。永远不信任 `CF_Authorization`
  cookie。
- **`gateway-credential`（Headscale TCP Serve）。** 持有为每个操作员签发的
  ≥256 bit 凭证（由 CLI 生成，不是用户自选密码），经 JSON API 或同源登录表单
  的 POST 正文提交——从不放进 URL 查询参数——换成短时 `__Host-` 会话 cookie
  （`HttpOnly`、`Secure`、`SameSite=Strict`）。网关只存校验哈希；会话可单独
  吊销，尝试会被限速但不永久锁定。TCP Serve 不贡献身份：能连上节点不是授权。
  Tailscale Serve 和 Cloudflare Access 不能选择该模式。

## 安装之后

```sh
dsh-gateway doctor
dsh-gateway credential issue --store /path/to/dsh-one-gateway/credentials.json --name operator-1
dsh-gateway credential list --store /path/to/dsh-one-gateway/credentials.json
dsh-gateway credential revoke --store /path/to/dsh-one-gateway/credentials.json --name operator-1
```

把生成条目的 `enabled: false` 并重启 DSH 即可停用。卸载**不会**删除 Tailscale
Serve 路由、Cloudflare tunnel、Access 应用或凭证文件，需要你自己删。

## 威胁模型与本机信任边界

网关防御伪造身份头、公开模式的入口配置、Host/Origin/请求目标走私、入口令牌泄
漏进 DSH、过期 JWT 密钥，以及会扩大暴露面的配置笔误。详见 `SECURITY.md`。

它**不**防御本机上能连接 `127.0.0.1:3080` 或 `127.0.0.1:3088`、能读 DSH
profile、或拥有本地 root 的进程。回环 TCP 无法证明是哪个本地可执行文件打开的
连接。本机沦陷不在范围内。

## TLS、密钥与凭证

- Profile YAML 从不包含私钥、JWT 或已签发的凭证明文。
- Cloudflare 签名密钥从团队 origin 的 JWKS 路径按有界 HTTPS 拉取，不写入
  profile。
- Headscale TCP Serve 要求操作员提供的证书和私钥（绝对路径、严格的私钥权限、
  密钥与证书匹配、未过期、SAN 覆盖 `externalOrigin`）。网关不生成 CA 或自签
  证书。客户端必须把该证书加入信任。
- 网关凭证（若使用）只在操作员提供的绝对路径存储校验器，并要求严格权限。明文
  只显示一次。
- 像对待其他密钥文件一样备份凭证库；撤销按主体进行。会话在内存中，网关进程
  重启即失效。

## 排障

**不要**为了“先跑起来”而关闭认证、Origin 检查、TLS 或入口校验。

| 现象 | 检查 |
| --- | --- |
| 网关一直未就绪 | `dsh-gateway doctor`；Tailscale Serve 冲突/Funnel；TCP Serve 冲突/Funnel；TLS 证书/私钥；Cloudflare JWKS；缺少允许名单 |
| 预期用户 403 | 精确、区分大小写的主体（`login:` / `email:`）；重复身份头；POST/API/WebSocket 缺少 Origin |
| setup 拒绝写入 | 已有 `dsh-gateway` 或旧版 `dsh-tailscale-gateway` 条目；非列表 YAML；`--yes` 缺值 |
| 配了 Access 仍 403 | 身份 token 缺失/过期；audience 错误；service token（无 `email`）；Access 未附着（探测可能报告 `unprotected`） |

## 尚未支持

它们以后可能映射到同一套约定。“它是 VPN”不够。

- **EasyTier** — 没有应用层身份、无法证明实际是谁在调用（正确映射是
  `gateway-credential`），但 overlay 绑定、转发与事后校验尚未取证。
- **Headscale HTTPS Serve** — 仍然不支持。Headscale 没有 Tailscale 那种带身份
  的 HTTPS Serve。已交付的 Headscale 路径是原始 TCP Serve，加上
  `gateway-credential` 和操作员提供的证书，而不是伪造的身份头。
- **ZeroTier / 仅 WireGuard** — 没有应用层身份；需要 `gateway-credential`、
  mTLS 或身份代理，外加私有绑定/TLS 证据。
- **NetBird** — 声称的身份头在没有引用过的覆盖配置文件和集成测试前不受支持。
- **Twingate / Pangolin** — 没有冻结的 JWT/头校验配置文件。
- **通用反向代理 / 任意 trusted-header** — 太容易配成可伪造的头。
- **裸 LAN、SSH 隧道、公开隧道** — 超出私有入口约定。

旧的 `dsh-tailscale-gateway` 包仍是仅 Tailscale 的参考产品。两个网关进程不能
同时绑定同一个固定网关端口。setup 若发现旧条目会拒绝再追加。

## 配置

只接受下面展示的字段。未知键是错误。不存在 `listenHost`、`listenPort`、
`upstream`、`headerName`、`jwksUrl`、`allowAnonymous`、`trustPrivateNetwork`、
`public` 或 `funnel` 键。

Tailscale — `trusted-header` 表示由 Serve 注入登录；`routeManagement: ensure`
表示 setup 会创建一条缺失的私有 Serve 路由：

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

Headscale TCP Serve — `gateway-credential` 表示持有系统生成的密钥；TCP Serve
只提供私有可达性。必须提供 `tls`：

```yaml
enabled: true
externalOrigin: 'https://gateway.example.invalid:8443'
provider:
  type: headscale-tcp-serve
  routeManagement: ensure
tls:
  certPath: '/path/to/dsh-one-gateway/cert.pem'
  keyPath: '/path/to/dsh-one-gateway/key.pem'
auth:
  mode: gateway-credential
  trustedPrincipals:
    - 'credential:operator-1'
  credentialStorePath: '/path/to/dsh-one-gateway/credentials.json'
```

Cloudflare — `signed-jwt` 表示网关在本地校验 Access 身份 JWT；
`routeManagement: verify-only` 表示由你自己挂上 Access：

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
