# OAP：OAuth/OIDC Provider

- 存储：`oauth_clients`、`api_resources`、`oauth_scopes`、`login_transactions`、`authorization_codes`、`authorization_grants`、`token_families`、`refresh_token_instances`、`access_token_records`、`revocation_entries`。
- 聚合：`Client`、`AuthorizationGrant`、`TokenFamily`；Code/Token 记录为单次或追加事实。
- 代码规则：Authorization Code + PKCE、精确 Redirect、Client 认证、Scope/Consent、Device Flow、Token 签发/验证、Refresh 轮换和撤销。
- 禁止：ROPC/自定义密码轮询；未完成登录事务签发；Token 原文落库；风险升高时静默降级。
- 事件：Grant/Token Family/Client 安全状态变化和撤销水位。
- 门禁：`REQ-OAP-*`、`AT-OAP-*`、`AT-SESSION-*` 和协议一致性套件。

