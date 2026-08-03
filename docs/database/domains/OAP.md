# OAP：OAuth/OIDC Provider

- 持久化范围：`oauth_clients`、`api_resources`、`oauth_scopes`、`login_transactions`、`authorization_codes`、`authorization_grants`、`token_families`、`refresh_token_instances`、`access_token_records`、`revocation_entries`；Access Token 记录按 JTI Hash 分区并由数据库保证 JTI 全局唯一。
- 业务模型边界：`Client`、`AuthorizationGrant`、`TokenFamily`；Code/Token 记录为单次或追加事实。
- 权威边界：OAP 持有 Client、API Resource、Scope、授权码、Grant 和 Token 事实；`login_transactions` 由 AUTH 持有，PLT 只负责编排接入，CTRL 只负责配置审批，`revocation_entries` 由 SESSION 持有，OAP 提交撤销原因并消费统一水位。
- 业务模型要求：持久化模型必须支持 Authorization Code + PKCE、精确 Redirect、Client 认证、Scope/Consent、Device Flow、Token 签发/验证、Refresh 轮换和撤销；签发记录固化 Subject/Actor/委托链、Profile、策略、Consent、水位、Audience 和 DPoP/mTLS 确认值。
- 禁止：ROPC/自定义密码轮询；未完成登录事务签发；Token 原文落库；风险升高时静默降级。
- 事件：Grant/Token Family/Client 安全状态变化和撤销水位。
- 门禁：`REQ-OAP-*`、`AT-OAP-*`、`AT-SESSION-*` 和协议一致性套件；SP4 禁止 Refresh Token，SP5 必须 PAR 和发送方约束。
