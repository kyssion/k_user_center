# SSC：Scope、订阅与 Consent 协同

- 存储：`oauth_scopes`、`authorization_grants`、`consent_aggregates`、`consents`、`webhook_subscriptions`、`policy_versions`。
- 聚合：Scope 为稳定目录；Grant、Consent 和订阅分别维护状态，代码计算共同有效交集。
- 代码规则：最小 Scope、目的和类别匹配、接收方约束、订阅前置、撤回传播及合法依据隔离。
- 禁止：Pending/拒绝/过期 Consent 启动订阅或签发 Token；撤回一个目的影响无关合法处理。
- 事件：Consent/Grant/订阅状态变化和传播进度。
- 门禁：`CAP-SSC-*`、`AT-PRIV-007/008/010`、Scope 收敛和传播对账。

