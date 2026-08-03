# SESSION：设备、会话与撤销

- 持久化范围：`devices`、`sessions`、`session_participants`、`revocation_entries`，并引用 Token/Grant 表。
- 业务模型边界：`Device`、`Session`、全局退出 `Operation`。
- 权威边界：SESSION 持有设备、会话和统一撤销事实；Token/Grant 由 OAP 持有，SESSION 不直接改写其生命周期，而通过统一撤销事实和安全水位约束后续签发与验证。
- 业务模型要求：持久化模型必须支持空闲/绝对过期、设备信任、冻结和安全水位、Profile/策略/Consent/撤销水位快照、并发会话、RP 前后通道退出和撤销失败关闭所需事实。
- 持久化原子性：撤销 Session/Grant/Token 的权威事实、安全水位递增、Outbox 和 Audit 必须共同提交。
- 事件：会话创建/刷新/撤销、设备信任变化、全局退出进度。
- 门禁：`AT-SESSION-*`、`SLO-REVOKE-*`；刷新与冻结、Consent 撤回、委托撤销竞争时不得产生新有效 Token，SP2/SP3/SP5 水位不确定时失败关闭。
