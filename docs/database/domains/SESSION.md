# SESSION：设备、会话与撤销

- 存储：`devices`、`sessions`、`session_participants`、`revocation_entries`，并引用 Token/Grant 表。
- 聚合：`Device`、`Session`、全局退出 `Operation`。
- 代码规则：空闲/绝对过期、设备信任、冻结和安全水位、Profile/策略/Consent/撤销水位快照比较、并发会话、RP 前后通道退出、撤销失败关闭。
- 事务：撤销 Session/Grant/Token 与安全水位递增、Outbox、Audit 同事务。
- 事件：会话创建/刷新/撤销、设备信任变化、全局退出进度。
- 门禁：`AT-SESSION-*`、`SLO-REVOKE-*`；刷新与冻结、Consent 撤回、委托撤销竞争时不得产生新有效 Token，SP2/SP3/SP5 水位不确定时失败关闭。
