# OBS：审计、可观测性与 SLO

- 存储：`audit_events`、`usage_records`、各类追加事实表，以及 `SLO_BASELINE` 配置。
- 聚合：审计为不可变事件；指标、日志和 Trace 主要在可观测性设施，不把时序平台复制成业务表。
- 代码规则：结构化日志、Trace 传播、审计失败关闭、敏感数据扫描、SLO/错误预算和告警路由。
- 权限：审计 Writer 仅 INSERT，Reader 仅 SELECT，普通应用不可更新或删除。
- 事件：安全告警和运维事件必须引用稳定原因码和 Trace，不含密码/验证码/Token。
- 门禁：`AT-AUDIT-*`、`AT-SEC-*`、`AT-SLO-*`、告警和值班演练。

