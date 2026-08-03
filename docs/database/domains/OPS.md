# OPS：跨域操作与运营处置

- 存储：`operations`、`operation_steps`、`approval_cases`、`audit_events`。
- 聚合：通用 Saga `Operation`，不为注销、合并、换绑、迁移分别建数据库工作流。
- 业务模型要求：`operations + operation_steps` 只保存检查点、幂等步骤状态、不可逆边界、超时、结果和证据；补偿、前向修复与人工接管流程不在数据库中实现。
- 事务：每一步只提交本地事实和下一步 Outbox；不使用分布式数据库事务。
- 禁止：越过不可逆边界后伪装回滚；重复执行已完成副作用。
- 门禁：故障注入、宕机恢复、检查点继续和跨主体/租户 Operation 越权测试。
