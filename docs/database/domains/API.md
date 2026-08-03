# API：通用 API 契约

- 存储：`idempotency_records`、`operations`、`operation_steps`。
- 聚合：`IdempotentRequest`、`Operation`。
- 业务模型要求：持久化模型必须支持统一错误码、`Idempotency-Key`、ETag/CAS、不透明分页、异步 `202 + operation_id`、逐项批量结果和协议错误映射；Operation 创建时固化调用作用域、幂等键、请求摘要、能力编号、Saga 类型与策略版本。
- 授权：查询、取消、继续和人工接管 Operation 时重新校验 Actor、Subject、Tenant 和能力权限。
- 事件：Operation 状态变化；不得把内部敏感错误直接进入响应或事件。
- 门禁：`API-G-001~019`、`AT-API-001~005`；同调用方幂等键不得绑定两个 Operation，创建快照不得被后续步骤改写。
