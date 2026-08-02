# API：通用 API 契约

- 存储：`idempotency_records`、`operations`、`operation_steps`。
- 聚合：`IdempotentRequest`、`Operation`。
- 代码规则：统一错误注册表、`Idempotency-Key`、ETag/CAS、不透明分页、异步 `202 + operation_id`、逐项批量结果和协议错误映射。
- 授权：查询、取消、继续和人工接管 Operation 时重新校验 Actor、Subject、Tenant 和能力权限。
- 事件：Operation 状态变化；不得把内部敏感错误直接进入响应或事件。
- 门禁：`API-G-001~019`、`AT-API-001~005`。

