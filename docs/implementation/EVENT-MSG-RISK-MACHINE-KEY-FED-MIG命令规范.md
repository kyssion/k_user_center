# EVENT、MSG、RISK、MACHINE、KEY、FED 与 MIG 命令规范

## 1. Outbox 发布与 Inbox 消费

- 领域命令只在业务事务中追加 Outbox，不直接调用消息系统。
- 发布 Worker 只更新发布状态、尝试次数、下一次时间和发布时间，不改写事件 ID、类型、主体、Actor 或 Payload。
- 消费者先竞争 `inbox_messages(consumer_id,event_id)` 唯一键，再执行业务；成功、失败和结果摘要原子记录。
- 聚合版本倒退、安全水位倒退、Schema 不兼容和未知事件类型必须失败关闭并告警。

## 2. Webhook 投递

- 代码校验订阅 Owner、状态、事件来源、过滤条件、接收方 Subject 改写、数据分类、SSRF 和签名策略。
- `delivery_id` 使用高熵 UUID；跨时间分区防重由事件处理幂等与代码检查保证，索引只用于定位和诊断。
- 投递任务的事件、订阅和载荷摘要创建后不可修改；Worker 只更新状态、尝试次数、退避和最终结果。
- 每次 HTTP 调用追加 `webhook_delivery_attempts`；尝试序号、签名、超时、退避和重放防护由代码控制。

## 3. 消息发送

- 代码校验模板版本、变量 Schema、目标规范化、抑制、限速、数据最小化、路由和币种 Allowlist。
- `request_id` 使用高熵 UUID；调用幂等以 `idempotency_records` 为权威，查询索引用于跨分区定位。
- 目标密文、模板和参数创建后不可修改；Worker 只更新优先级、计划时间、状态和完成时间。
- 每次供应商调用追加 Delivery Attempt；尝试序号、并发控制、熔断、降级、成本语义和回执解释由代码处理。

## 4. 风险信号与评估

- 风险信号和评估为追加事实，`signal_id` 由高熵生成器与事件幂等保证跨分区唯一；数据库索引用于定位。
- 模型/策略配置引用、发布状态、适用范围、输入信号集合和新鲜度均由代码校验。
- 评分、阈值、降级和处置不通过 Check 或 Trigger 实现。
- 风险 Case、Security Signal 和 Restriction 只允许更新生命周期元数据，原始证据摘要不可改写。

## 5. 机器主体与凭证轮换

- 激活前校验 Owner、用途、环境、Tenant、到期、最小权限、算法和轮换策略。
- 新凭证创建新行并通过 `replaces_credential_id` 形成替代链；旧凭证只更新状态和失效时间。
- 指纹、Secret 哈希、Key/Certificate 引用和替代关系创建后不可修改。
- `COMPROMISED` 不得原地恢复；创建替代安全版本并撤销受影响 Token。

## 6. 密钥、证书与 JWKS 轮换

- KMS/HSM 创建 Key 后，在 `cryptographic_keys` 登记 `key_ref`、用途、算法、Owner 和有效期；业务表只保存内部 `key_id`。
- 代码校验用途、算法 Allowlist、Owner、审批、重叠验证窗口和下游兼容性；数据库不推进 Key 状态。
- 轮换创建新的 Key/Certificate/JWKS Release；使用 `Q-KEY-*` 反向索引枚举 Identifier、认证材料、导出物、证书、机器凭证、Webhook 和 JWKS 影响面。
- 外部 KMS 调用、重试和销毁属于受审批 Operation；越过销毁不可逆点前必须证明所有读写方已切换。

## 7. 目录同步

- FED 代码校验 Connector 配置、Tenant、作用域、字段映射和数据最小化；同步游标使用 CAS。
- 每批次保存起止游标摘要、读取/创建/更新/删除/冲突计数和 Operation。
- 外部对象稳定键不可修改；映射目标、源版本、墓碑和最近发现时间按源权威规则推进。
- 单对象失败不得破坏整批幂等；冲突进入显式状态并产生人工处理项。

## 8. 迁移与切换

- Legacy System 先登记权威范围、Owner、冻结窗口、权限映射和回滚条件。
- 外部对象键和变更日志幂等键不可修改；映射结果、批次检查点和逐项结果使用 CAS。
- Change Log 只追加；双写、校验、切换、回滚和物理清理由 Operation 或受审批维护流程编排。
- 越过切换不可逆点前完成数量对账、抽样一致性、权限差异、逻辑引用孤儿和撤销传播验证。
