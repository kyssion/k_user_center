# EVENT、MSG、RISK、MACHINE、KEY、FED 与 MIG 命令规范

## 1. Outbox 发布与 Inbox 消费

- 领域命令只负责同事务追加 Outbox，不直接调用消息系统。
- 发布 Worker 只能更新发布状态、尝试次数、下一次时间和发布时间，不得改写事件 ID、类型、主体、Actor 或 Payload。
- 消费者先竞争 `inbox_messages(consumer_id,event_id)` 唯一键，再执行业务；成功、失败和结果摘要原子记录。
- 聚合版本倒退、安全水位倒退或 Schema 不兼容时失败关闭并告警。

## 2. Webhook 投递

- 创建投递前校验订阅 Owner、状态、事件来源注册、事件过滤、接收方 Subject 改写和数据分类；`event_source_code` 必须明确区分本库 Outbox 与外部事件总线。
- `delivery_id` 由数据库全局唯一；同 Event/Subscription 的重复创建由 Inbox 幂等和事件订阅处理器事务保证，并通过 `(event_id,subscription_id)` 索引诊断。
- 投递任务的事件、订阅和载荷摘要创建后不可修改；Worker 只更新状态、尝试次数、退避和最终结果。
- 每次 HTTP 调用追加 `webhook_delivery_attempts`；签名、SSRF、防重放、超时和退避由代码执行。

## 3. 消息发送

- 创建请求前完成模板版本、变量 Schema、目标规范化、抑制、限速和数据最小化校验。
- `request_id` 数据库全局唯一，调用幂等由 `idempotency_records` 保证。
- 目标密文、模板和参数创建后不可修改；Worker 只更新优先级、计划时间、状态和完成时间。
- 每次供应商调用追加 Delivery Attempt；路由、熔断、降级和回执解释由代码处理。

## 4. 风险信号与评估

- 风险信号和评估为追加事实，`signal_id` 数据库全局唯一；`RISK_MODEL/RISK_POLICY` 配置版本和输入信号关系必须持久化，代码负责校验配置类型、发布状态和适用范围。
- 风险评分、阈值、降级和处置属于代码，不通过 Check 或 Trigger 实现。
- 风险 Case、Security Signal 和 Restriction 只允许更新生命周期元数据；原始证据摘要不可改写。

## 5. 机器主体与凭证轮换

- 激活前校验 Owner、用途、环境、Tenant、到期、最小权限和轮换策略。
- 新凭证创建新行并通过 `replaces_credential_id` 形成唯一替代链；旧凭证只更新状态和失效时间。
- 指纹、Secret 哈希、Key/Certificate 引用和替代关系创建后不可修改。
- `COMPROMISED` 不得原地恢复；创建替代安全版本并撤销受影响 Token。

## 6. 密钥、证书与 JWKS 轮换

- KMS/HSM 创建不可导出 Key 后，先在 `cryptographic_keys` 登记唯一 `key_ref`、用途、算法、Owner 和有效期；其他表只保存其内部 `key_id`，不得直接保存无法追踪的外部 Key 标识。
- 激活、轮换、撤销和销毁前校验用途、算法 Allowlist、Owner、审批、重叠验证窗口和下游兼容性；数据库不自行推进 Key 状态。
- 轮换创建新的 Key/Certificate/JWKS Release，不改写旧 Key 对象；使用 `Q-KEY-*` 反向索引枚举 Identifier、认证材料、导出物、证书、机器凭证、Webhook 和 JWKS 影响面。允许重加密的当前数据以 CAS 原子更新密文、指纹和 `key_id`，凭证材料、证书和发布内容则创建新版本/新行。
- 旧 Key 只更新状态；证书写入撤销事实；JWKS 通过不可变 Release/Release Key 发布。私钥材料、KMS 解密结果和签名上下文不得落库。
- 外部 KMS 调用、重试和销毁属于受审批 Operation；越过销毁不可逆点前必须证明所有读写方已切换并保留审计证据。

## 7. 目录同步

- Connector 配置和作用域由 FED 代码验证；同步游标使用 CAS。
- 每批次保存起止游标摘要、读取/创建/更新/删除/冲突计数和 Operation。
- 外部对象稳定键不可修改；映射目标、源版本、墓碑和最近发现时间按源权威规则推进。
- 单对象失败不得破坏整批幂等；冲突进入显式状态并产生人工处理项。

## 8. 迁移与切换

- Legacy System 先登记权威范围、Owner、冻结窗口和回滚条件。
- 外部对象键和变更日志幂等键不可修改；映射结果、批次检查点和逐项结果使用 CAS。
- Change Log 只追加；双写、校验、切换和回滚由 Operation 编排。
- 越过切换不可逆点前必须完成数量对账、抽样一致性、权限差异和撤销传播验证。
