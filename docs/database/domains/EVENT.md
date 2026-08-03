# EVENT：事件、Webhook 与消费水位

- 持久化范围：`outbox_events`、`inbox_messages`、`event_schema_versions`、`webhook_subscriptions`、`webhook_signing_keys`、`webhook_deliveries`、`webhook_delivery_attempts`、`event_replay_requests`、`consumer_checkpoints`。
- 业务模型边界：`EventSchemaVersion`、`WebhookSubscription`、`ReplayRequest`；投递为队列事实。
- 权威边界：EVENT 持有事件信封、去重、Schema、Webhook 和消费水位契约；各业务域只在自己的权威事务中追加 Outbox 或按统一契约写 Inbox，不得改写其他领域事件与消费事实。
- 业务模型要求：持久化模型必须支持至少一次、Inbox 去重、聚合版本防乱序、核心事件 Schema、Producer 授权、完整事件信封、显式 Subject/Actor 标识类型、敏感级别、pairwise Subject、Webhook 验签/重放窗/SSRF 和受控回放。
- 分区：Outbox/Inbox Hash 保证全局去重；投递和尝试按月 Range。
- 禁止：把核心信封隐藏在 `headers`；事件默认携带 PII/Global UID；未授权 Producer；回放重复不可逆副作用。
- 门禁：`EVT-G-*`、`AT-EVENT-*`、断档补拉和 DNS 重绑定负向测试。
