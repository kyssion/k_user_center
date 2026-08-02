# EVENT：事件、Webhook 与消费水位

- 存储：`outbox_events`、`inbox_messages`、`event_schema_versions`、`webhook_subscriptions`、`webhook_signing_keys`、`webhook_deliveries`、`webhook_delivery_attempts`、`event_replay_requests`、`consumer_checkpoints`。
- 聚合：`EventSchemaVersion`、`WebhookSubscription`、`ReplayRequest`；投递为队列事实。
- 代码规则：至少一次、Inbox 去重、聚合版本防乱序、核心事件 Schema、Producer 授权、完整事件信封、显式 Subject/Actor 标识类型、敏感级别、pairwise Subject、Webhook 验签/重放窗/SSRF、受控回放。
- 分区：Outbox/Inbox Hash 保证全局去重；投递和尝试按月 Range。
- 禁止：把核心信封隐藏在 `headers`；事件默认携带 PII/Global UID；未授权 Producer；回放重复不可逆副作用。
- 门禁：`EVT-G-*`、`AT-EVENT-*`、断档补拉和 DNS 重绑定负向测试。
