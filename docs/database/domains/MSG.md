# MSG：消息投递

- 存储：`message_providers`、`message_template_versions`、`message_requests`、`message_delivery_attempts`、`contact_reachability`、`message_suppressions`。
- 聚合：`MessageRequest`、`ContactReachability`、`MessageSuppression`；模板版本不可变。
- 代码规则：目标加密、目的限速、模板变量 Schema、安全转义、抑制优先级、多供应商路由、回执和成本归一。
- 禁止：供应商故障时绕过认证；模板/日志含验证码之外的秘密或完整 Token；营销退订失效。
- 事件：发送结果、可达性变化、抑制变化和供应商健康。
- 门禁：通道故障演练、幂等发送、硬退信/投诉、模板注入和敏感输出扫描。

