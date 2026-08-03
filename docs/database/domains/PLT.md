# PLT：平台接入与运行基座

- 存储：`business_lines`、`applications`、`oauth_clients`、`api_resources`、`usage_records`、`resource_quotas`、配置发布表。
- 聚合：`BusinessLine`、`Application`、Client 上线认证 `Operation`。
- 业务模型要求：持久化模型必须保存所有者、环境、Security Profile、接入结果、配额和发布证据；容量、备份恢复与发布门禁的执行属于非数据库职责。
- 禁止：Seed 创建生产 Client/管理员/秘密；业务系统直接获得 IAM 数据库账号。
- 事件：应用/Client 状态、配置发布、配额告警和接入认证结果。
- 门禁：`CAP-PLT-*`、协议一致性、状态机属性、密钥轮换、租户隔离和 DR 演练。
