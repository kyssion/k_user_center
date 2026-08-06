# 代码实施契约索引

本目录把能力地图、验收蓝图和数据库持久化边界展开为代码必须实现的命令、事务、并发、幂等、事件和错误契约，但不绑定 Controller、Handler、Repository、ORM 或消息组件。

数据库只负责事实持久化、PK/Unique/NOT NULL、稳定的基础行内 Check、CAS 字段、技术时间、索引、分区和部署身份的粗粒度隔离。参数与 Schema 校验、逻辑引用、状态转换、最终用户/管理员权限、租户与数据范围、领域 Owner、风险、审批、协议语义、重试、补偿和删除编排均由用户中心代码负责。

## 文档

| 文档 | 范围 |
|---|---|
| [全局持久化与事务规范](./全局持久化与事务规范.md) | 所有命令统一遵守的事务、CAS、幂等、Outbox、Audit、权限、错误和查询契约 |
| [ID、AUTH、OAP 与 SESSION 命令规范](./ID-AUTH-OAP-SESSION命令规范.md) | 用户、Subject、标识、认证、授权码、Token 和会话 |
| [TENANT、AUTHZ、PRIV 与 CTRL 命令规范](./TENANT-AUTHZ-PRIV-CTRL命令规范.md) | Membership、邀请、授权事实、Consent、隐私请求、审批和配置发布 |
| [EVENT、MSG、RISK、MACHINE、KEY、FED 与 MIG 命令规范](./EVENT-MSG-RISK-MACHINE-KEY-FED-MIG命令规范.md) | 事件投递、消息、风险、机器身份、密钥证书、目录同步和迁移 |
| [PROFILE、SSC、ASR、PLT 与 OBS 命令规范](./PROFILE-SSC-ASR-PLT-OBS命令规范.md) | 资料、身份保证、自助安全中心、应用接入、配额、审计与可观测性 |

## 开始编码前门禁

每个进入迭代的命令必须明确：

1. 对应 `CAP/REQ/INV/API/EVT/AT` 编号。
2. 调用者、主体和 Tenant/Client/Business Line 作用域。
3. 参数格式、Schema、Allowlist、前置条件和失败关闭规则。
4. 最终用户/管理员权限、数据范围、领域 Owner、风险和审批判断。
5. 读取表、写入表、逻辑引用校验、事务边界和锁/CAS 条件。
6. 唯一、NOT NULL、基础 Check、并发和持久化异常的稳定错误映射。
7. 幂等键作用域、请求摘要及同键不同请求处理。
8. 与权威事实同事务写入的 Outbox、Audit 和幂等结果。
9. 外部调用位置、重试、补偿、不可逆边界和人工接管条件。
10. 正向、参数非法、越权、跨租户、并发、重放、过期和故障注入测试。

数据库角色只代表部署身份，不能作为业务授权已经通过的证据。禁止仅凭“由代码负责”开始实现，也禁止把同一套业务权限或状态机同时放入代码和数据库。
