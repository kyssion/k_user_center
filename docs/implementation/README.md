# 代码实施契约索引

本目录把能力地图和验收蓝图中的业务规则展开为可直接指导代码实现的命令、事务、并发、幂等、事件和错误契约，但不提前绑定 Controller、Handler、Repository、ORM 或消息组件。

数据库继续只负责：事实持久化、明确内部引用的存在性、唯一性、基础行内结构、CAS 字段、技术时间、索引、分区和最小数据库权限。状态转换、租户/作用域一致性、授权、风险、审批、协议语义、重试和补偿由代码实现。

## 文档

| 文档 | 范围 |
|---|---|
| [全局持久化与事务规范](./全局持久化与事务规范.md) | 所有命令统一遵守的事务、CAS、幂等、Outbox、Audit、错误和查询契约 |
| [ID、AUTH、OAP 与 SESSION 命令规范](./ID-AUTH-OAP-SESSION命令规范.md) | 用户、Subject、标识、认证、授权码、Token 和会话 |
| [TENANT、AUTHZ、PRIV 与 CTRL 命令规范](./TENANT-AUTHZ-PRIV-CTRL命令规范.md) | Membership、邀请、授权事实、Consent、隐私请求、审批和配置发布 |
| [EVENT、MSG、RISK、MACHINE、KEY、FED 与 MIG 命令规范](./EVENT-MSG-RISK-MACHINE-KEY-FED-MIG命令规范.md) | 事件投递、消息、风险、机器身份、密钥证书、目录同步和迁移 |
| [PROFILE、SSC、ASR、PLT 与 OBS 命令规范](./PROFILE-SSC-ASR-PLT-OBS命令规范.md) | 资料、身份保证、自助安全中心、应用接入、配额、审计与可观测性 |

## 开始编码前门禁

每个进入迭代的命令必须明确：

1. 对应 `CAP/REQ/INV/API/EVT/AT` 编号。
2. 调用者、主体和 Tenant/Client/Business Line 作用域。
3. 前置条件、合法状态转换和失败关闭规则。
4. 读取表、写入表、事务边界和锁/CAS 条件。
5. 唯一冲突、Foreign Key、Check、权限和并发异常的错误映射。
6. 幂等键作用域、请求摘要及同键不同请求处理。
7. 与权威事实同事务写入的 Outbox、Audit 和幂等结果。
8. 外部调用位于事务前、事务后或 Operation 步骤中的明确位置。
9. 重试、退避、补偿、不可逆边界和人工接管条件。
10. 正向、越权、跨租户、并发、重放、过期和故障注入测试。

禁止仅凭领域文档中的一句“由代码负责”开始实现。
