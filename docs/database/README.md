# 数据库实施导航

数据库实施以 [数据库设计总纲](../数据库设计总纲.md) 为候选基线，以 `database/postgresql` 下的 SQL 为可执行权威来源；算法与密码合规开放项关闭并完成真实 PostgreSQL 验证后，方可标记为最终冻结基线。

本目录描述业务模型是否能被数据库事实完整表达、哪些关系需要持久化以及 PostgreSQL 应承担哪些硬边界。技术无关的命令、事务、CAS、幂等、事件和错误契约位于 `docs/implementation`；具体类、Handler、Repository、API DTO、ORM 和组件调用实现不在本目录定义。

## 交付物

| 位置 | 用途 |
|---|---|
| `database/postgresql/bootstrap` | 数据库角色和数据库级最小权限 |
| `database/postgresql/migrations` | 117 张表、约束、索引、分区和运行时权限 |
| `database/postgresql/seeds` | 稳定目录和 DRAFT 控制面候选版本，不创建用户、租户、Client 或秘密 |
| `database/postgresql/verification` | Schema、Comment、禁止对象、敏感字段、全部可解析逻辑关系、Seed 和权限门禁 |
| `业务模型与持久化边界清单.md` | 业务模型、持久化事实、数据库硬边界和非数据库职责索引 |
| `逻辑关系与非数据库校验清单.md` | FK 保护关系、逻辑引用登记和非数据库校验提示 |
| `需求编号与数据库持久化覆盖索引.md` | 能力地图/蓝图编号到数据库持久化边界的覆盖索引；不是代码实施或验收矩阵 |
| `查询与索引契约.md` | 关键代码查询路径到索引/唯一约束的可执行前置契约 |
| `domains/*.md` | 21 个能力域的业务模型、持久化边界和明确非数据库职责 |
| `generated/*.md` | 从 SQL 或数据库目录生成的只读报告 |
| `../implementation/*.md` | 面向代码实现的命令、事务、并发、幂等、事件和错误契约 |

## 设计边界

- 数据库：存储事实、PK/Unique、基础 Check、确定内部引用的 FK、内部多值关系表、技术时间、数据库维护的 CAS 版本、索引、分区和列级权限。
- 非数据库职责：多态/外部引用解析、租户一致性、目标状态、业务授权求值、风险、审批、加密、协议、幂等语义、流程和删除编排；具体实现以 `docs/implementation` 为准。
- 数据权威：每张逻辑表映射到一个主要业务模型和权威域；多域复用按 `业务模型与持久化边界清单.md` 的共享表权威执行，不得形成未声明双写或影子状态。
- 直接内部引用使用 `RESTRICT` Foreign Key；只允许统一维护 `updated_at/row_version` 的纯技术 Trigger，不创建业务 Trigger、持久化业务 Routine、PostgreSQL Enum 和业务 View。
- 所有重要写入必须将权威数据、Outbox、审计事件和幂等结果放在同一应用事务中。

## 分区实现说明

PostgreSQL 分区表的唯一约束必须包含分区键。凡标识承担数据库去重键或被其他表稳定引用时，使用该标识作为 Hash 分区键；仅按时间归档且不承担全局唯一目标的事实使用 Range 分区。因此实施采用：

- `outbox_events`：按 `event_id` Hash 分区，数据库维持 `event_id` 全局唯一。
- `inbox_messages`：按 `(consumer_id,event_id)` Hash 分区，数据库维持消费幂等唯一。
- `access_token_records`：按 `jti` Hash 分区，数据库维持 JTI 全局唯一。
- `audit_events`、`authorization_decisions`、`risk_signals`、`webhook_deliveries`、`message_requests`：分别按全局事件、决策、信号、投递和请求 ID Hash 分区。
- `authentication_attempts`、`workload_attestations`、`webhook_delivery_attempts`、`message_delivery_attempts`、`migration_change_logs`：按时间月度 Range 分区。

Hash 分区表的时间保留通过时间索引和受控批量归档完成；该策略只保护持久化唯一性，不解释业务状态。

## 版本支持

- PostgreSQL 15 及以上，使用 `UNIQUE NULLS NOT DISTINCT`。
- UUID 由应用生成，推荐 UUIDv7。
- Seed 使用 PostgreSQL 内置 `sha256(bytea)` 计算内容摘要，不依赖扩展；同键内容漂移直接失败，控制面对象默认 DRAFT。

## 发布门禁

1. 空数据库按文件名顺序执行全部 Migration 和 Seed。
2. 执行全部 Verification，任一异常阻断发布。
3. 执行生成脚本，确认数据库需求覆盖编号、117/117 业务模型与领域持久化范围映射、全部多领域复用表权威、完整逻辑关系和数据库报告全部更新。
4. 进入编码阶段后，按单独的代码实施文档执行状态机属性测试、逻辑引用负向测试、租户隔离测试和敏感日志扫描。
5. 检查未来 12 个月以上分区、默认分区积压、孤儿关系、Outbox 积压和安全水位传播。
6. 保存 Schema 快照、验证输出和迁移校验和作为发布证据。
