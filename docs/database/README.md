# 数据库实施导航

数据库实施以 [数据库设计总纲](../数据库设计总纲.md) 为基线，以 `database/postgresql` 下的 SQL 为可执行权威来源。

## 交付物

| 位置 | 用途 |
|---|---|
| `database/postgresql/bootstrap` | 数据库角色和数据库级最小权限 |
| `database/postgresql/migrations` | 113 张表、约束、索引、分区和运行时权限 |
| `database/postgresql/seeds` | 经批准的稳定系统配置，不创建用户、租户、Client 或秘密 |
| `database/postgresql/verification` | Schema、Comment、禁止对象、敏感字段、孤儿关系和权限门禁 |
| `.NET业务规则与状态机实现清单.md` | 后续 C# 聚合、命令、状态机、事务和测试实现索引 |
| `逻辑关系与代码校验清单.md` | 无 Foreign Key 时的代码校验契约 |
| `需求能力表测试追踪矩阵.md` | 能力地图/蓝图到存储、代码和证据的映射 |
| `domains/*.md` | 21 个能力域的代码实现边界 |
| `generated/*.md` | 从 SQL 或数据库目录生成的只读报告 |

## 设计边界

- 数据库：存储事实、PK/Unique、基础 Check、技术默认时间、CAS 字段、索引、分区和权限。
- .NET：引用存在性、租户一致性、状态转换、权限、风险、审批、加密、协议、幂等语义、流程和删除编排。
- 不创建 Foreign Key、业务 Trigger、持久化业务 Routine、PostgreSQL Enum 和业务 View。
- 所有重要写入必须将权威数据、Outbox、审计事件和幂等结果放在同一应用事务中。

## 分区实现说明

总纲要求高容量表按月分区，同时要求 Outbox `event_id` 和 Inbox `(consumer_id,event_id)` 在数据库全局唯一。PostgreSQL Range 分区的唯一约束必须包含分区键，无法同时满足这两项。因此实施采用：

- `outbox_events`：按 `event_id` Hash 分区，数据库维持 `event_id` 全局唯一。
- `inbox_messages`：按 `(consumer_id,event_id)` Hash 分区，数据库维持消费幂等唯一。
- 其余 11 张高容量表：按时间月度 Range 分区。

该修正只改变物理分区方式，不改变业务契约。Outbox/Inbox 的时间保留通过 `recorded_at/received_at` 索引和运维归档完成。

## 版本支持

- PostgreSQL 15 及以上，使用 `UNIQUE NULLS NOT DISTINCT`。
- UUID 由应用生成，推荐 UUIDv7。
- Seed 使用 PostgreSQL 内置 `sha256(bytea)` 计算配置摘要，不依赖扩展。

## 发布门禁

1. 空数据库按文件名顺序执行全部 Migration 和 Seed。
2. 执行全部 Verification，任一异常阻断发布。
3. 执行 .NET 状态机属性测试、逻辑引用负向测试、租户隔离测试和敏感日志扫描。
4. 检查未来 12 个月以上分区、默认分区积压、孤儿关系、Outbox 积压和安全水位传播。
5. 保存 Schema 快照、验证输出和迁移校验和作为发布证据。

