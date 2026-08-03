# 数据库实施导航

数据库实施以 [数据库设计总纲](../数据库设计总纲.md) 为候选基线，以 `database/postgresql` 下的 SQL 为可执行权威来源；算法与密码合规开放项关闭并完成真实 PostgreSQL 验证后，方可标记为最终冻结基线。

本目录只描述业务模型是否能被数据库事实完整表达、哪些关系需要持久化以及 PostgreSQL 应承担哪些硬边界。代码目录、类、接口、Handler、Repository、API DTO 和外部组件调用顺序不在本目录定义；进入编码阶段后另行生成代码实施文档。

## 交付物

| 位置 | 用途 |
|---|---|
| `database/postgresql/bootstrap` | 数据库角色和数据库级最小权限 |
| `database/postgresql/migrations` | 113 张表、约束、索引、分区和运行时权限 |
| `database/postgresql/seeds` | 稳定目录和 DRAFT 控制面候选版本，不创建用户、租户、Client 或秘密 |
| `database/postgresql/verification` | Schema、Comment、禁止对象、敏感字段、全部可解析逻辑关系、Seed 和权限门禁 |
| `业务模型与持久化边界清单.md` | 业务模型、持久化事实、数据库硬边界和非数据库职责索引 |
| `逻辑关系与非数据库校验清单.md` | 无 Foreign Key 时的逻辑引用登记和非数据库校验提示 |
| `需求编号与数据库持久化覆盖索引.md` | 能力地图/蓝图编号到数据库持久化边界的覆盖索引；不是代码实施或验收矩阵 |
| `domains/*.md` | 21 个能力域的业务模型、持久化边界和明确非数据库职责 |
| `generated/*.md` | 从 SQL 或数据库目录生成的只读报告 |

## 设计边界

- 数据库：存储事实、PK/Unique、基础 Check、技术默认时间、CAS 字段、索引、分区和权限。
- 非数据库职责：引用存在性、租户一致性、状态转换、业务授权求值、风险、审批、加密、协议、幂等语义、流程和删除编排；具体实现以后续代码实施文档为准。
- 数据权威：每张逻辑表映射到一个主要业务模型和权威域；多域复用按 `业务模型与持久化边界清单.md` 的共享表权威执行，不得形成未声明双写或影子状态。
- 不创建 Foreign Key、业务 Trigger、持久化业务 Routine、PostgreSQL Enum 和业务 View。
- 所有重要写入必须将权威数据、Outbox、审计事件和幂等结果放在同一应用事务中。

## 分区实现说明

总纲要求高容量表按月分区，同时要求 Outbox `event_id`、Inbox `(consumer_id,event_id)` 和 Access Token `jti` 在数据库全局唯一。PostgreSQL Range 分区的唯一约束必须包含分区键，无法同时满足这些全局唯一性。因此实施采用：

- `outbox_events`：按 `event_id` Hash 分区，数据库维持 `event_id` 全局唯一。
- `inbox_messages`：按 `(consumer_id,event_id)` Hash 分区，数据库维持消费幂等唯一。
- `access_token_records`：按 `jti` Hash 分区，数据库维持 JTI 全局唯一。
- 其余 10 张高容量表：按时间月度 Range 分区。

该修正只改变物理分区方式，不改变业务契约。三张 Hash 分区表的时间保留通过时间索引和受控运维归档完成。

## 版本支持

- PostgreSQL 15 及以上，使用 `UNIQUE NULLS NOT DISTINCT`。
- UUID 由应用生成，推荐 UUIDv7。
- Seed 使用 PostgreSQL 内置 `sha256(bytea)` 计算内容摘要，不依赖扩展；同键内容漂移直接失败，控制面对象默认 DRAFT。

## 发布门禁

1. 空数据库按文件名顺序执行全部 Migration 和 Seed。
2. 执行全部 Verification，任一异常阻断发布。
3. 执行生成脚本，确认 718 个数据库需求覆盖编号、113/113 业务模型与领域持久化范围映射、全部多领域复用表权威、完整逻辑关系和数据库报告全部更新。
4. 进入编码阶段后，按单独的代码实施文档执行状态机属性测试、逻辑引用负向测试、租户隔离测试和敏感日志扫描。
5. 检查未来 12 个月以上分区、默认分区积压、孤儿关系、Outbox 积压和安全水位传播。
6. 保存 Schema 快照、验证输出和迁移校验和作为发布证据。
