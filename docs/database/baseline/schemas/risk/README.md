# risk Schema

风险信号、评估、处置、案件、拒绝名单与策略版本。

## 文件

- `tables.sql`：本 Schema 的全部基表、同 Schema 约束、索引和对象注释。
- `routines.sql`：本 Schema 的函数、过程、局部触发器和对象注释。
- `security.sql`：本 Schema 的对象级授权、敏感对象排除和函数 PUBLIC 权限收敛。
- `build.sql`：只构建本 Schema 局部对象，不执行跨 Schema 绑定。
- `links.sql`：本 Schema 源表拥有的跨 Schema 外键、绑定和支撑索引。

## 表清单（5）

- `risk.risk_policy_release`
- `risk.risk_signal`
- `risk.risk_assessment`
- `risk.security_case`
- `risk.denylist_entry`

## 依赖与执行

- 前置：先执行 `../../bootstrap.sql` 和 `../core/build.sql`；本模块依赖 core 公共表与共享例程。
- 局部构建：在本目录执行 `psql --file build.sql`。
- 对象权限：完成全库对象和 `../../roles.sql` 后，在本目录执行 `psql --file security.sql`。
- 跨域依赖：`control`、`org`、`privacy`；所有 Schema 的 `build.sql` 完成后再执行本模块 `links.sql`。

## 数据库与 .NET 边界

- 数据库负责：类型、非空、主键/唯一性、同域与跨域引用、查询索引、不可变证据、终态保护及令牌/验证码等关键原子安全底线。
- .NET 10 领域层负责：完整状态机、调用上下文匹配、权限与租户上下文校验、策略组合、JSON Schema、外部协议与错误映射。
- SqlSugar 映射、事务和并发约定见 [SqlSugar 接入约定](../../../SqlSugar接入约定.md)，业务规则见 [.NET 业务规则清单](../../../.NET业务规则与状态机实现清单.md)。
