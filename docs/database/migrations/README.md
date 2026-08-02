# 后续增量迁移

本目录不保存空库基线。空库结构以 `../baseline/` 为唯一来源。

上线后新增变更采用版本优先目录：

```text
YYYYMMDD_NNN_change_name/
├─ README.md
├─ up.sql
└─ verify.sql
```

要求：

- 目录版本全局唯一且只增不改。
- `README.md` 说明受影响 Schema、锁与停机风险、数据回填、.NET 兼容窗口、COMMENT 变化和验收条件。
- `up.sql` 只包含本次增量，跨 Schema 约束仍归属被修改的源表 Schema。
- 新增或修改 Database、Schema、Table、View、Column、Index、Constraint、Trigger、Routine、Role、Policy 等对象时，同一迁移必须维护对应 COMMENT。
- `verify.sql` 只验收本次变更，并由全局基线验收补充回归。
- 当前未上线阶段不设计回滚脚本；基线问题通过修正 `baseline/` 后重建空库解决。

