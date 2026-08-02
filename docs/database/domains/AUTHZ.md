# AUTHZ：授权与策略

- 存储：`permissions`、`roles`、`role_permissions`、三类 Assignment、`data_scope_definitions`、`policy_versions`、`policy_bindings`、`authorization_decisions`、`relationship_tuples`。
- 聚合：`Role`、`Assignment`、`PolicyVersion/Binding`、关系元组；决策为不可变证据。
- 代码规则：默认拒绝、作用域包含、最小权限、职责分离、PDP/PIP、列表查询前过滤、缓存水位和 Obligation。
- 禁止：数据库 View 表达“有效授权”；前端作为可信 PEP；依赖过期缓存继续高风险放行。
- 事件：角色/权限/策略/关系变化和安全水位推进。
- 门禁：`AT-AUTHZ-*`、`AT-FAIL-001`、租户隔离和撤销时效测试。

