# AUTHZ：授权与策略

- 持久化范围：`permissions`、`roles`、`role_permissions`、`user_role_assignments`、`group_role_assignments`、`machine_role_assignments`、`data_scope_definitions`、`policy_versions`、`policy_bindings`、`authorization_decisions`、`relationship_tuples`。
- 业务模型边界：`Role`、`Assignment`、`PolicyVersion/Binding`、关系元组；决策为不可变证据。
- 业务模型要求：持久化模型必须支持默认拒绝、作用域包含、最小权限、职责分离、Subject/Actor/委托、PDP/PIP、属性版本与新鲜度、决策有效期、列表查询前过滤、缓存水位和 Obligation。
- 禁止：数据库 View 表达“有效授权”；前端作为可信 PEP；依赖过期缓存继续高风险放行。
- 事件：角色/权限/策略/关系变化和安全水位推进。
- 门禁：`AT-AUTHZ-*`、`AT-FAIL-001`、租户隔离和撤销时效测试；改变 Actor、风险、资源版本、PIP 版本或 Consent Epoch 不得命中旧允许缓存。
