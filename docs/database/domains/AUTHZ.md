# AUTHZ：授权与策略

- 持久化范围：`permissions`、`roles`、`role_permissions`、`user_role_assignments`、`group_role_assignments`、`machine_role_assignments`、`data_scope_definitions`、`policy_versions`、`policy_bindings`、`authorization_decisions`、`relationship_tuples`。
- 业务模型边界：`Role`、`Assignment`、`PolicyVersion/Binding`、关系元组；决策为不可变证据。
- 业务模型要求：持久化模型必须支持默认拒绝、作用域包含、最小权限、职责分离、Subject/Actor/委托、PDP/PIP、属性版本与新鲜度、决策有效期、列表查询前过滤、缓存水位和 Obligation。
- 禁止：数据库 View 表达“有效授权”；前端、数据库账号/角色或 RLS/Policy 作为业务授权的权威/唯一 PEP；受保护仓储在缺少可信授权上下文时继续读写；依赖过期缓存继续高风险放行。
- 事件：角色/权限/策略/关系变化和安全水位推进。
- 门禁：`AT-AUTHZ-*`、`AT-FAIL-001`、租户隔离、领域 Owner 越权、受保护数据访问绕过、追加/不可变历史篡改和撤销时效测试；改变 Actor、风险、资源版本、PIP 版本或 Consent Epoch 不得命中旧允许缓存。
