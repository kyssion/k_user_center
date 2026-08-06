# TENANT、AUTHZ、PRIV 与 CTRL 命令规范

## 1. 创建、结束和重新加入 Membership

- 代码校验 User、Business Line、Tenant、Organization 的逻辑引用、作用域链、主体生命周期和操作者权限。
- 创建新 Membership 时写 `current_occupancy_slot=1`；数据库只保证同一作用域和用户最多一个当前占位。
- 离开时 CAS 写入终态、`left_at` 和 `current_occupancy_slot=NULL`；何时允许离开由 TENANT 状态机判断。
- `LEFT/REJECTED/EXPIRED` 后重新加入必须创建新 Membership，不得复活或改写历史记录。
- 访问决策必须同时评估全局用户、租户、Membership、限制和安全冻结，取最严格结果。

## 2. 接受邀请

- 代码校验邀请摘要、过期时间、消费状态、邀请者状态、目标匹配、角色上界和租户作用域。
- 同事务条件消费邀请，创建 Membership/角色授予，并写 Outbox、Audit 和幂等结果。
- 并发接受只能一个成功；不存在、过期和已消费对外使用防枚举响应。

## 3. 授予和撤销角色

- 代码校验角色 Owner、Scope、受授主体、权限上界、职责分离、审批和调用者数据范围。
- 角色与权限目录键不可更新；关系变化通过新增 assignment/role_permission 和填写失效时间表达。
- 同事务写授权事实、必要安全水位、Outbox 和 Audit。
- 数据库唯一性只防止声明的重复事实，不计算用户有效权限；角色变更影响面使用查询契约反向定位。

## 4. 发布 Policy 或 Configuration

- DRAFT 内容的 JSON Schema、静态分析、依赖、环境、Owner 和审批在代码中校验；数据库不解析载荷。
- 发布命令 CAS 更新生命周期元数据，创建不可变 Release/Release Item，并更新目标对象当前配置指针。
- 回滚创建新的发布事实或切换到已存在版本，不篡改历史内容。
- 策略版本影响面通过 Session、Token、Operation 和授权决策的数组 GIN 查询获取，查询结果仍须按作用域过滤。

## 5. 授予与撤回 Consent

- 代码校验主体、目的、类别、接收方、地区、协议版本、合法依据和操作者权限。
- 授予时追加 `consents`，CAS 更新 `consent_aggregates.current_consent_id/consent_epoch`。
- 撤回时追加撤回事实并递增 epoch，发布 Grant、Token、会话、订阅和下游处理联动事件。
- 数据库唯一键只定位 Consent 聚合，不判断是否允许展示、同意或撤回。

## 6. 隐私请求

- 创建时在代码中完成身份核验、请求类型、地区、数据范围和权限判断，创建 `privacy_requests + operation_steps`。
- 外部系统步骤保存检查点、结果和删除/保留证据；Legal Hold 使流程进入明确阻断状态。
- 越过匿名化或删除不可逆点前重新校验撤回、审批、保留期和 Hold；完成后追加 `deletion_proofs`。
- 运行时身份无 DELETE；物理清理只能由受审批维护流程执行，不能依赖级联或数据库 Trigger。

## 7. 审批与单次执行

- 审批 Case 固化请求摘要、资源版本、策略版本、作用域和所需票数。
- 审批动作只追加；代码校验审批人资格、职责分离、法定人数、过期时间和目标是否仍为原版本。
- 达到条件后原子占用唯一 `execution_id`，只有一个执行者推进目标命令。
- 执行失败记录稳定错误和 Operation，禁止重复产生不可逆副作用。
