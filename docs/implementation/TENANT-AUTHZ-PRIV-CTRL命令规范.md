# TENANT、AUTHZ、PRIV 与 CTRL 命令规范

## 1. 创建和结束 Membership

- 创建前校验 User、Business Line、Tenant、Organization 的作用域链和主体生命周期。
- 插入新 Membership 时占用 `current_occupancy_slot=1`；数据库保证同一作用域和用户只有一个当前占位。
- 离开时 CAS 设置终态、`left_at` 和 `current_occupancy_slot=NULL`，保留历史 Membership ID。
- 重新加入必须创建新 Membership，不得复活或改写历史行。
- Membership 状态不能替代全局用户、租户和安全冻结状态，访问决策取最严格结果。

## 2. 接受邀请

- 校验邀请未过期、未消费、目标摘要匹配、邀请者仍有效、角色上界和租户作用域有效。
- 同事务原子消费邀请并创建 Membership/角色授予；写 Outbox、Audit 和幂等结果。
- 并发接受只能一个成功；已消费和不存在对外使用防枚举响应。

## 3. 授予和撤销角色

- 校验角色 Owner、Scope、被授予主体、职责分离、权限上界和审批要求。
- 角色、权限目录键不可更新；关系变化通过新增 assignment/role_permission 和填写失效时间表达。
- 同事务写授权事实、必要安全水位、Outbox 和 Audit。
- 数据库 FK 只校验 Role/Permission/User/Group/Machine 存在，不计算授权结果。

## 4. 发布 Policy 或 Configuration

- 内容版本在 DRAFT 创建后不可原地改写；语义校验、静态分析和审批在代码中完成。
- 发布命令 CAS 更新版本生命周期元数据，创建不可变 Release/Release Item，并更新目标对象当前配置指针。
- 激活前校验审批、环境、Schema、依赖版本和回滚目标；数据库不自动选择配置。
- 回滚创建新的发布事实或切换到已存在版本，不篡改历史内容。

## 5. 授予与撤回 Consent

- 校验主体、目的、类别、接收方、地区、协议版本和合法依据。
- 授予时追加 `consents`，CAS 更新 `consent_aggregates.current_consent_id/consent_epoch`。
- 撤回时追加撤回事实并递增 epoch；触发 Grant、Token、订阅和下游处理联动事件。
- 数据库唯一键确定 Consent 聚合，不判断是否应展示或允许同意。

## 6. 隐私请求

- 创建时完成身份核验、请求类型和适用地区判断，创建 `privacy_requests + operation_steps`。
- 每个外部系统处理步骤保存检查点、结果和删除/保留证据；Legal Hold 阻断进入明确状态。
- 越过删除不可逆点前重新校验撤回、审批和 Hold；完成后追加 `deletion_proofs`。
- 数据库不自动删除业务数据，也不通过级联删除执行隐私流程。

## 7. 审批与单次执行

- 审批 Case 固化请求摘要、资源版本、策略版本和所需票数。
- 审批动作只追加；代码校验审批人资格、职责分离、法定人数和过期时间。
- 达到条件后原子占用唯一 `execution_id`，只有一个执行者可推进目标命令。
- 执行失败记录稳定错误和 Operation，禁止重复产生不可逆副作用。
