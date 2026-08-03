# ASR：保证、恢复、委托与代理

- 持久化范围：`authentication_contexts`、`identity_assurance_assertions`、`authenticators`、`recovery_code_batches`、`recovery_codes`、`delegations`、`approval_*`。
- 业务模型边界：`AssuranceContext`、恢复 `Operation`、`Delegation`、`ApprovalCase`。
- 权威边界：ASR 持有保证等级规则和 `delegations`；`identity_assurance_assertions` 由 PROFILE 持有，认证上下文、认证器与恢复码由 AUTH 持有，审批单与审批动作由 CTRL 持有，恢复 Operation 遵守 OPS 的实例唯一 Owner 规则。
- 业务模型要求：持久化模型必须支持恢复不降低保证等级、认证器替换风险保护、Actor/Subject 分离、委托权限交集/链深/撤销和未成年人或代理规则；审批执行必须绑定唯一 `execution_id`。
- 禁止：同步型 Passkey 误评 AAL3；找回绕过 MFA；代理扩权；发起人自审。
- 事件：恢复进度、认证器替换、委托生效/撤销和审批结果。
- 门禁：`CAP-ASR-*`、`AT-AUTH-004~007/015`、`AT-ASR-*`、`AT-MACHINE-004`；同一审批并发执行只能成功一次。
