# ASR：保证、恢复、委托与代理

- 存储：`authentication_contexts`、`identity_assurance_assertions`、`authenticators`、`recovery_code_*`、`delegations`、`approval_*`。
- 聚合：`AssuranceContext`、恢复 `Operation`、`Delegation`、`ApprovalCase`。
- 代码规则：恢复不得降低保证等级；认证器替换风险保护；Actor/Subject 分离；委托权限交集、链深、撤销和未成年人/代理规则。
- 禁止：同步型 Passkey 误评 AAL3；找回绕过 MFA；代理扩权；发起人自审。
- 事件：恢复进度、认证器替换、委托生效/撤销和审批结果。
- 门禁：`CAP-ASR-*`、`AT-AUTH-004~007/015`、`AT-ASR-*`、`AT-MACHINE-004`。

