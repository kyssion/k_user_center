# AUTH：认证器与认证

- 持久化范围：`authenticators`、`credential_materials`、`password_history`、`recovery_code_batches`、`recovery_codes`、`auth_challenges`、`login_transaction*`、`authentication_contexts`、`authentication_attempts`。
- 业务模型边界：`Authenticator`、`Challenge`、`LoginTransaction`、`AuthenticationContext`。
- 权威边界：AUTH 持有认证器、认证材料、恢复码、Challenge、登录事务、认证上下文和尝试事实；ASR/SSC 只能通过受控命令使用这些事实，不得直接改写凭证生命周期。
- 业务模型要求：持久化模型必须为算法 Allowlist、密码自适应哈希、Challenge 单次消费、尝试限制、防枚举、MFA/Passkey、AAL 计算和风险 Step-up 保存所需事实与版本。
- 禁止：密码/验证码/TOTP 原文落库或进入日志、事件；冻结用户登记认证器；未完成 Login Transaction 签发。
- 事件：认证器登记/替换/撤销、认证成功/失败安全事件、登录事务完成。
- 门禁：`AT-AUTH-*`、`INV-G-007/013/016`，包含并发消费和保证等级决策表。
