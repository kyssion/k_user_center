# ID、AUTH、OAP 与 SESSION 命令规范

## 1. 创建用户 `CreateGlobalUser`

- 代码前置：校验调用者创建权限、用户类型、初始生命周期/锁定/冻结组合和 Guest 到期规则；生成内部 UUIDv7 与公开高熵 ID。
- 事务：插入 `global_users`、幂等结果、Outbox 和 Audit。
- 数据库边界：公开 ID 唯一、非负水位和版本；不判断调用者权限或用户类型是否合法。
- 失败：公开 ID 冲突视为生成器或重放异常，不把已存在用户返回给调用者。

## 2. 分配与轮换 Subject `AllocateSubject` / `RotateSubject`

- 代码前置：User 与 Client 存在且状态允许；调用者具备 Client 作用域；Subject 类型和生成算法版本有效。
- 首次分配：插入 `user_subjects`，`current_subject_slot=1`。
- 轮换事务：锁定当前映射并校验 expected `row_version`；将旧行写入 `retired_at`、`current_subject_slot=NULL` 并递增版本；插入全新的 Subject 行；写 Outbox/Audit 后提交。
- 数据库边界：同 User/Client 最多一个当前占位，同 Client 下历史 Subject 永久唯一；数据库不校验 User/Client 引用与状态。
- 代码规则：是否允许轮换、兼容窗口、通知、旧 Token 处理和对外映射范围。

## 3. 标识占用、绑定与解绑 `ClaimIdentifier` / `BindIdentifier` / `UnbindIdentifier`

- 参数校验：按版本规范化标识，计算盲索引，校验标识类型、作用域和可恢复密文元数据；不得记录明文。
- 代码前置：User、Tenant/Business Line、Identifier 和所有逻辑引用存在且有效；完成高风险 Step-up、最后凭证保护、隔离期和回收标识防继承判断。
- 事务：竞争 `identifier_claims` 唯一占用；追加或终止 `identifier_bindings`；必要时更新 `user_identities`；写 Outbox、Audit 和幂等结果。
- 数据库边界：作用域、类型和盲索引唯一；不判断归属、租户一致性、释放资格或隔离期。
- 禁止：物理删除 Identifier、Claim 或绑定历史；重新分配前必须保留旧绑定墓碑。

## 4. 链接外部身份 `LinkExternalIdentity`

- OIDC 使用 `issuer + sub`，SAML 使用完整稳定键元组；不得只凭 email 合并。
- 代码校验 Provider、User、Tenant、协议断言、保证等级和防接管规则。
- 事务插入 `user_identities`，必要时创建冲突处理 Operation，并写 Outbox/Audit。
- 数据库只保证已声明的唯一和基础目标形状，不替代码确认 Provider/User 引用或授权。

## 5. 登记与轮换认证材料 `RegisterAuthenticator` / `RotateCredential`

- 代码校验认证/恢复权限、算法 Allowlist、参数强度、材料类型和 Key 状态；秘密只以哈希、密文或公钥落库。
- 事务插入 `authenticators` 与新的 `credential_materials` 版本；旧材料只更新退役元数据，不原地改写秘密。
- Passkey 使用计数以 expected `row_version` 做 CAS；代码显式递增版本和刷新 `updated_at`，计数倒退或异常由 AUTH/RISK 判断。
- 密码历史、认证尝试和认证上下文为追加事实；运行时无 DELETE。

## 6. 创建和消费 Challenge `IssueChallenge` / `ConsumeChallenge`

- 创建时校验目的、目标、上下文 Schema、TTL 和最大尝试策略，只保存 Token 摘要。需要异步投递时，秘密原值写入独立短期秘密存储，IAM 数据库只在消息请求中保存非承载型句柄和失效时间。
- 消费时在代码中校验摘要、上下文绑定、主体/Client/Tenant、状态、过期时间和尝试上限。
- 使用单条条件 UPDATE 匹配 expected version；成功时设置终态与 `consumed_at`，失败和成功都按命令契约记录尝试。
- 未知、过期和已使用 Token 对外使用防枚举响应；数据库 Check 仅兜底非负计数和基础时间形状。

## 7. 完成登录 `CompleteLoginTransaction`

- 代码确认 Client、精确 Redirect、原请求摘要、所需步骤、AAL/ACR、风险、Consent 和策略版本全部满足。
- 事务 CAS 完成 `login_transactions`，追加 `authentication_contexts`，创建 Session、授权码和参与 RP 事实，并写 Outbox/Audit/幂等结果。
- 数据库不根据步骤记录自动判断登录是否完成，也不决定是否可以签发授权码。

## 8. 消费授权码 `RedeemAuthorizationCode`

- 代码校验 Code 摘要、Client、Redirect、PKCE、Scope、登录事务、过期时间和协议错误映射。
- 条件 UPDATE 保证同一授权码只有一个竞争者从可用态进入已消费态。
- 同事务创建或激活 Grant、Token Family、首个 Refresh Token 实例和 Access Token 元数据，并写 Outbox/Audit。
- 重放统一返回 `invalid_grant`，并按安全 Profile 产生风险信号。

## 9. Refresh Token 轮换 `RotateRefreshToken`

- 代码校验 Family、Client、User、Device/持有证明、安全水位、摘要和状态。
- 事务锁定或 CAS 当前实例；旧实例写 `used_at/replaced_by_id`，插入序号递增的新实例，更新 Family 当前指针并写 Token 元数据、Outbox/Audit。
- 数据库裁决 Token 摘要和 Family 内序号唯一；逻辑引用、重试窗口、恶意重放和家族撤销由代码判断。

## 10. 撤销会话或安全水位 `RevokeSession`

- 代码确认操作者对 Session/User/Client/Tenant 的权限与数据范围，并计算撤销范围。
- 事务 CAS 更新 Session 状态和 `revoked_at`，递增适用安全水位，追加 `revocation_entries`、Outbox 和 Audit。
- 数据库只保存撤销事实和水位，不扫描 Token、不计算授权，也不物理删除会话。
