# ID、AUTH、OAP 与 SESSION 命令规范

## 1. 创建用户 `CreateGlobalUser`

- 前置：调用方具备创建主体权限；公开 UID、内部 UUID 由应用生成；Guest 必须提供到期时间。
- 事务：插入 `global_users`、必要的 `idempotency_records`、Outbox 和 Audit。
- 数据库裁决：`global_user_id` 唯一、版本和安全水位非负。
- 代码规则：用户类型、初始生命周期/锁定/冻结组合及 Guest Profile。
- 失败：UID 冲突视为生成器或重放异常，不改用已存在用户。
- 事件：`UserCreated`，包含公开 UID 类型但不包含 Identifier 明文。

## 2. 分配与轮换 Subject `AllocateSubject` / `RotateSubject`

- 前置：User 与 Client 存在且可发布 Subject；调用方具备该 Client 作用域；生成算法版本有效。
- 首次分配：插入 `user_subjects`，`current_subject_slot=1`。
- 轮换事务：
  1. 读取当前行并校验 expected `row_version`。
  2. 将旧行 `current_subject_slot=NULL`、写入 `retired_at`、递增 `row_version`。
  3. 插入全新 `id/subject_id` 的当前行，禁止更新旧 `subject_id`。
  4. 写 Outbox 和 Audit 后提交。
- 数据库裁决：同 User/Client 最多一个当前占位；同 Client 下历史 Subject 永久唯一；User/Client 引用存在。
- 代码规则：是否允许轮换、通知、Token/事件中何时切换以及旧 Token 的兼容窗口。
- 并发：任一步唯一冲突或 CAS 失败时整笔回滚并重读，不产生两个当前 Subject。
- 事件：`SubjectRotated` 只向受信任内部消费者发布旧/新映射；外部事件仅使用接收方当前 pairwise Subject。

## 3. 标识占用与绑定 `ClaimIdentifier` / `BindIdentifier`

- 前置：完成版本化规范化、盲索引计算和必要验证；作用域及 Identifier 类型已确定。
- 事务：插入或更新 `identifiers`；竞争 `identifier_claims` 唯一占用；追加 `identifier_bindings`；写 Outbox/Audit/幂等结果。
- 重新分配：只有 Claim 已完成释放和隔离期后，才允许更新当前占用的 `identifier_id/owner_user_id/claimed_at`；历史绑定记录不得改写或删除。
- 数据库裁决：作用域、类型和盲索引唯一；Identifier/User 引用存在。
- 代码规则：规范化、验证、隔离期、回收标识防继承、Tenant 一致性和高风险 Step-up。
- 失败：唯一冲突返回 `409 IDENTITY_ALREADY_BOUND`，不得返回占用用户。

## 4. 解绑标识 `UnbindIdentifier`

- 前置：目标绑定属于当前用户；解绑后仍满足最后登录凭证和恢复能力保护；高风险场景完成 Step-up。
- 事务：CAS 更新 `identifier_bindings.binding_state/unbound_at`；更新 Claim 的释放和隔离时间；必要时停用 `user_identities`；写撤销、Outbox 和 Audit。
- 禁止：直接删除 Identifier、Claim 或绑定历史；数据库不根据时间自动释放占用。

## 5. 链接外部身份 `LinkExternalIdentity`

- 前置：OIDC 使用 `issuer + sub`，SAML 使用完整稳定键元组；不得只凭 email 合并；Provider、User 和租户范围有效。
- 事务：插入 `user_identities`，外部键摘要唯一；必要时创建 Operation 处理账号冲突。
- 数据库裁决：本地身份和联合身份目标形状互斥；Provider/User 引用存在；外部稳定键唯一。
- 代码规则：协议验证、防接管、保证等级和冲突处置。

## 6. 登记或轮换认证器 `RegisterAuthenticator` / `RotateCredential`

- 前置：完成认证或恢复授权；算法、参数和材料类型通过 Allowlist；秘密只以哈希、密文或公钥落库。
- 事务：插入 `authenticators` 与新的 `credential_materials` 版本；旧材料只更新 `retired_at`，不得改写秘密、算法或公钥；写 Outbox/Audit。
- Passkey 使用计数：仅 CAS 更新 `usage_counter` 和 `row_version`，发现倒退或异常由 AUTH/RISK 代码判断。
- 密码历史、认证尝试和认证上下文为追加事实。

## 7. 创建和消费 Challenge `IssueChallenge` / `ConsumeChallenge`

- 创建：保存 Token 摘要、最大尝试、版本化上下文和过期时间；不得保存验证码明文。
- 消费条件：Token 摘要匹配、上下文绑定正确、未消费、未过期、尝试次数未超限。
- 原子更新：匹配 expected `row_version`，递增尝试次数；成功时同时设置终态与 `consumed_at`。
- 失败：未知和已使用 Token 使用一致外部响应，防止枚举；数据库 Check 只保证计数范围和时间形状。

## 8. 完成登录 `CompleteLoginTransaction`

- 前置：Client、Redirect、原请求摘要、所需步骤、AAL/ACR、风险和 Consent 全部满足。
- 事务：CAS 完成 `login_transactions`；追加 `authentication_contexts`；创建 Session、授权码及参与 RP 事实；写 Outbox/Audit/幂等结果。
- 禁止：未完成步骤时签发授权码；数据库不判断登录流程是否完成。

## 9. 消费授权码 `RedeemAuthorizationCode`

- 前置：Code 摘要、Client、精确 Redirect、PKCE、Scope 和原登录事务匹配，且未过期。
- 原子更新：仅一方可把 Code 从可用态更新为已消费并写入 `consumed_at`。
- 同事务：创建/激活 Grant、Token Family、首个 Refresh Token 实例和 Access Token 记录，写 Outbox/Audit。
- 重放：统一返回协议 `invalid_grant`，并按 Profile 产生风险信号。

## 10. Refresh Token 轮换 `RotateRefreshToken`

- 前置：Family、Client、User、Device/持有证明、安全水位和 Token 摘要匹配。
- 事务：锁定或 CAS 更新当前实例；旧实例写 `used_at/replaced_by_id`；插入序号递增的新实例；更新 Family 当前指针和版本；写新 Token 记录、Outbox/Audit。
- 数据库裁决：Token 摘要、Family 序号和当前指针关系唯一；引用存在。
- 代码规则：网络丢包重试窗口、恶意重放识别、家族级撤销和 Profile 差异。
- 并发：只有一个竞争者创建后继实例；其余返回 `invalid_grant` 或命中受控重试结果。

## 11. 撤销会话或安全水位 `RevokeSession`

- 前置：操作者对目标 Session/User/Client/Tenant 有权；撤销范围由业务命令明确。
- 事务：CAS 更新 Session 状态与 `revoked_at`，递增适用安全水位，追加 `revocation_entries`，写 Outbox/Audit。
- 代码规则：传播范围、RP Logout、Token Family 和 Access Token 影响、失败关闭及撤销 SLO。
- 数据库只保存撤销事实和水位，不主动扫描或使 Token 失效。
