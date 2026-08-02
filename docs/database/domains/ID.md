# ID：身份主体与标识

- 存储：`global_users`、`user_subjects`、`identifiers`、`identifier_claims`、`identifier_bindings`、`user_identities`、`user_aliases`。
- 聚合：`GlobalUser`、`IdentifierClaim`、`ExternalIdentityLink`、账号合并 `Operation`。
- 代码规则：UUID/公开 ID 不复用；正式/Guest 类型与到期升级；生命周期、认证锁定、安全冻结正交；版本化规范化；标识并发唯一占用；解绑隔离；合并补偿；匿名化终态。
- 事务：主体/标识事实、唯一占用、Outbox、Audit、幂等同事务提交。
- 事件：用户创建/冻结/恢复/终态，标识验证/绑定/解绑，身份链接/解绑，账号合并。
- 门禁：`AT-ID-*`、`INV-G-001~005/009/013`；同标识双绑定、Guest 到期继续签发、锁定/冻结维度互相覆盖、旧 UID 复用和匿名化恢复必须失败。
