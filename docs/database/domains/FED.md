# FED：身份联合与企业目录

- 存储：`identity_providers`、`directory_connectors`、`directory_sync_cursors`、`directory_sync_batches`、`directory_object_mappings`、`user_identities`。
- 聚合：`IdentityProvider`、`DirectoryConnector`、同步 `Operation/Batch`。
- 业务模型要求：持久化模型必须支持 OIDC `issuer+sub`、SAML 完整限定元组、禁止仅凭邮箱合并、路由和属性映射版本化以及 SCIM/API 游标、ETag、墓碑和冲突。
- 秘密：Client Secret、第三方 Token 和私钥只存 KMS/Vault；数据库保存配置/Key 引用。
- 事件：身份链接、目录对象创建/更新/墓碑、同步批次结果。
- 门禁：`AT-FED-*`、协议负向测试、旧版本覆盖和跨租户目录映射测试。
