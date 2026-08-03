# FED：身份联合与企业目录

- 持久化范围：`identity_providers`、`directory_connectors`、`directory_sync_cursors`、`directory_sync_batches`、`directory_object_mappings`、`user_identities`、`legacy_systems`、`legacy_id_mappings`、`migration_batches`、`migration_items`、`migration_change_logs`。
- 业务模型边界：`IdentityProvider`、`DirectoryConnector`、同步 `Operation/Batch`、存量身份源与凭证迁移 `MigrationSystem/Batch`。
- 权威边界：FED 持有身份源、目录连接器、同步游标/批次、外部对象映射及 `CAP-FED-012/013` 对应的迁移模型；`user_identities` 的链接生命周期由 ID 持有，FED 只提交外部身份源事实并消费链接结果。
- 业务模型要求：持久化模型必须支持 OIDC `issuer+sub`、SAML 完整限定元组、禁止仅凭邮箱合并、路由和属性映射版本化以及 SCIM/API 游标、ETag、墓碑和冲突。
- 秘密：Client Secret、第三方 Token 和私钥只存 KMS/Vault；数据库保存配置/Key 引用。
- 事件：身份链接、目录对象创建/更新/墓碑、同步批次结果。
- 门禁：`AT-FED-*`、协议负向测试、旧版本覆盖和跨租户目录映射测试。
