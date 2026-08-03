# KEY：密钥与证书

- 存储：`cryptographic_keys`、`certificates`、`jwks_releases`、`jwks_release_keys`。
- 聚合：`KeyMetadata`、`Certificate`、`JwksRelease`。
- 业务模型要求：数据库只保存 KMS/HSM 引用和公开材料，并为用途隔离、算法 Allowlist、签名与验证重叠窗口、紧急阻断和销毁证明保存所需版本与事实。
- 禁止：私钥、可导出 Secret 和完整凭证明文落库；未批准算法投入生产。
- 事件：Key 生成/激活/轮换/撤销、JWKS 发布/退役、证书失陷。
- 门禁：`AT-KEY-*`、双轮换、旧 Token 验证、盲索引不可枚举和失陷演练。
