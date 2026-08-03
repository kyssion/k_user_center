# MACHINE：机器与工作负载身份

- 持久化范围：`machine_principals`、`machine_credentials`、`workload_trust_bundle_versions`、`workload_attestations`、`machine_role_assignments`。
- 业务模型边界：`MachinePrincipal`、`MachineCredential`、`TrustBundleVersion`。
- 权威边界：MACHINE 持有机器主体、机器凭证、信任包和证明事实；`machine_role_assignments` 的授权关系由 AUTHZ 持有，MACHINE 只提交主体用途、环境与最小权限约束。
- 业务模型要求：持久化模型必须支持负责人、用途、环境、最小权限、强制到期、private_key_jwt/mTLS、明确 Audience、短 Token、自动轮换、替代凭证链、失陷响应、工作负载证明和重放检测。
- 禁止：长期无主机器账号、共享凭证明文、跨环境凭证和无 Audience 的证明。
- 事件：主体/凭证状态、Trust Bundle 发布、证明失败和失陷处置。
- 门禁：`AT-MACHINE-*`、SP4 不签发 Refresh Token、台账差异、轮换窗口、Nonce/JTI 重放和紧急阻断测试。
