# MACHINE：机器与工作负载身份

- 存储：`machine_principals`、`machine_credentials`、`workload_trust_bundle_versions`、`workload_attestations`、`machine_role_assignments`。
- 聚合：`MachinePrincipal`、`MachineCredential`、`TrustBundleVersion`。
- 代码规则：负责人、用途、环境、最小权限、强制到期、凭证轮换、失陷响应、工作负载证明和重放检测。
- 禁止：长期无主机器账号、共享凭证明文、跨环境凭证和无 Audience 的证明。
- 事件：主体/凭证状态、Trust Bundle 发布、证明失败和失陷处置。
- 门禁：`AT-MACHINE-*`、台账差异、轮换窗口、Nonce/JTI 重放和紧急阻断测试。

