# CTRL：控制面、审批与安全例外

- 存储：`configuration_versions`、`configuration_releases`、`configuration_release_items`、`approval_cases`、`approval_actions`、`security_exceptions`。
- 聚合：不可变 `ConfigurationVersion`、`ConfigurationRelease`、`ApprovalCase`、`SecurityException`。
- 业务模型要求：持久化模型必须支持 Schema/语义验证、Seed 内容摘要与漂移检测、差异、审批、职责分离、资源版本绑定、唯一执行标识、灰度、回滚和例外到期收紧。
- 禁止：DRAFT/未审批配置激活；Seed 同版本静默漂移；发起人自审；批准后修改请求；超期例外继续生效。
- 事件：配置发布/回滚、审批终态、例外生效/到期。
- 门禁：`AT-CTRL-*`、`AT-ASR-003`、根密钥与首个管理员恢复演练。
