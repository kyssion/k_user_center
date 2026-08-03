# SSC：用户自助账号与安全中心

- 存储：复用 `identifiers`、`identifier_bindings`、`authenticators`、`authentication_attempts`、`audit_events`、`devices`、`sessions`、`authorization_grants`、`consents`、`privacy_requests`、`data_export_artifacts`、`profile_documents` 和 `operations`；不建立第二套 SSC 用户、凭证、会话、Grant 或 Consent 表。
- 业务模型：SSC 是用户侧查询和命令入口，不拥有重复的权威聚合；登录方式、设备/会话、应用授权、Consent、导出和注销继续由原领域模型持久化。
- 业务模型要求：持久化事实必须支持登录方式管理、最后凭证保护、安全活动历史、设备和会话退出、应用授权撤回、可疑活动上报、协议/Consent 查看、数据导出、注销进度、安全建议和通知偏好。
- 权威边界：认证器由 AUTH 持有，会话由 SESSION 持有，Grant 由 OAP 持有，Consent/隐私请求由 PRIV 持有；SSC 不得直接复制或形成更弱的状态与撤销模型。
- 禁止：为页面展示建立不可对账的影子状态；把脱敏活动时间线当作完整审计证据；允许移除最后一个可用登录方式后失去全部恢复路径。
- 事件：复用各权威领域事件；可疑活动上报产生风险信号或受控 Operation，不新增语义重复事件。
- 门禁：`CAP-SSC-*`；验证最后凭证保护、跨用户数据隔离、单个/全部退出、授权撤回、Consent/协议展示、导出与注销进度，以及安全通知不可完全关闭。
