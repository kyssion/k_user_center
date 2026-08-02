# PROFILE：用户资料与身份保证

- 存储：`user_profiles`、`profile_documents`、`identity_assurance_assertions`。
- 聚合：稳定 `UserProfile`、作用域化 `ProfileDocument`、不可变保证断言。
- 代码规则：字段级权威、JSON Schema、可见性、输入净化、版本化 Claim 映射和脱敏。
- 删除：隐私流程按数据目录删除或匿名化；保证断言只保留最小证据和摘要。
- 事件：资料版本变化、保证断言签发/撤销；对外事件使用接收方 Subject。
- 门禁：`CAP-PROFILE-*`、隐私字段授权负向测试和乱序事件测试。

