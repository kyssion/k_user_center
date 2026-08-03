# PROFILE：用户资料与身份保证

- 持久化范围：`user_profiles`、`profile_documents`、`identity_assurance_assertions`。
- 业务模型边界：稳定 `UserProfile`、作用域化 `ProfileDocument`、不可变保证断言。
- 权威边界：PROFILE 持有用户资料、作用域化文档和 `identity_assurance_assertions`；ASR 使用断言计算保证等级，其他领域只引用有效断言并执行最小披露。
- 业务模型要求：持久化模型必须支持字段级权威、JSON Schema、可见性、版本化 Claim 映射和脱敏；主联系方式必须引用当前用户已验证且有效绑定的 Identifier，输入净化属于非数据库职责。
- 删除：隐私流程按数据目录删除或匿名化；保证断言只保留最小证据和摘要。
- 事件：资料版本变化、保证断言签发/撤销；对外事件使用接收方 Subject。
- 门禁：`CAP-PROFILE-*`、主联系方式跨用户/未验证/已解绑负向测试、隐私字段授权和乱序事件测试。
