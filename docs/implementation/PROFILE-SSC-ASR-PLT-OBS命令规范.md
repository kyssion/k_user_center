# PROFILE、SSC、ASR、PLT 与 OBS 命令规范

## 1. 更新用户资料与文档

- 代码解析字段权威、Namespace、Schema 版本、可见性、数据分类和操作者字段权限；客户端不得通用 JSON Patch 未授权字段。
- `user_profiles` 与可变 `profile_documents` 使用 expected `row_version` CAS，显式更新允许字段、摘要、版本和 `updated_at`。
- 设置 `primary_contact_identifier_id` 前校验 Identifier 属于当前用户、已验证、当前绑定且作用域有效；数据库只保存逻辑 ID 和查询索引。
- 日志、Outbox 和 Audit 只包含变化字段名及摘要，不包含联系方式原文或完整资料文档。

## 2. 身份保证断言

- 代码验证 Provider 信任、证据来源、保证等级映射、主体绑定、有效期、用途和最小披露；原始核验材料不落库。
- `identity_assurance_assertions` 保存稳定断言 ID、证据摘要、Provider、保证等级、签发/失效时间和状态，断言内容创建后不可改写。
- 撤销只更新生命周期元数据并发布安全事件；读取时重新校验状态、有效期、Provider 和适用场景。

## 3. 用户自助安全中心

- SSC 只组合读取 Identifier、认证器、设备、Session、Grant、Consent、隐私请求和资料事实，不建立第二套状态。
- 改密、换绑、恢复、删除最后凭证、退出全部会话和隐私请求复用对应领域命令，并执行重新认证、Step-up、风险和防枚举策略。
- 展示活动历史使用脱敏投影；数据库只读角色不能代替接口级字段授权。
- 一个页面操作涉及多个领域时，由幂等命令或 Operation 编排，SSC 不直接跨域更新底层表。

## 4. 应用接入与平台配置

- 创建 Application、Client、Resource 或 Scope 前校验 Owner、Business Line、环境、命名、Security Profile 和审批。
- 配置内容进入 `configuration_versions`，接入对象只保存当前配置指针和必要快照；激活、回滚和下线通过 CTRL 发布命令完成。
- 配额修改使用 CAS 和版本化配置；`usage_records` 只追加，聚合、限流、超限处置和容量告警由 PLT 代码执行。
- 下线前按查询契约完成 Client、Token、Session、Webhook、消息和机器凭证影响分析，不依赖级联删除。

## 5. 审计与可观测性

- 每个安全敏感命令在同一事务追加 `audit_events`；Audit 构造器执行动作码注册、字段白名单、敏感值脱敏、前后摘要和 Trace 关联。
- 审计 Writer 只能 INSERT，Reader 只能 SELECT；审计记录不得由业务角色更新或删除。要求审计的命令在审计写入失败时失败关闭。
- 指标、Trace、日志和 SLO 计算不写入业务表；数据库只保存稳定基线、审计证据和必要结果摘要。
- 告警、错误预算、异常检测和留存策略由 OBS/SRE 代码及监控系统实现；物理归档或删除前校验 Legal Hold、审计保留和默认分区积压。
