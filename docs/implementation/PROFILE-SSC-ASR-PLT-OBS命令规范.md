# PROFILE、SSC、ASR、PLT 与 OBS 命令规范

## 1. 更新用户资料与文档

- 更新前解析字段权威、资料 Namespace、Schema 版本、可见性和数据分类；客户端不得通过通用 JSON Patch 修改未授权字段。
- `user_profiles` 使用 expected `row_version` CAS；`profile_documents` 同时更新文档版本、规范化 Payload 摘要和允许变化的内容字段。
- 设置 `primary_contact_identifier_id` 前校验 Identifier 属于当前用户、已验证、当前绑定且满足作用域要求；Foreign Key 只校验 Identifier 存在。
- 日志、Outbox 和 Audit 只包含变化字段名及摘要，不包含联系方式原文或完整资料文档。

## 2. 身份保证断言

- 创建前验证 Provider 信任、证据来源、保证等级映射、主体绑定、有效期和最小披露要求；原始核验材料不落库。
- `identity_assurance_assertions` 保存稳定断言 ID、证据摘要、Provider、保证等级、签发/失效时间和状态；断言内容创建后不可改写。
- 撤销只更新生命周期元数据并发布安全事件；AUTH/ASR 读取时必须重新校验状态、有效期、Provider 和适用场景，不能仅凭保证等级字段放行。

## 3. 用户自助安全中心

- SSC 只组合读取 Identifier、认证器、设备、Session、Grant、Consent、隐私请求和资料事实，不建立第二套用户、凭证、会话或授权状态。
- 改密、换绑、恢复、删除最后凭证、退出全部会话和导出/删除请求复用对应领域命令，并执行重新认证、Step-up、风险和防枚举策略。
- 展示活动历史时使用审计/认证尝试的脱敏投影；不得向普通只读角色开放凭证、Token、联系方式、投递目标或迁移原文。
- 一个页面操作涉及多个领域时，由幂等命令或 Operation 编排；SSC 不直接跨域更新底层表。

## 4. 应用接入与平台配置

- 创建 Application、Client、Resource 或 Scope 前校验 Owner、Business Line、环境、命名占用、Security Profile 和审批要求。
- 配置内容进入 `configuration_versions`，接入对象只保存当前配置指针和必要快照；激活、回滚和下线通过 CTRL 发布命令完成。
- 配额修改使用 CAS 和版本化配置；`usage_records` 只追加，聚合、限流、超限处置和容量告警由 PLT 代码执行。
- 下线前使用引用与查询契约完成 Client、Token、Session、Webhook、消息和机器凭证影响分析，不依赖数据库级联删除。

## 5. 审计与可观测性

- 每个安全敏感命令在同一事务追加 `audit_events`；Audit 构造器执行动作码注册、字段白名单、敏感值脱敏、前后摘要和 Trace 关联。
- 审计 Writer 只能 INSERT，Reader 只能 SELECT；审计记录不得由业务角色更新或删除。审计写入失败时，要求审计的命令失败关闭。
- 指标、Trace、日志和 SLO 计算不写入业务表；数据库只保存稳定 SLO/时长基线、审计证据和必要结果摘要。
- 告警、错误预算、异常检测和留存策略由 OBS/SRE 代码及监控系统实现；归档或删除前必须校验 Legal Hold、审计保留和默认分区积压。

