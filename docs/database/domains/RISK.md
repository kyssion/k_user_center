# RISK：风险与安全状态

- 存储：`risk_signals`、`risk_assessments`、`risk_assessment_signals`、`risk_cases`、`security_signals`、`restriction_entries`、`risk_entity_links`。
- 聚合：不可变 `RiskAssessment`、`RiskCase`、`RestrictionEntry`。
- 代码规则：信号 Schema、模型/策略版本、解释码、场景处置、限制优先级、风险关联图边界和数据保留。
- 降级：模型、特征、撤销水位不可确定时按版本化失败策略 Step-up 或拒绝。
- 事件：风险等级变化、案件开启/关闭、安全信号和限制生效/解除。
- 门禁：`AT-RISK-*`、管理员/恢复/换绑/合并/机器身份场景覆盖与故障注入。

