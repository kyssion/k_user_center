# PRIV：协议、Consent 与隐私权利

- 存储：`agreement_versions`、`agreement_acceptances`、`consent_aggregates`、`consents`、`privacy_requests`、`legal_holds`、`data_export_artifacts`、`deletion_proofs`。
- 聚合：`ConsentAggregate`、`PrivacyRequest`、`LegalHold`；协议接受和删除证明不可变。
- 业务模型要求：持久化模型必须支持明确目的/类别/接收方、单独同意、撤回水位、法定期限、代理核验、导出加密、删除编排和依法保留所需的权威事实与证明。
- 禁止：Consent 撤回后继续签发/订阅；Legal Hold 下删除；删除终态主体恢复。
- 事件：Consent 授予/撤回、隐私请求进度、导出就绪、删除证明完成。
- 门禁：`AT-PRIV-*`、下游传播对账、备份保留核查和跨境/敏感信息规则测试。
