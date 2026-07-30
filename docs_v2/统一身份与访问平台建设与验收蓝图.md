# 统一身份与访问平台建设与验收蓝图

> 文档状态：目标态建设与验收基线  
> 适用范围：统一 IAM/CIAM 平台及所有接入业务、租户、客户端和资源服务器  
> 能力范围：[统一身份与访问平台（IAM/CIAM）能力地图](./中心能力地图.md)  
> 文档目标：把能力地图转换为可设计、可实现、可测试、可审计和可持续验收的工程契约

## 1. 文档约定

### 1.1 规范性用语

- **必须（MUST）**：不满足即不得上线；任何例外都必须有风险接受人、到期日和补偿控制。
- **应该（SHOULD）**：默认必须满足；不采用时必须记录原因、影响和替代方案。
- **可以（MAY）**：按业务场景选择，不影响基础合规。
- **禁止（MUST NOT）**：任何环境均不得采用。

### 1.2 追踪编号

| 类型 | 格式 | 示例 |
|---|---|---|
| 规范性需求 | `REQ-{领域}-{序号}` | `REQ-ID-001` |
| 不变量 | `INV-{领域}-{序号}` | `INV-SESSION-001` |
| API 契约 | `API-{领域}-{序号}` | `API-AUTH-001` |
| 事件契约 | `EVT-{领域}-{序号}` | `EVT-USER-001` |
| 自动化验收 | `AT-{领域}-{序号}` | `AT-ID-001` |
| 服务目标 | `SLO-{领域}-{序号}` | `SLO-REVOKE-001` |

每条 MUST 必须至少关联一种可验证证据：自动化测试、数据库约束、策略即代码检查、监控查询、审计查询或演练报告。只有说明文字而没有验证方式的 MUST 不视为完成。

### 1.3 交付完成定义

一项能力只有同时满足以下条件才可标记完成：

1. 领域对象、状态机、不变量和权威写入方已明确。
2. API、事件、错误码、幂等和版本兼容契约已发布。
3. 正向、负向、并发、部分失败和恢复测试已自动化。
4. 权限、审计、指标、告警、隐私和数据保留已实现。
5. 容量、可用性、撤销时效和灾备目标已验证。
6. SDK、接入文档、迁移和回滚方案可用。
7. 安全、隐私、SRE 和能力 Owner 完成审批。

## 2. 建设范围与架构边界

### 2.1 平台负责

- Global User、Identifier、Identity、Authenticator 和保证等级。
- OAuth/OIDC、联合登录、会话、Grant、Token 和完整退出。
- Application、Client、API Resource、机器身份和工作负载凭证。
- Membership、Tenant、Organization 的统一关系和隔离元数据。
- 公共 Profile、Consent、Privacy Request 和账号生命周期编排。
- RBAC、作用域、数据范围、策略决策和授权审计。
- 风险信号、全生命周期欺诈、安全响应和持续撤销。
- 控制面、管理后台、审计、事件、SDK、SLO、容灾和迁移。

### 2.2 平台不负责

- 订单、资产、积分、等级、内容、客户标签等业务事实数据。
- 替代 CRM、HR、会员或业务权限域的全部业务规则。
- 通过共享数据库或跨域事务直接修改业务系统数据。
- 在没有明确合法依据和用途时集中收集业务私有资料。

### 2.3 信任边界

系统至少划分为以下故障域和信任域：

| 区域 | 职责 | 关键约束 |
|---|---|---|
| 协议数据面 | authorize、token、userinfo、logout、introspection | 高可用、低延迟、最小依赖 |
| 身份与凭证域 | User、Identity、Authenticator、恢复 | 凭证与普通资料隔离 |
| 会话与撤销域 | Session、Grant、Token Family、revocation | 接近实时、故障时保护优先 |
| 授权决策域 | PAP、PDP、PEP、PIP | 默认拒绝、版本化、可解释 |
| 风险域 | 信号、评分、处置、案件 | 输入可追溯、策略可回滚 |
| 控制面 | Client、策略、密钥、身份源和配置 | 与数据面权限及发布隔离 |
| 隐私编排域 | Consent、导出、删除、法律保留 | 跨系统 Saga 和完成证明 |
| 事件与审计域 | Outbox、事件、Webhook、审计 | 至少一次、可验签、不可篡改 |

业务应用只能通过标准协议、API 和事件接入。任何业务、脚本和管理后台均禁止直接写平台数据库。

## 3. 上线前必须完成的架构决策

| 决策 | 默认基线 | 阻断点 |
|---|---|---|
| 用户判同 | 禁止仅按手机号、邮箱或姓名自动判同 | 数据模型冻结 |
| 外部身份唯一键 | OIDC：`issuer + sub`；SAML：`entityID + NameID + Format + SPNameQualifier（适用时）` | 联合登录开发 |
| Subject 发布 | 默认应用级 pairwise Subject | Client 接入 |
| 手机/邮箱唯一性 | 规范化后全局唯一；例外必须单独 Profile | 数据模型冻结 |
| 业务封禁 | 只影响目标 Membership | 状态机冻结 |
| 账号冻结 | 阻止新认证、刷新和高风险访问 | 会话开发 |
| 保证等级 | 采用 IAL/AAL/FAL 或等价分级 | 认证接口冻结 |
| 用户登录流程 | Authorization Code + PKCE S256 | 协议开发 |
| 机器身份 | 短期凭证优先，不共享人类账号 | 生产服务接入 |
| 权限边界 | 平台管通用角色、作用域、数据范围；业务管业务事实 | 授权设计 |
| 退出传播 | 明确 OP、RP、设备和 Token 最大残留 | SDK 发布 |
| 数据删除 | 明确法律保留、备份和下游证明 | 隐私评审 |
| RTO/RPO | 使用第 15 章默认基线或审批更严格目标 | 架构评审 |

任何未决项必须有负责人、截止日期和受影响里程碑。带 `TBD` 的信任边界、唯一性、撤销或恢复规则不得进入生产。

## 4. 核心数据模型与全局不变量

### 4.1 正交状态模型

禁止使用单一 `account_status` 表达全部状态。至少拆分：

- `user_lifecycle_state`：用户创建、启用、注销和匿名化。
- `security_access_state`：锁定、冻结和安全恢复。
- `membership_state`：业务、租户或组织成员关系。
- `authenticator_state`：认证器登记、有效、失陷和撤销。
- `session_state`：在线会话状态。
- `grant_state`：Client 授权关系。
- `consent_state`：隐私同意状态。
- `risk_state`：风险评估结果，不直接覆盖生命周期状态。

### 4.2 全局不变量

| ID | 不变量 | 实现与验证 |
|---|---|---|
| INV-G-001 | UID、Subject ID、Membership ID 永不复用 | 唯一约束 + 属性测试 |
| INV-G-002 | 同一唯一性作用域内，一个有效 Identifier 最多绑定一个用户 | 规范化唯一索引 + 并发测试 |
| INV-G-003 | 手机、邮箱和外部 ID 不作为内部跨域主键 | Schema/代码扫描 |
| INV-G-004 | 外部身份按协议专用稳定键唯一关联，Transient SAML NameID 不得作为永久账号键 | 唯一约束 + 联合登录测试 |
| INV-G-005 | 全局、租户和 Membership 状态正交且按最严格结果执行 | 决策表测试 |
| INV-G-006 | 未明确授权一律拒绝，前端不构成可信 PEP | 授权负向测试 |
| INV-G-007 | 密码、验证码、完整 Token、私钥不得进入日志和事件 | 持续敏感数据扫描 |
| INV-G-008 | 高风险操作必须有不可篡改审计；审计不可写时失败关闭 | 故障注入测试 |
| INV-G-009 | 已匿名化主体不得恢复，旧 UID 不得分配给新主体 | 状态机 + 数据约束 |
| INV-G-010 | 权威状态写入和领域事件通过同一事务 Outbox 提交 | 宕机恢复测试 |
| INV-G-011 | 未审批、未版本化的控制面配置不得激活 | 发布策略测试 |
| INV-G-012 | 同一幂等键同一请求结果稳定，不同请求体必须冲突 | API 契约测试 |
| INV-G-013 | 冻结主体不能新建会话、刷新 Token 或登记认证器 | 跨域场景测试 |
| INV-G-014 | Grant、Client 或高风险权限撤销后不得继续签发相关 Token | 撤销时效测试 |
| INV-G-015 | 任何跨租户访问必须同时校验主体、资源和作用域租户 | 隔离属性测试 |

### 4.3 安全版本

用户、Client、策略和租户必须维护可单调递增的安全版本：

- `user_security_epoch`：改密、恢复、认证器变更、冻结和账号合并时递增。
- `client_security_epoch`：Client 凭证轮换、禁用或失陷时递增。
- `policy_version`：授权策略激活时递增。
- `tenant_security_epoch`：租户停用、身份源或管理员安全变更时递增。
- `revocation_watermark`：资源服务器判断 Token 是否早于撤销时点。

缓存键必须包含适用的版本；安全版本变化必须主动失效缓存。

## 5. 通用 API、错误与事件契约

### 5.1 API 基线

- `API-G-001 MUST`：除 OAuth `/token` 等已有专用重放语义的标准端点外，所有业务写接口接受 `Idempotency-Key`，保留时间不得短于客户端最大重试窗口。
- `API-G-002 MUST`：更新接口使用 `ETag/If-Match` 或 `expected_version` 防止丢失更新。
- `API-G-003 MUST`：超过同步事务边界的操作返回 `202 Accepted + operation_id`。
- `API-G-004 MUST`：异步 Operation 支持查询状态、失败原因、重试状态和最终结果。
- `API-G-005 MUST`：分页使用不透明游标；查询条件和游标必须绑定租户与权限上下文。
- `API-G-006 MUST`：错误体包含 `code`、安全收敛的 `message`、`retryable`、`trace_id` 和可选 `details`。
- `API-G-007 MUST`：认证、注册和找回接口不得通过状态码、正文或显著时延泄漏账号是否存在。
- `API-G-008 MUST`：批量接口逐项返回结果，禁止因部分成功返回模糊的整体成功。
- `API-G-009 MUST`：所有时间使用 UTC 和明确时区格式，安全判断使用服务端可信时钟。
- `API-G-010 MUST`：所有 API Schema 版本化，破坏性变更必须新主版本并提供迁移窗口。

### 5.2 统一失败语义

| HTTP | 领域码 | 含义 | 客户端处理 |
|---|---|---|---|
| 400 | `INVALID_REQUEST` | 格式或参数错误 | 修正后新请求 |
| 401 | `AUTHENTICATION_REQUIRED` | 无有效认证 | 重新认证 |
| 403 | `ACCESS_DENIED` | 已认证但无权 | 不自动重试 |
| 409 | `IDENTITY_ALREADY_BOUND` | 唯一身份已被占用 | 进入冲突流程 |
| 409 | `IDEMPOTENCY_KEY_REUSED` | 同键请求体不同 | 使用新键 |
| 412 | `VERSION_MISMATCH` | 乐观锁冲突 | 重新读取后决策 |
| 422 | `INVALID_STATE_TRANSITION` | 当前状态不允许操作 | 修正业务流程 |
| 423 | `SUBJECT_FROZEN` | 主体被冻结 | 不重试，进入处置 |
| 429 | `RATE_LIMITED` | 超出频率或配额 | 按 `Retry-After` |
| 503 | `DEPENDENCY_UNAVAILABLE` | 依赖暂不可用 | 仅幂等重试 |
| 503 | `AUTHZ_UNAVAILABLE` | 授权结论不可确定 | 高风险操作失败关闭 |

请求超时表示结果未知，不等于失败。客户端必须使用原幂等键重试或查询 Operation，禁止直接生成新业务请求。

### 5.3 事件信封

所有领域事件必须包含：

```json
{
  "event_id": "evt_...",
  "event_type": "identity.bound",
  "schema_version": 1,
  "aggregate_type": "identity",
  "aggregate_id": "idn_...",
  "aggregate_version": 7,
  "subject_id": "usr_...",
  "tenant_id": "ten_...",
  "business_line_id": "biz_...",
  "actor": {"type": "user|admin|client|system", "id": "..."},
  "occurred_at": "2026-07-30T10:00:00Z",
  "recorded_at": "2026-07-30T10:00:00Z",
  "trace_id": "...",
  "correlation_id": "...",
  "causation_id": "...",
  "data_classification": "internal",
  "payload": {}
}
```

事件规则：

- `EVT-G-001 MUST`：采用至少一次投递，不宣称基础设施天然提供业务“恰好一次”。
- `EVT-G-002 MUST`：单 aggregate 版本单调，不承诺跨 aggregate 全局顺序。
- `EVT-G-003 MUST`：消费者按 `event_id` 去重，并拒绝旧版本覆盖新版本。
- `EVT-G-004 MUST`：提供重试、死信、受控回放、按版本补拉和定期对账。
- `EVT-G-005 MUST`：Webhook 对规范化原始字节签名，携带 key ID 和时间戳，使用有限重放窗口并支持密钥双轮换。
- `EVT-G-006 MUST`：事件默认不携带 PII；确需携带时使用字段白名单和用途约束。
- `EVT-G-007 MUST`：删除、改义或改变字段类型必须升级 Schema 主版本。
- `EVT-G-008 MUST`：回放需要审批、范围和审计，不得重复触发不可逆副作用。
- `EVT-G-009 MUST`：每个 Producer 使用机器主体认证，并通过 `producer principal → event type/tenant` ACL 授权发布。
- `EVT-G-010 MUST`：Webhook 目标在启用前验证所有权；出站连接执行 HTTPS、端口/域名 allowlist、DNS 重绑定防护、重定向限制、私网地址阻断和租户配额隔离。
- `EVT-G-011 MUST`：签名算法、规范化方式、key ID、最大时钟偏差、重放窗口和密钥轮换窗口形成版本化接收方契约。

自动化验收：

- `AT-EVENT-001`：未授权 Producer、事件类型或租户发布被拒绝并告警。
- `AT-EVENT-002`：修改任一请求字节、使用未知 key ID、过期时间戳或重复投递时验签失败或幂等拒绝。
- `AT-EVENT-003`：Webhook 目标的私网地址、DNS 重绑定、跨域重定向和未验证域名被阻断。
- `AT-EVENT-004`：消费者断档后可通过补拉恢复，乱序旧版本不能覆盖新状态。

## 6. 安全 Profile

| Profile | 适用场景 | 最低要求 |
|---|---|---|
| SP1 普通用户 | 普通登录和低风险读取 | Authorization Code + PKCE S256、Refresh Rotation、基础风控 |
| SP2 敏感操作 | 改密、换绑、导出、注销、授权 | AAL2、5 分钟内重新认证、实时风险和实时授权 |
| SP3 特权管理 | 管理员、密钥、策略、批量敏感操作 | 抗钓鱼 MFA、短会话、审批/JIT、强审计、可信管理端 |
| SP4 机器身份 | 服务间和工作负载 | 私钥或 mTLS、明确 audience、Token 不超过 5 分钟、自动轮换 |
| SP5 高价值 API | 资金、核心资产、强监管 | FAPI 2.0、PAR、sender-constrained Token、严格 Client 认证 |

- `REQ-PROFILE-001 MUST`：每个 Client 只能启用已审批 Profile 允许的 grant、scope、回调和认证方式。
- `REQ-PROFILE-002 MUST`：风险升高时可以要求更高 Profile，禁止静默降级。
- `REQ-PROFILE-003 MUST`：Profile 版本进入 Token、审计和接入报告。
- `REQ-PROFILE-004 MUST`：Profile 变更必须经过兼容评估、灰度和回滚。

## 7. 身份、标识与账号生命周期

### 7.1 状态转换

用户生命周期：

`PROVISIONAL → ACTIVE → DELETION_PENDING → ANONYMIZED`

| 转换 | 前置条件 | 原子结果 | 后续动作 |
|---|---|---|---|
| `PROVISIONAL → ACTIVE` | 至少一个注册 Identity 已验证 | 激活用户并递增版本 | 发布 `user.activated` |
| `ACTIVE → DELETION_PENDING` | 强认证、风险通过、注销确认 | 记录冷静期和阻断状态 | 撤销高风险 Grant |
| `DELETION_PENDING → ACTIVE` | 冷静期内撤回、未进入不可逆阶段 | 恢复生命周期 | 重新评估风险与授权 |
| `DELETION_PENDING → ANONYMIZED` | 业务阻断已处理、保留例外确定 | 删除或匿名化 PII | 发布完成证明 |

安全访问使用两个正交维度：

- 认证锁定状态：`ENABLED ⇄ LOCKED`。
- 安全冻结状态：`CLEAR ⇄ FROZEN`。

有效访问要求生命周期为 `ACTIVE`、锁定状态为 `ENABLED` 且冻结状态为 `CLEAR`。解冻只改变冻结状态，不得清除冻结前已经存在的锁定。

### 7.2 规范性规则

- `REQ-ID-001 MUST`：UID 无业务含义、不可变、不可复用。
- `REQ-ID-002 MUST`：Identifier 在写入唯一索引前使用版本化算法统一规范化，记录 `normalization_version`，算法升级执行双键检测和受控迁移。
- `REQ-ID-003 MUST`：两个并发绑定同一 Identifier 时最多一个成功。
- `REQ-ID-004 MUST`：OIDC 外部身份使用 `issuer + sub`；SAML 使用 IdP entityID、NameID 值、NameID Format 及适用的 SPNameQualifier；Transient NameID 不得持久链接；不得仅凭 email 自动合并。
- `REQ-ID-005 MUST`：换绑对原、新 Identifier 分别验证，并执行风险、保护期和通知。
- `REQ-ID-006 MUST`：新持有人验证回收手机号或重分配邮箱时不得继承旧账号。
- `REQ-ID-007 MUST`：账号合并必须验证双方账号、处理冲突、保留旧 UID 映射并撤销双方会话。
- `REQ-ID-008 MUST`：匿名化为不可逆终态，任何恢复请求必须拒绝。
- `REQ-ID-009 SHOULD`：用户名永久不复用；允许复用时必须有长隔离期和历史墓碑。
- `REQ-ID-010 MUST`：业务系统不得以手机号、邮箱或旧业务 ID 作为跨系统主键。
- `REQ-ID-011 MUST`：手机号规范化 v1 使用明确地区解析并存储 E.164；没有可信地区且号码有歧义时拒绝，分机独立存储且不进入唯一键。
- `REQ-ID-012 MUST`：邮箱规范化 v1 去除首尾空白、本地部分使用 Unicode NFC 后 simple case-fold、域名使用 IDNA2008 A-label 并小写；禁止通用的点号删除、plus tag 删除和 provider-specific 别名折叠。
- `REQ-ID-013 MUST`：用户名规范化 v1 使用 NFKC_Casefold、保留词和混淆字符检查；允许字符集、脚本混用和长度规则版本化。

### 7.3 失败语义

- 唯一冲突：`409 IDENTITY_ALREADY_BOUND`，不得泄漏完整占用主体。
- 版本冲突：`412 VERSION_MISMATCH`，调用方重新获取状态。
- 高风险换绑：`403 STEP_UP_REQUIRED` 或 `202 REVIEW_PENDING`。
- 非法合并：`422 MERGE_CONFLICT`，返回不含敏感信息的冲突类型。
- 注销受阻：Operation 保持 `BLOCKED`，列出可向用户展示的阻断项。

### 7.4 API、事件与自动化验收

核心命令：创建用户、绑定/验证/解绑/换绑 Identifier、冻结/解冻、发起合并、发起注销、查询 Operation。

核心事件：`user.created`、`user.lifecycle.changed`、`user.security_state.changed`、`identity.bound`、`identity.unbound`、`identifier.verified`、`identifier.reassigned`、`user.merge.*`、`user.anonymized`。

- `AT-ID-001`：修改手机号和邮箱后 UID 保持不变。
- `AT-ID-002`：100 个并发请求绑定同一号码，仅一个成功，其余确定性冲突。
- `AT-ID-003`：相同邮箱但不同 OIDC 稳定键或 SAML 稳定键不会被静默合并；Transient NameID 不建立永久链接。
- `AT-ID-004`：新持有人不能用回收号码找回旧账号。
- `AT-ID-005`：匿名化后原 UID、Identifier 和凭证均不能恢复或复用。
- `AT-ID-006`：合并任一步骤失败时，系统处于可补偿或明确人工处置状态。
- `AT-ID-007`：已锁定账号被冻结再解冻后仍保持锁定；业务解封不能改变全局冻结或锁定状态。
- `AT-ID-008`：不同服务对国际号码、IDN 邮箱和 Unicode 用户名生成相同 v1 规范键。
- `AT-ID-009`：点号、plus tag 和 provider 别名不会被通用规则错误折叠；规范化升级可发现冲突且不静默合并。

## 8. 认证器、认证、联合与恢复

### 8.1 认证器状态

`PENDING → ACTIVE ⇄ SUSPENDED/LOCKED → EXPIRED/COMPROMISED/REVOKED/REPLACED`

| 状态 | 允许认证 | 允许恢复 | 说明 |
|---|---|---|---|
| PENDING | 否 | 否 | 尚未完成持有证明 |
| ACTIVE | 是 | 作为恢复证据 | 正常认证器 |
| SUSPENDED | 否 | 受限 | 临时风险或人工暂停 |
| LOCKED | 否 | 受限 | 尝试次数超限，可按策略冷却或强验证解锁 |
| EXPIRED | 否 | 受限 | 到期后必须重新登记或替换 |
| COMPROMISED | 否 | 否 | 必须撤销关联会话 |
| REVOKED/REPLACED | 否 | 否 | 终态，保留审计 |

短信、邮件和一次性验证 Challenge 使用独立状态机：

`ISSUED → VERIFIED → CONSUMED`，以及 `ISSUED → EXPIRED/LOCKED/CANCELLED`

Challenge 必须绑定用途、Client、用户或待验证目标、事务和风险上下文；验证成功不等于业务操作完成，业务提交必须原子消费 Challenge。

### 8.2 规范性规则

- `REQ-AUTH-001 MUST`：人类用户登录只允许 Authorization Code + PKCE S256，禁止 Implicit 和 ROPC。
- `REQ-AUTH-002 MUST`：redirect URI 精确匹配，生产环境禁止通配符。原生应用 loopback 仅允许 RFC 8252 规定的动态端口；scheme、字面 loopback host 和 path 必须精确匹配。
- `REQ-AUTH-003 MUST`：协议校验责任按参与方和消息类型执行，具体要求见下表，不得把 Client、RP 和资源服务器责任混为一体。
- `REQ-AUTH-004 MUST`：授权码单次使用并绑定 Client、redirect URI 和 PKCE。
- `REQ-AUTH-005 MUST`：登记或删除认证器需要近期认证、风险检查和安全通知。
- `REQ-AUTH-006 MUST`：恢复不得将高保证账号降级为单短信即可接管。
- `REQ-AUTH-007 MUST`：恢复码哈希存储、单次使用；生成新批次时旧批次全部失效。
- `REQ-AUTH-008 MUST`：密码使用可升级的自适应哈希并检查已泄漏口令。
- `REQ-AUTH-009 MUST`：Passkey 记录 UV、AAGUID、可发现性、同步和备份状态。
- `REQ-AUTH-010 MUST`：管理员使用抗钓鱼 MFA，且不能使用普通客服流程重置。
- `REQ-AUTH-011 MUST`：找回、换绑、认证器替换后递增 security epoch 并撤销相关会话。
- `REQ-AUTH-012 MUST`：错误响应和时延不得形成账号枚举信号。
- `REQ-AUTH-013 MUST`：验证码 Challenge 短时有效、限制尝试次数和发送频率，并在重发时按策略撤销旧 Challenge。
- `REQ-AUTH-014 MUST`：Challenge 单次消费并绑定用途、Client 和原事务，禁止跨流程或跨账号复用。
- `REQ-AUTH-015 MUST`：Challenge 的验证与消费使用原子状态转换，并发消费最多一个成功。

协议校验责任：

| 消息 | 校验方 | 必须校验 |
|---|---|---|
| Authorization Response | OAuth Client | state、响应 issuer（适用时）、code 与原事务绑定 |
| ID Token | OIDC RP | 签名、issuer、audience、azp（多 audience 等适用条件）、nonce、exp、iat、auth_time |
| Access Token | Resource Server | 签名或内省、issuer、audience、exp/nbf、Token 类型、scope/authorization_details |
| UserInfo Response | OIDC RP | TLS、响应来源、`sub` 与 ID Token `sub` 完全一致；JWT 响应还校验签名、issuer、audience |
| Token Request | Authorization Server | Client 认证、授权码或 Refresh Token、PKCE、redirect URI 和重放状态 |

任何参与方校验失败都必须返回对应标准错误并记录安全审计，但不得向终端用户暴露可利用的内部差异。

### 8.3 保证等级

- IAL 表达身份核验程度；手机号验证不等于自然人实名。
- AAL 表达本次认证强度；`acr` 表达等级，`amr` 表达方法。
- FAL 表达联合断言保护程度。
- 每项敏感操作配置最低等级、最大认证年龄、允许认证器和风险上限。
- 恢复、管理员代操作和认证器变化后必须重新计算等级。

### 8.4 失败语义

- 认证失败统一返回安全收敛结果，不区分账号不存在、密码错误或账号锁定。
- 需要升级认证返回 `403 STEP_UP_REQUIRED`，附目标 `acr` 和事务绑定 ID。
- 外部 IdP 不可用返回可重试依赖错误，不得自动降级到弱认证。
- 恢复证据不足返回 `202 REVIEW_PENDING` 或拒绝，不泄漏已有认证器。

### 8.5 自动化验收

- `AT-AUTH-001`：错误账号、错误密码、冻结账号响应不形成可利用枚举差异。
- `AT-AUTH-002`：错误 state、nonce、issuer、audience、PKCE、算法全部拒绝。
- `AT-AUTH-003`：授权码重放和跨 Client 使用均失败。
- `AT-AUTH-004`：SP2/SP3 在等级或认证年龄不足时必定 Step-up。
- `AT-AUTH-005`：恢复完成后旧认证器、相关 Session 和 Token Family 全部失效。
- `AT-AUTH-006`：删除最后一个强认证器被拒绝或进入强审批流程。
- `AT-AUTH-007`：外部 IdP 故障时不发生弱认证降级。
- `AT-AUTH-008`：非 loopback 回调的端口或任意路径变化被拒绝；合法 loopback 动态端口可用。
- `AT-AUTH-009`：Challenge 过期、超次、重发后的旧码、跨用途和跨 Client 使用全部失败。
- `AT-AUTH-010`：100 个并发消费同一 Challenge 时最多一个成功。
- `AT-AUTH-011`：锁定认证器在暂停恢复或账户解冻后仍按原锁定规则处理，终态认证器不能重新激活。
- `AT-AUTH-012`：UserInfo `sub` 与 ID Token 不一致时，无论 JSON 还是 JWT 响应都被拒绝。

## 9. 会话、Grant、Token 与完整退出

### 9.1 对象与状态

- OP Session：身份平台浏览器会话。
- RP Session：业务应用本地会话。
- Device Session：用户在一个设备上的登录关系。
- Authorization Grant：主体对 Client 的资源访问授权。
- Token Family：一组轮换 Refresh Token。
- Refresh Token Instance：Token Family 中的一次性 Token 实例。
- Access Token：短期资源访问凭证。

Session：`ACTIVE → EXPIRED/REVOKED`，失陷时 `ACTIVE → COMPROMISED → REVOKED`。  
Grant：`PENDING → ACTIVE → REVOKED/EXPIRED`。  
Refresh Token Instance：`CURRENT → USED/REVOKED/EXPIRED`。  
Token Family：`ACTIVE → COMPROMISED/REVOKED/EXPIRED`。

### 9.2 规范性规则

- `REQ-SESSION-001 MUST`：Access Token 包含最小声明、明确 issuer、audience、scope 和有效期。
- `REQ-SESSION-002 MUST`：Refresh Token 使用原子 compare-and-set 完成“旧实例标记 USED + 新实例创建”，任一时刻每个 Family 最多一个 CURRENT 实例。
- `REQ-SESSION-003 MUST`：ID Token 不得用于调用业务 API。
- `REQ-SESSION-004 MUST`：改密、恢复、冻结和高风险认证器变更按矩阵撤销会话。
- `REQ-SESSION-005 MUST`：支持当前应用、当前设备、指定设备、租户和全局退出。
- `REQ-SESSION-006 MUST`：RP-Initiated Logout 仅允许已注册 `post_logout_redirect_uri` 精确匹配，校验 `id_token_hint` 或适用 Client 上下文，并安全原样返回 `state`。
- `REQ-SESSION-007 MUST`：Back-Channel Logout Token 校验签名、issuer、audience、sid/sub、iat、jti 和 events 声明并防重放；Logout Token 不使用 nonce。
- `REQ-SESSION-008 MUST`：RP 必须关闭本地会话，不能只删除前端 Token。
- `REQ-SESSION-009 MUST`：会话 Cookie 使用 Secure、HttpOnly、合适的 SameSite，并防止固定会话和 CSRF。
- `REQ-SESSION-010 MUST`：冻结和紧急撤销满足第 15 章传播 SLO。
- `REQ-SESSION-011 SHOULD`：高价值 API 使用 DPoP 或 mTLS 发送方约束 Token。
- `REQ-SESSION-012 MUST`：资源服务器通过短时 Access Token、内省或签名撤销流持续获取 user/client/tenant security epoch 与 revocation watermark；缓存刷新上界不得超过适用撤销 SLO。
- `REQ-SESSION-013 MUST`：高风险操作在 epoch/watermark 不可获得或落后时失败关闭，并纳入每个 API Resource 的接入认证。
- `REQ-SESSION-014 MUST`：并发刷新、响应丢失重试和恶意重放必须区分。SP1 可在同 Client、设备或持有证明绑定下使用受控短重试窗口；SP2/SP3/SP5 默认严格轮换。
- `REQ-SESSION-015 MUST`：Front-Channel Logout 只调用已注册 `frontchannel_logout_uri`，使用规范定义的 `iss + sid` 上下文关闭本地会话，不得按 Back-Channel Logout Token 处理。

### 9.3 失败语义

- Refresh Token 重放：超过受控重试窗口、绑定上下文不一致或出现多个消费来源时，拒绝请求、将 Family 标为 `COMPROMISED`、家族级撤销并产生风险事件。
- 并发刷新：仅原子竞争成功方获得新实例；失败方得到 `invalid_grant`。符合 Profile 的网络丢包重试可在短窗口返回同一轮换结果，不得创建第二条分支。
- RP 退出不可达：全局退出 Operation 标记 `PARTIAL`，持续重试并可对账。
- Token 状态不可确定：普通短期 Token 可按 Profile 降级；SP2/SP3/SP5 失败关闭。
- 密钥轮换期间：新旧公钥按明确窗口并行，过窗旧 Token 按策略拒绝。

### 9.4 自动化验收

- `AT-SESSION-001`：旧 Refresh Token 重放后，新旧 family 成员均不能继续刷新。
- `AT-SESSION-002`：冻结后 60 秒内所有受保护操作拒绝，P99 不超过 30 秒。
- `AT-SESSION-003`：全局退出覆盖 OP、RP、本地 Cookie 和 Refresh Token。
- `AT-SESSION-004`：重复 Logout Token 不产生副作用，错误 audience 或签名被拒绝。
- `AT-SESSION-005`：JWKS 双钥轮换期间新旧合法 Token 可按窗口验证。
- `AT-SESSION-006`：部分 RP 不可达时可见、可重试、可补拉并最终对账。
- `AT-SESSION-007`：100 个并发刷新同一实例时只产生一个 CURRENT 后继，不出现分叉。
- `AT-SESSION-008`：同绑定上下文的丢包重试按 Profile 得到确定结果；窗口外或绑定变化触发 Family 失陷。
- `AT-SESSION-009`：资源服务器断开撤销流或持有过期 epoch 时，SP2/SP3/SP5 操作失败关闭。
- `AT-SESSION-010`：未注册或非精确匹配 post-logout URI 被拒绝，state 不被替换或注入。
- `AT-SESSION-011`：Back-Channel Logout Token 的重放、错误 events/audience/签名被拒绝；Front-Channel 请求不要求或解析 Logout Token。

## 10. 业务线、租户、组织与 Membership

### 10.1 状态

Membership：

`INVITED → PENDING_APPROVAL → ACTIVE ⇄ SUSPENDED`  
`INVITED/PENDING_APPROVAL → REJECTED/EXPIRED`  
`ACTIVE/SUSPENDED → BANNED → ACTIVE`（解封需独立授权）  
`ACTIVE/SUSPENDED/BANNED → LEFT`

Tenant：

`PROVISIONING → ACTIVE ⇄ SUSPENDED → CLOSING → CLOSED`  
`CLOSING → ACTIVE` 仅允许在不可逆关闭步骤前撤回。

### 10.2 规范性规则

- `REQ-TENANT-001 MUST`：业务封禁只改变目标 Membership，不修改全局用户状态。
- `REQ-TENANT-002 MUST`：租户上下文由可信入口和服务端解析，禁止直接信任客户端传入。
- `REQ-TENANT-003 MUST`：数据库、缓存、搜索、事件、日志和导出均包含租户隔离。
- `REQ-TENANT-004 MUST`：租户管理员只能管理授权范围内成员、组织和策略。
- `REQ-TENANT-005 MUST`：租户所有权转移需要强认证、双人复核、等待期和通知。
- `REQ-TENANT-006 MUST`：企业目录停用必须撤销对应租户 Membership、角色、会话和 Grant。
- `REQ-TENANT-007 MUST`：恢复企业成员时不得自动恢复历史高权限。
- `REQ-TENANT-008 MUST`：域名所有权持续验证，失效时停止基于域名的自动路由和 JIT。
- `REQ-TENANT-009 MUST`：暂停恢复、业务解封、邀请拒绝/过期和关闭撤回均检查当前版本、操作者范围、原因和状态守卫。
- `REQ-TENANT-010 MUST`：`LEFT`、`REJECTED`、`EXPIRED` 和 `CLOSED` 为终态；重新加入或重建必须创建新 Membership/Tenant 版本，不复活旧记录。

### 10.3 失败与契约

- 跨租户资源访问统一返回 `403 ACCESS_DENIED`，不泄漏资源是否存在。
- SCIM 乱序更新只按可信源端单调版本或 ETag 拒绝旧状态覆盖；时间戳仅用于诊断，不能决定重新启用或覆盖停用墓碑。
- 目录源不可用不自动重新启用成员；超过离职撤权 SLO 产生安全事故。
- 批量组织变更使用异步 Operation，逐项记录成功、失败和补偿。

### 10.4 自动化验收

- `AT-TENANT-001`：跨租户 ID、游标、缓存键、搜索和批量接口全部拒绝。
- `AT-TENANT-002`：业务封禁不影响同一用户其他业务 Membership。
- `AT-TENANT-003`：SCIM 停用在 SLA 内撤销本租户会话和权限。
- `AT-TENANT-004`：乱序 SCIM 更新不能使离职用户重新激活。
- `AT-TENANT-005`：租户管理员无法提升到平台管理员或越过管理范围。
- `AT-TENANT-006`：暂停成员恢复、业务解封和关闭撤回只在合法前置条件与授权下成功。
- `AT-TENANT-007`：终态 Membership/Tenant 的恢复请求返回非法状态转换，不会原地复活。

### 10.5 企业联合与目录契约

- `REQ-FED-001 MUST`：上游 OIDC/SAML IdP 配置包含租户、issuer/entity ID、元数据来源、受众、回调、允许算法、密钥状态和 Owner。
- `REQ-FED-002 MUST`：OIDC 校验 issuer、签名、audience、nonce、时间和 subject；SAML 校验签名、issuer、audience、recipient、InResponseTo、时间窗口和断言重放。
- `REQ-FED-003 MUST`：IdP 元数据、JWKS 和证书轮换使用受控双版本窗口；拉取失败不得接受未知密钥或弱算法。
- `REQ-FED-004 MUST`：JIT 创建先执行租户、外部身份和 Identifier 冲突检查，不得按 email 静默接管既有用户。
- `REQ-FED-005 MUST`：外部属性经过版本化映射、类型校验和权限上限，不能直接生成平台高权限。
- `REQ-FED-006 MUST`：SCIM 使用源端单调版本或 ETag；不能以不可信客户端时间戳作为唯一顺序依据。
- `REQ-FED-007 MUST`：停用墓碑优先级高于旧更新，重新启用需要更高源版本和显式策略。
- `REQ-FED-008 MUST`：SCIM 创建、替换、补丁、停用和组变更具备幂等、分页、批量部分失败和限流语义。

自动化验收：

- `AT-FED-001`：错误 OIDC issuer/audience/nonce 和 SAML recipient/InResponseTo/时间/签名全部拒绝。
- `AT-FED-002`：OIDC 响应、SAML Assertion 和 SCIM 请求重放不会重复创建或恢复主体。
- `AT-FED-003`：JIT 同邮箱冲突进入安全链接或人工流程，不发生静默合并。
- `AT-FED-004`：旧 SCIM 更新无法覆盖停用墓碑；更高版本显式恢复按策略执行。
- `AT-FED-005`：外部超范围角色和畸形属性不能提升平台权限。

## 11. Profile、Consent 与隐私请求

### 11.1 状态

Consent：

`PENDING → GRANTED → WITHDRAWN/EXPIRED/SUPERSEDED`

Privacy Request：

`SUBMITTED → IDENTITY_VERIFIED → IN_PROGRESS → BLOCKED/PARTIAL → COMPLETED/REJECTED`

### 11.2 规范性规则

- `REQ-PRIV-001 MUST`：公共 Profile 和业务扩展 Profile 分命名空间、权威域和权限。
- `REQ-PRIV-002 MUST`：字段元数据记录类型、来源、敏感级别、用途、可见性、可改性和保留期。
- `REQ-PRIV-003 MUST`：Consent、协议接受、营销订阅和 OAuth Grant 分别建模。
- `REQ-PRIV-004 MUST`：Consent 记录用途、字段、接收方、版本、来源、时间和撤回状态。
- `REQ-PRIV-005 MUST`：建立 `purpose + data categories + recipient` 到 scope、claim、Grant、订阅和下游副本的可审计映射；撤回只阻止并传播到受影响部分，不得误撤销其他合法依据或无关授权。
- `REQ-PRIV-006 MUST`：数据导出使用与敏感度匹配的强认证、异步生成、加密和短期下载。
- `REQ-PRIV-007 MUST`：删除编排覆盖业务系统、搜索、缓存、事件副本和已定义备份策略。
- `REQ-PRIV-008 MUST`：Legal Hold 与删除冲突时记录依据、范围、期限和审批人。
- `REQ-PRIV-009 MUST`：匿名化评估重识别风险；假名化不得宣称为匿名化。
- `REQ-PRIV-010 MUST`：Pairwise Subject 为对外默认标识，跨业务 Global UID 需要明确授权。
- `REQ-PRIV-011 MUST`：Consent 撤回后，包含受影响 scope/claim 的存量 Access Token 通过 consent epoch、内省、denylist 或不超过撤销 SLA 的最大 TTL 停止使用。

### 11.3 失败语义

- 下游未完成时 Privacy Request 不得标记 `COMPLETED`。
- Legal Hold 使请求进入 `BLOCKED`，但不阻止完成可执行的其他部分。
- 导出生成失败可幂等重试；下载链接过期后需重新强认证生成。
- Consent 撤回传播失败触发重试和告警，高风险用途立即失败关闭。
- 资源服务器无法获得最新 consent epoch 或撤销状态时，涉及该用途的 SP2/SP3/SP5 请求失败关闭。

### 11.4 自动化验收

- `AT-PRIV-001`：业务无法读取未授权字段，日志和事件不出现非必要 PII。
- `AT-PRIV-002`：Consent 撤回后不能获得包含受影响 scope/claim 的新 Token 或继续相关订阅，同时无关合法授权仍可使用。
- `AT-PRIV-003`：删除部分失败时请求保持 PARTIAL，恢复后从检查点继续。
- `AT-PRIV-004`：Legal Hold 阻止对应数据删除，解除后流程可继续。
- `AT-PRIV-005`：备份恢复或历史事件回放不会使已删除 PII 重新进入在线系统。
- `AT-PRIV-006`：导出链接过期、越权和重复使用均被拒绝。
- `AT-PRIV-007`：撤回前签发且包含受影响 scope/claim 的 Token 在 SLA 内失效，无关 scope 仍按原 Grant 可用。

## 12. 授权策略与执行

### 12.1 组件契约

- PAP：策略创建、测试、审批、发布、回滚。
- PDP：接收决策输入，返回 allow/deny、reason、obligations、policy_version、decision_id、有效期。
- PEP：网关、后端、数据层和异步执行点。
- PIP：提供身份、资源、租户、风险和保证属性，并声明来源与新鲜度。

### 12.2 规范性规则

- `REQ-AUTHZ-001 MUST`：未匹配允许规则时默认拒绝。
- `REQ-AUTHZ-002 MUST`：决策输入包含 Subject、Actor、Resource、Action、Tenant、Environment、Risk 和 Assurance。
- `REQ-AUTHZ-003 MUST`：显式拒绝优先于允许；继承和冲突规则版本化。
- `REQ-AUTHZ-004 MUST`：前端权限只用于展示，后端 PEP 再次校验。
- `REQ-AUTHZ-005 MUST`：列表查询在数据获取阶段执行范围过滤。
- `REQ-AUTHZ-006 MUST`：高风险写入在提交点重决策或绑定资源版本，防止 TOCTOU。
- `REQ-AUTHZ-007 MUST`：缓存键使用规范化决策输入摘要，至少覆盖 Subject、Actor、资源及资源版本、动作、租户、环境、风险、保证等级、PIP 属性版本/新鲜度、策略版本和所有适用 security epoch。
- `REQ-AUTHZ-008 MUST`：高风险操作在 PDP/PIP 不可用或上下文缺失时失败关闭。
- `REQ-AUTHZ-009 MUST`：外部 IdP 属性需经过受控映射，不能直接赋予高权限角色。
- `REQ-AUTHZ-010 MUST`：策略发布前通过 lint、单元、属性、影子和回归测试。
- `REQ-AUTHZ-011 MUST`：权限授予、使用、回收和决策均可审计解释。
- `REQ-AUTHZ-012 SHOULD`：临时和高权限授权自动到期并定期复核。
- `REQ-AUTHZ-013 MUST`：SP2/SP3/SP5 的高风险决策禁止跨 Actor、风险、保证等级、资源版本或属性新鲜度复用缓存。
- `REQ-AUTHZ-014 MUST`：obligation 使用版本化 Schema，至少包含类型、参数、适用资源和执行时点；典型义务包括 Step-up、脱敏、行级过滤、水印和附加审计。
- `REQ-AUTHZ-015 MUST`：PEP 在请求中声明支持的 obligation 类型；PDP 不得向不支持的 PEP 返回允许结果。
- `REQ-AUTHZ-016 MUST`：允许结果中的全部强制 obligation 必须成功执行；未知、无法执行或执行失败时 PEP 必须拒绝并记录 decision ID。

### 12.3 失败语义

- PDP 不可用：SP2/SP3/SP5 失败关闭；SP1 仅可使用未过期且版本匹配的短缓存。
- PIP 属性缺失：按拒绝处理，不采用宽松默认值。
- 策略冲突：发布阶段阻断；运行时按已激活版本的确定性规则执行。
- 策略回滚：生成新版本，不修改历史决策证据。

### 12.4 自动化验收

- `AT-AUTHZ-001`：删除全部匹配规则后所有受保护请求拒绝。
- `AT-AUTHZ-002`：权限撤回后高风险操作不能命中旧缓存。
- `AT-AUTHZ-003`：列表和详情接口得到一致的数据范围。
- `AT-AUTHZ-004`：篡改客户端 tenant、role、risk 属性不能提升权限。
- `AT-AUTHZ-005`：PDP 故障时各 Profile 按预定策略执行。
- `AT-AUTHZ-006`：策略可解释结果包含匹配规则、拒绝原因和版本。
- `AT-AUTHZ-007`：只改变 Actor、风险、保证等级、资源版本或 PIP 属性版本时不会命中旧允许缓存。
- `AT-AUTHZ-008`：删除 PEP 对某 obligation 的支持后，依赖该义务的请求被拒绝而非忽略。
- `AT-AUTHZ-009`：脱敏、行级过滤或 Step-up 义务执行失败时请求失败关闭并可按 decision ID 审计。

## 13. Client、API Resource 与机器身份

### 13.1 状态

Client：

`DRAFT → VALIDATED → APPROVED → ACTIVE → SUSPENDED/COMPROMISED → RETIRED`

Machine Principal：

`PROVISIONING → ACTIVE → SUSPENDED/COMPROMISED → RETIRED`

工作负载证明与短期凭证签发：

`ATTESTATION_RECEIVED → VERIFIED → CREDENTIAL_ISSUED → EXPIRED/REVOKED`

证明校验失败进入 `REJECTED`；该状态机的每次签发都是独立短期实例，不得把一次通过永久缓存为工作负载可信。

### 13.2 规范性规则

- `REQ-MACHINE-001 MUST`：每个 Client 和机器主体有负责人、用途、环境、资源、到期日和最后使用时间。
- `REQ-MACHINE-002 MUST`：公开客户端不得持有 Client Secret。
- `REQ-MACHINE-003 MUST`：机密客户端优先 private_key_jwt、mTLS 或工作负载联合。
- `REQ-MACHINE-004 MUST`：生产 Client 不共享环境、业务线或无关工作负载。
- `REQ-MACHINE-005 MUST`：API Resource 注册明确 audience、Owner、允许 scope 和 Token Profile。
- `REQ-MACHINE-006 MUST`：机器 Token 使用最小 audience/scope，默认有效期不超过 5 分钟。
- `REQ-MACHINE-007 MUST`：Token Exchange 记录 Subject、Actor、委托链和目标 audience。
- `REQ-MACHINE-008 MUST`：禁止无边界 impersonation；代表用户调用必须区分用户和执行服务。
- `REQ-MACHINE-009 MUST`：机器身份不得使用人类账号找回流程。
- `REQ-MACHINE-010 MUST`：负责人离职、工作负载下线或长期闲置触发复核或自动回收。
- `REQ-MACHINE-011 MUST`：密钥失陷可立即阻止签发、吊销相关 Token 并追踪影响。
- `REQ-MACHINE-012 MUST`：工作负载联合明确 trust domain、证明签发方、audience、环境、工作负载选择器、最大证明年龄和一次性标识。
- `REQ-MACHINE-013 MUST`：证明校验包含签名、issuer、audience、时间、nonce/jti 重放状态和环境绑定，成功后只签发短期凭证。
- `REQ-MACHINE-014 MUST`：信任包、CA、联合密钥和工作负载映射版本化并支持安全轮换、撤销和回滚。
- `REQ-MACHINE-015 MUST`：`private_key_jwt` Client Assertion 要求 `iss = sub = client_id`、audience 精确指向目标 Token 端点、短 `exp`、合理 `iat`、单次 `jti`、已绑定算法和处于有效状态的 Client 公钥。
- `REQ-MACHINE-016 MUST`：Client Assertion 的 `jti` 在有效窗口内全局防重放，且不能跨 Token 端点、环境或 Client 使用。

### 13.3 失败与自动化验收

- Client 禁用立即阻止新 Token；存量 Token 按 Profile 的撤销 SLA 处理。
- 凭证轮换失败保持旧凭证在受控短窗口有效，不得无限延期。
- 负责人缺失或到期未复核使主体进入 `SUSPENDED`。

- `AT-MACHINE-001`：公开客户端使用 secret 认证必定失败。
- `AT-MACHINE-002`：错误 audience 的机器 Token 被资源服务器拒绝。
- `AT-MACHINE-003`：Client 禁用后不能签发或交换新 Token。
- `AT-MACHINE-004`：委托链超限、缺 Actor 或跨租户 Token Exchange 被拒绝。
- `AT-MACHINE-005`：过期、孤儿和闲置机器身份按策略自动暂停。
- `AT-MACHINE-006`：密钥轮换和紧急吊销在目标窗口内完成且可审计。
- `AT-MACHINE-007`：伪造、过期、错误 audience、跨环境和重复 assertion 全部被拒绝。
- `AT-MACHINE-008`：信任包轮换期间合法新旧证明按窗口工作，撤销后旧证明不能签发凭证。
- `AT-MACHINE-009`：`private_key_jwt` 的错误 iss/sub、跨端点 audience、过长 exp、弱算法、撤销密钥和 jti 重放全部被拒绝。

## 14. 风险、欺诈、安全响应与事件

### 14.1 风险覆盖范围

风险决策必须覆盖注册、登录、MFA、Passkey、找回、绑定、换绑、合并、注销撤回、Consent、授权、管理员操作、Client 变更和机器凭证使用。

### 14.2 规范性规则

- `REQ-RISK-001 MUST`：每个信号记录来源、时间、置信度、适用主体和保留期。
- `REQ-RISK-002 MUST`：风险策略版本化、可解释、可灰度、可回滚和可紧急关闭。
- `REQ-RISK-003 MUST`：处置支持放行、挑战、Step-up、等待、拒绝、冻结和人工审核。
- `REQ-RISK-004 MUST`：人工审核证据按最小权限展示，审核动作不可抵赖。
- `REQ-RISK-005 MUST`：风险服务不可用时 SP2/SP3/SP5 失败关闭。
- `REQ-RISK-006 MUST`：安全规则和模型监控误拒、申诉改判、漂移和公平性。
- `REQ-RISK-007 MUST`：账号接管、Refresh 重放、Client 失陷和异常管理员操作产生持续安全信号。
- `REQ-RISK-008 MUST`：安全事件支持调查、证据保全、处置、通知和复盘。

### 14.3 事件与自动化验收

核心事件：`risk.detected`、`risk.disposition.changed`、`authenticator.compromised`、`token.family.compromised`、`assurance.changed`、`client.compromised`、`session.revoked`。

- `AT-RISK-001`：注册、恢复、换绑和管理员操作均经过风险决策。
- `AT-RISK-002`：规则服务故障时高风险操作失败关闭。
- `AT-RISK-003`：同一风险事件重复投递不重复冻结或通知。
- `AT-RISK-004`：规则灰度和回滚不修改历史决策证据。
- `AT-RISK-005`：安全案件可关联认证、会话、Client、设备、审计和处置结果。

## 15. 控制面、审计、SLO 与容灾

### 15.1 控制面

控制面配置状态：

`DRAFT → VALIDATED → APPROVED → STAGED → ACTIVE → DEPRECATED/REVOKED`

| 转换 | 执行者与前置条件 | 失败语义 |
|---|---|---|
| `DRAFT → VALIDATED` | Owner 提交；Schema、引用、冲突、安全规则和 dry-run 通过 | 保持 DRAFT，返回确定性校验问题 |
| `VALIDATED → APPROVED` | 与提交人不同且具备范围权限的审批人 | 自批或职责冲突返回 `APPROVAL_FORBIDDEN` |
| `APPROVED → STAGED` | 发布系统锁定内容哈希和目标环境 | 环境漂移或依赖缺失则阻断 |
| `STAGED → ACTIVE` | 灰度指标、兼容和安全门禁通过 | 失败时停止发布，原 ACTIVE 版本继续服务 |
| `ACTIVE → DEPRECATED` | 新版本已接管且兼容窗口明确 | 仍有活跃依赖则保持 ACTIVE |
| `* → REVOKED` | 授权安全管理员执行紧急撤销 | 立即阻止新使用并传播撤销 |

Client、IdP、策略和密钥必须维护各自独立状态与版本。状态不反向转换；回滚通过引用最后已知良好内容创建新的不可变 Rollback Release，重新校验并使用预先批准或紧急双人审批的发布路径激活，不得把 DEPRECATED 直接改回 ACTIVE，也不得改写历史内容。

- `REQ-CTRL-001 MUST`：Client、回调、IdP、策略、密钥、保留规则和风险规则版本化。
- `REQ-CTRL-002 MUST`：高风险配置双人审批并执行职责分离。
- `REQ-CTRL-003 MUST`：配置支持 dry-run、灰度、自动回滚和紧急撤销。
- `REQ-CTRL-004 MUST`：环境通过受控晋级发布并持续检测漂移。
- `REQ-CTRL-005 MUST`：根密钥、首个管理员和灾备恢复具备书面信任链和演练。
- `REQ-CTRL-006 MUST`：Break-glass 限时、最小权限、使用即告警、自动失效并事后复核。
- `REQ-CTRL-007 MUST`：控制面故障不得放宽数据面认证或授权。

密钥与证书使用独立生命周期：

`GENERATED → PUBLISHED → SIGNING_AND_VERIFYING → VERIFY_ONLY → RETIRED → DESTROYED`

任一未销毁状态发现失陷时进入 `COMPROMISED → REVOKED`。证书另有 `ISSUED → ACTIVE → GRACE/EXPIRED/REVOKED`，不得用通用配置状态代替密码学资产状态。

- `REQ-KEY-001 MUST`：私钥在 KMS/HSM 或等价受控边界生成和使用，禁止以明文导出。
- `REQ-KEY-002 MUST`：新验证键先发布并等待最小传播窗口后才开始签名；旧键停止签名后至少保留到最大 Token TTL、JWKS 缓存和时钟偏差窗口结束。
- `REQ-KEY-003 MUST`：任何时刻至少存在一个可用签名键和覆盖所有未过期合法 Token 的验证键；删除最后一个有效键必须阻断。
- `REQ-KEY-004 MUST`：算法使用 allowlist 和退役计划，禁止 `none`、算法混淆和密钥用途跨用。
- `REQ-KEY-005 MUST`：失陷时立即停止签名、标记撤销、传播受影响 kid/证书、评估存量 Token 并启动应急轮换。
- `REQ-KEY-006 MUST`：跨区域复制和恢复保持密钥版本与撤销状态单调，不得恢复已销毁或已撤销密钥。
- `REQ-KEY-007 MUST`：每个密钥和证书记录 Owner、用途、算法、kid/序列号、环境、创建、启用、到期、轮换和销毁证据。

### 15.2 审计

高风险审计至少包含操作者、Actor、Subject、租户、来源、动作、对象、前后版本、原因、审批、结果、时间、trace ID 和策略版本。

- 审计追加写入、防篡改、独立存储并按法律与安全要求保留。
- 查询审计本身产生审计；敏感字段按角色脱敏。
- 审计不可用时，密钥、策略、高权限、恢复、合并和删除操作失败关闭。

### 15.3 默认 SLO

业务未批准更严格指标时采用以下基线：

| ID | 目标 |
|---|---|
| SLO-AUTH-001 | 核心认证和 Token 端点月可用性不低于 99.99% |
| SLO-API-001 | 管理面及非关键用户 API 月可用性不低于 99.9% |
| SLO-TOKEN-001 | Token 签发 P95 ≤ 150ms，P99 ≤ 300ms，不含外部 IdP |
| SLO-AUTHZ-001 | 在线授权决策 P99 ≤ 50ms |
| SLO-REVOKE-001 | 冻结传播 P99 ≤ 30 秒，硬上限 60 秒 |
| SLO-EVENT-001 | 普通资料事件 99.9% 在 60 秒内可见 |
| SLO-DR-001 | 区域灾难 RTO ≤ 30 分钟；C2 普通资料 RPO ≤ 5 分钟 |
| SLO-DR-002 | Identifier、Credential、Authenticator、Grant 撤销和所有 security epoch 等 C0/C1 安全状态 RPO = 0；无法证明单调时失败关闭至对账完成 |
| SLO-HA-001 | 同可用区数据库故障切换 RPO = 0 |

降低上述基线必须经安全、SRE、业务 Owner 联合风险接受；提高目标可通过配置和容量计划实施。

### 15.4 故障语义

| 依赖故障 | 允许行为 | 禁止行为 |
|---|---|---|
| 短信/邮件 | 提供已批准的其他认证器 | 绕过验证直接放行 |
| 外部 IdP | 已有短期会话按 Profile 继续；新联合登录失败 | 自动创建弱本地账号 |
| 缓存 | 限流回源或使用版本匹配短缓存 | 使用无限期旧权限 |
| PDP/PIP | 低风险按短缓存，高风险失败关闭 | 默认允许 |
| 事件总线 | Outbox 积压、告警、恢复后回放 | 丢弃事件或同步双写 |
| KMS/HSM | 已加载短期密钥按安全窗口使用 | 从不受控副本读取私钥 |
| 审计 | 普通只读按策略降级 | 执行高风险不可审计写入 |

### 15.5 自动化验收

- `AT-CTRL-001`：未审批配置和非法回调在激活前被拒绝。
- `AT-CTRL-002`：Break-glass 到期自动失效且全程告警审计。
- `AT-CTRL-003`：提交人不能审批自己的高风险配置，越权审批被拒绝。
- `AT-CTRL-004`：灰度失败时原 ACTIVE 版本持续服务；激活后回滚会生成新 Release，历史版本和审批证据不被改写。
- `AT-CTRL-005`：紧急撤销可从任意非终态执行并满足传播 SLO。
- `AT-KEY-001`：JWKS 先发布后签名、旧键保留窗口和最终退役顺序通过自动化轮换测试。
- `AT-KEY-002`：删除最后有效签名/验证键、算法降级和密钥跨用途使用被阻断。
- `AT-KEY-003`：密钥失陷后新签发停止、存量影响可识别且撤销在 SLA 内传播。
- `AT-KEY-004`：跨区恢复不会复活已撤销、已销毁密钥或回退密钥版本。
- `AT-AUDIT-001`：每个高风险命令可按 trace ID 重建完整证据链。
- `AT-SEC-001`：持续扫描日志、事件和追踪，不出现密码、验证码、完整 Token 或私钥。
- `AT-SLO-001`：目标峰值 1.5 倍压测期间安全控制不降级。
- `AT-DR-001`：区域故障在 RTO/RPO 内恢复并完成状态、事件和审计对账。
- `AT-DR-002`：跨区故障、复制延迟和脑裂后不会复活旧密码、旧认证器、已撤销 Grant 或较低 security epoch。
- `AT-FAIL-001`：逐项注入短信、IdP、缓存、PDP、事件、KMS 和数据库故障，行为符合表格。

## 16. 跨领域 Saga 与一致性

禁止跨领域数据库双写，统一采用“本域原子事务 + Outbox + Saga + 幂等消费者 + 对账”。

| 流程 | 强一致部分 | 最终一致部分 | 失败与补偿 |
|---|---|---|---|
| 注册 | User 与初始 Identity 唯一绑定 | Membership、通知 | Membership 重试，不删除已签发 UID |
| 换绑 | 新 Identifier 占用和旧绑定切换 | 通知、会话处置 | 原子失败保持旧绑定 |
| 改密/恢复 | Authenticator 版本和 security epoch | 全会话撤销 | 超过撤销 SLO 触发安全事故 |
| 全局冻结 | 状态写入、拒绝新 Token | RP 会话与缓存传播 | 超过 60 秒升级告警 |
| 账号合并 | 任务、主账号和不可逆边界 | 业务资产和 Membership 迁移 | 边界前补偿，之后人工处置 |
| 注销删除 | 请求、冷静期和生命周期状态 | 下游删除、匿名化、证明 | Legal Hold 或失败保持 Pending |
| 权限回收 | Grant/策略版本 | 缓存失效 | 高风险不允许旧缓存 |
| 租户停用 | Tenant 状态 | 成员会话和 Client 访问 | 只影响目标租户 |
| Client 失陷 | 禁用和阻止新签发 | 存量 Token、Webhook 和委托链 | 受控重试并持续告警 |
| Consent 撤回 | Consent 与相关新 Grant 阻断 | 下游订阅和副本处置 | 未完成保持 PARTIAL |

一致性等级：

- **C0 强一致**：Identifier、Authenticator、Grant、关键授权写入。
- **C1 有界陈旧**：冻结、撤销、高风险权限、安全 epoch。
- **C2 最终一致**：Profile、偏好、普通 Membership 副本。
- **C3 可靠追加**：审计、安全证据和事件 Outbox。

每个 Saga 必须声明：

1. Coordinator 和每一步权威域。
2. 幂等键、超时、最大重试和退避。
3. 可补偿步骤与不可逆边界。
4. `PENDING/PARTIAL/BLOCKED/COMPLETED/FAILED` 对外语义。
5. 人工接管、继续、取消和对账接口。
6. 关联 trace、correlation 和 causation ID。

## 17. 迁移、灰度与回滚

迁移批次状态：

`DISCOVERED → CLEANSED → MAPPED → SHADOW → CANARY → CUTOVER → OBSERVING → COMPLETE`

任一可逆阶段可进入 `PAUSED` 或 `ROLLED_BACK`。

每个阶段必须声明回滚截止点和写入保全方式。进入 `CUTOVER` 前可通过重新导入或丢弃影子副本回滚；进入 `CUTOVER` 后产生的新写入必须进入不可变变更日志，并通过反向 CDC 或受控重放同步到回退系统。超过已声明的不可逆边界后只允许前向修复，不得伪装成回滚。

- `REQ-MIG-001 MUST`：旧 ID 到 UID 映射 100% 可追溯，旧 ID 不进入新主键语义。
- `REQ-MIG-002 MUST`：双轨期间每类数据只能有一个权威写入方。
- `REQ-MIG-003 MUST`：密码采用合规的渐进式升级或强制重置，不导入不可接受的明文或弱凭证。
- `REQ-MIG-004 MUST`：重复账号只生成候选，不静默合并。
- `REQ-MIG-005 MUST`：每批迁移对账总量、唯一性、状态、身份、凭证和 Membership。
- `REQ-MIG-006 MUST`：灰度错误、认证失败或差异超过阈值自动暂停。
- `REQ-MIG-007 MUST`：切换后阻止旧系统创建新账号。
- `REQ-MIG-008 MUST`：变更日志不完整、已执行不可逆匿名化/Schema 变换、或回退系统已无法安全恢复时即越过不可逆边界，只允许前向修复；新系统独占写入本身不构成不可逆条件，但必须有完整反向同步能力。
- `REQ-MIG-009 MUST`：切换后的变更日志记录顺序、版本、幂等键和权威来源，反向同步按版本执行并隔离冲突。
- `REQ-MIG-010 MUST`：回滚顺序为停止新写入、排空变更、完成反向同步、对账、切换读写和恢复流量，任一步失败保持 PAUSED。

自动化验收：

- `AT-MIG-001`：每批数量、映射和关键字段差异为零或有逐项审批例外。
- `AT-MIG-002`：双轨并发更新不会产生双主写入。
- `AT-MIG-003`：回滚恢复登录能力且不丢失切换期间产生的数据。
- `AT-MIG-004`：旧手机号、邮箱和外部账号冲突不会触发自动合并。
- `AT-MIG-005`：迁移完成后旧认证入口和新增账号能力不可用。
- `AT-MIG-006`：切换后持续产生写入再执行回滚，回退系统数据无丢失、无重复且版本一致。
- `AT-MIG-007`：超过不可逆边界的回滚请求被拒绝并转为前向修复 Operation。

## 18. 自动化验收门禁

### 18.1 持续测试层级

| 层级 | 必须覆盖 |
|---|---|
| 单元与属性测试 | 状态转换、规范化、策略、不变量 |
| 数据库契约测试 | 唯一约束、版本、事务、Outbox |
| API 契约测试 | Schema、错误、幂等、乐观锁、权限 |
| 事件契约测试 | Schema、重复、乱序、回放、补拉 |
| 协议一致性测试 | OIDC/OAuth、Logout、WebAuthn、SCIM、SAML |
| 安全负向测试 | mix-up、code replay、Token substitution、算法降级、枚举 |
| 租户隔离测试 | API、搜索、缓存、事件、审计、导出 |
| 故障与混沌测试 | 依赖、网络、数据库、KMS、消息和区域故障 |
| 性能容量测试 | 峰值、热点、配额、风控和撤销不降级 |
| 灾备演练 | RTO/RPO、密钥失陷、全局撤销和恢复对账 |

### 18.2 发布阻断条件

出现任一情况必须阻断发布：

1. 任何适用 MUST 没有实现或有效例外。
2. 状态机、不变量、跨租户或协议安全负向测试失败。
3. 数据库迁移不可回滚且未经过演练。
4. 密钥、回调、Client、scope 或策略变更未经审批。
5. 撤销、冻结、授权或审计 SLO 未达到。
6. 日志、事件或追踪发现凭证、验证码、完整 Token 或私钥。
7. API/Event Schema 存在未处理的破坏性兼容变更。
8. 容量测试期间通过关闭安全控制才能达标。

### 18.3 验收证据

每次里程碑验收必须归档：

- 需求与测试追踪矩阵。
- API 和事件 Schema 版本。
- 协议一致性报告。
- 安全负向和渗透测试报告。
- SLO、容量和撤销时延查询。
- 数据库约束与不变量测试报告。
- 隔离、故障注入和灾备演练报告。
- 审计抽样和敏感数据扫描结果。
- 未关闭风险、例外负责人和到期日。

### 18.4 需求到证据追踪矩阵

正式实施时必须维护“一条规范性需求一行”的机器可解析矩阵，字段固定为：

`requirement_id, owner, profile, phase, invariant_ids, api_event_ids, test_ids, slo_ids, evidence_uri, exception_id`

CI 必须校验所有 `MUST` 编号均存在矩阵行、所有引用 ID 存在、适用测试最近一次通过且例外未过期。以下为本蓝图的领域级初始映射；进入迭代前必须展开为逐条映射：

| 需求范围 | 主要不变量/契约 | 自动化证据 | Owner |
|---|---|---|---|
| `API-G-* / EVT-G-*` | `INV-G-010/012`、API/Event Schema | `AT-EVENT-*`、API 契约套件 | 平台 API/事件团队 |
| `REQ-PROFILE-*` | Client Profile、协议元数据 | OIDC/OAuth 一致性与负向套件 | 身份协议团队 |
| `REQ-ID-*` | `INV-G-001/002/004/009` | `AT-ID-*` | 身份领域团队 |
| `REQ-AUTH-*` | Challenge/Authenticator 状态机 | `AT-AUTH-*` | 认证团队 |
| `REQ-SESSION-*` | `INV-G-013/014`、epoch/watermark | `AT-SESSION-*`、`SLO-REVOKE-001` | 会话团队 |
| `REQ-TENANT-* / REQ-FED-*` | `INV-G-005/015`、SCIM/OIDC/SAML 契约 | `AT-TENANT-* / AT-FED-*` | 租户与联合团队 |
| `REQ-PRIV-*` | Consent/Privacy Request 状态机 | `AT-PRIV-*` | 隐私与数据治理团队 |
| `REQ-AUTHZ-*` | `INV-G-006/014/015`、PDP 决策契约 | `AT-AUTHZ-* / SLO-AUTHZ-001` | 授权团队 |
| `REQ-MACHINE-*` | Client/Machine/Attestation 状态机 | `AT-MACHINE-*` | 平台身份团队 |
| `REQ-RISK-*` | Risk Signal/Case 契约 | `AT-RISK-*` | 安全风控团队 |
| `REQ-CTRL-*` | `INV-G-008/011`、配置状态机 | `AT-CTRL-* / AT-AUDIT-*` | 控制面团队 |
| `REQ-KEY-*` | Key/Certificate 生命周期、JWKS 契约 | `AT-KEY-* / SLO-REVOKE-001` | 密钥与平台安全团队 |
| `REQ-MIG-*` | 迁移状态机、变更日志 | `AT-MIG-*` | 迁移团队 |

## 19. 能力规格卡模板

后续新增能力必须按以下模板进入蓝图，禁止只在能力地图增加名称：

```markdown
### {能力 ID} {能力名称}

- Owner：
- 适用 Profile：
- 依赖：
- 数据分类：

#### 前置与后置条件

#### MUST / SHOULD / MAY

#### 状态机与合法转换

#### 不变量

#### 事务、一致性、并发与幂等

#### API、事件和版本契约

#### 失败语义与重试

#### 权限、审计、指标和告警

#### 隐私、保留与删除

#### 自动化验收测试

#### 降级、回滚、容灾与迁移
```

## 20. 参考标准基线

- OpenID Connect Core、Discovery、Dynamic Client Registration。
- OAuth 2.0 及 RFC 9700 OAuth 2.0 Security Best Current Practice。
- RFC 7636 PKCE、RFC 9126 PAR、RFC 9101 JAR、RFC 9396 RAR。
- RFC 8705 OAuth mTLS、RFC 9449 DPoP、RFC 8693 Token Exchange。
- RFC 9068 JWT Access Token Profile、JWT/JWK/JWKS。
- OIDC RP-Initiated、Front-Channel、Back-Channel Logout。
- FAPI 2.0 Security Profile。
- WebAuthn / FIDO2。
- SCIM 2.0、SAML 2.0。
- NIST SP 800-63-4 数字身份指南。
- Shared Signals Framework、CAEP、RISC。

标准定义互操作和安全基线；账号判同、租户隔离、业务状态、权限边界、隐私合法依据及运营流程仍以本平台明确规则为准。
