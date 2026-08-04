\set ON_ERROR_STOP on

SET ROLE iam_owner;

-- 认证器与认证事务。算法选择、挑战校验、尝试限制和状态转换由 AUTH 代码负责。

CREATE TABLE iam.authenticators (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    authenticator_type varchar(40) NOT NULL,
    state varchar(40) NOT NULL,
    display_name varchar(160),
    assurance_level varchar(40),
    phishing_resistant boolean NOT NULL DEFAULT false,
    backup_eligible boolean,
    registered_at timestamptz NOT NULL,
    last_used_at timestamptz,
    replaced_by_id uuid,
    state_reason varchar(100),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_authenticators_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.authenticators IS '用户认证器根记录；登记、替换、挂失、撤销和保证等级由 AUTH 领域状态机处理。';
COMMENT ON COLUMN iam.authenticators.id IS '应用生成的认证器 UUIDv7。';
COMMENT ON COLUMN iam.authenticators.user_id IS '逻辑引用 iam.global_users.id；写入前校验用户生命周期。';
COMMENT ON COLUMN iam.authenticators.authenticator_type IS '认证器类型，例如 PASSWORD、PASSKEY、TOTP。';
COMMENT ON COLUMN iam.authenticators.state IS '认证器状态；合法转换由 AUTH 代码维护。';
COMMENT ON COLUMN iam.authenticators.display_name IS '可空；用户可识别名称，按展示文本处理。';
COMMENT ON COLUMN iam.authenticators.assurance_level IS '可空；认证器可贡献的保证等级配置快照。';
COMMENT ON COLUMN iam.authenticators.phishing_resistant IS '是否具备抗钓鱼属性；结论由登记代码基于凭证类型写入。';
COMMENT ON COLUMN iam.authenticators.backup_eligible IS '可空；Passkey 等认证器的可备份属性。';
COMMENT ON COLUMN iam.authenticators.registered_at IS '登记完成业务时间。';
COMMENT ON COLUMN iam.authenticators.last_used_at IS '可空；最近成功使用时间，仅作事实存储。';
COMMENT ON COLUMN iam.authenticators.replaced_by_id IS '可空；逻辑引用 iam.authenticators.id。';
COMMENT ON COLUMN iam.authenticators.state_reason IS '可空；最近状态变化原因码。';
COMMENT ON COLUMN iam.authenticators.metadata IS '非秘密认证器元数据；代码按类型 Schema 校验。';
COMMENT ON COLUMN iam.authenticators.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.authenticators.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.authenticators.row_version IS '乐观锁版本。';

CREATE TABLE iam.credential_materials (
    id uuid PRIMARY KEY,
    authenticator_id uuid NOT NULL,
    material_type varchar(40) NOT NULL,
    secret_hash text,
    secret_ciphertext text,
    public_material jsonb,
    credential_id_digest varchar(256),
    algorithm varchar(80) NOT NULL,
    algorithm_parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    key_id uuid,
    material_version integer NOT NULL,
    usage_counter bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_credential_material_version UNIQUE (authenticator_id, material_type, material_version),
    CONSTRAINT uq_credential_id_digest UNIQUE (credential_id_digest),
    CONSTRAINT ck_credential_material_present CHECK (secret_hash IS NOT NULL OR secret_ciphertext IS NOT NULL OR public_material IS NOT NULL),
    CONSTRAINT ck_credential_material_version CHECK (material_version > 0 AND usage_counter >= 0 AND row_version >= 0)
);
COMMENT ON TABLE iam.credential_materials IS '认证凭证安全材料；只保存自适应哈希、应用密文或公钥材料，普通应用角色不得读取。';
COMMENT ON COLUMN iam.credential_materials.id IS '应用生成的凭证材料 UUIDv7。';
COMMENT ON COLUMN iam.credential_materials.authenticator_id IS '逻辑引用 iam.authenticators.id。';
COMMENT ON COLUMN iam.credential_materials.material_type IS '材料类型，例如 PASSWORD_HASH、TOTP_SECRET、PASSKEY_PUBLIC_KEY。';
COMMENT ON COLUMN iam.credential_materials.secret_hash IS '可空；不可逆凭证哈希，禁止保存可逆密码。';
COMMENT ON COLUMN iam.credential_materials.secret_ciphertext IS '可空；应用加密后的秘密材料，属于最高敏感级别。';
COMMENT ON COLUMN iam.credential_materials.public_material IS '可空；不可变公钥等非秘密结构，代码校验格式；可变使用计数器单独存入 usage_counter。';
COMMENT ON COLUMN iam.credential_materials.credential_id_digest IS '可空；Passkey Credential ID 的摘要或安全编码值。';
COMMENT ON COLUMN iam.credential_materials.algorithm IS '算法标识，必须由代码对照算法 Allowlist。';
COMMENT ON COLUMN iam.credential_materials.algorithm_parameters IS '算法参数快照，例如成本和盐；禁止存储秘密明文。';
COMMENT ON COLUMN iam.credential_materials.key_id IS '可空；逻辑引用 iam.cryptographic_keys.id；KMS/HSM 外部引用先登记为密钥元数据，数据库 FK 校验存在性。';
COMMENT ON COLUMN iam.credential_materials.material_version IS '同认证器和材料类型内的正整数版本。';
COMMENT ON COLUMN iam.credential_materials.usage_counter IS '认证器协议要求的非负使用计数器；代码使用 CAS 单调更新，公钥和秘密材料本身不可改写。';
COMMENT ON COLUMN iam.credential_materials.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.credential_materials.retired_at IS '可空；材料退出使用的业务时间。';
COMMENT ON COLUMN iam.credential_materials.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.credential_materials.row_version IS '使用计数器和退役元数据的乐观锁版本。';

CREATE TABLE iam.password_history (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    authenticator_id uuid NOT NULL,
    password_hash text NOT NULL,
    algorithm varchar(80) NOT NULL,
    algorithm_parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.password_history IS '历史口令哈希事实，用于代码执行口令复用检查；不得存储明文或可逆密文。';
COMMENT ON COLUMN iam.password_history.id IS '应用生成的历史记录 UUIDv7。';
COMMENT ON COLUMN iam.password_history.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.password_history.authenticator_id IS '逻辑引用 iam.authenticators.id。';
COMMENT ON COLUMN iam.password_history.password_hash IS '历史自适应口令哈希，最高敏感级别。';
COMMENT ON COLUMN iam.password_history.algorithm IS '哈希算法标识。';
COMMENT ON COLUMN iam.password_history.algorithm_parameters IS '历史哈希参数快照。';
COMMENT ON COLUMN iam.password_history.created_at IS '数据库插入时间，也是历史排序时间。';

CREATE TABLE iam.recovery_code_batches (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    batch_version integer NOT NULL,
    state varchar(40) NOT NULL,
    code_count integer NOT NULL,
    generated_at timestamptz NOT NULL,
    expires_at timestamptz,
    invalidated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_recovery_batch_version UNIQUE (user_id, batch_version),
    CONSTRAINT ck_recovery_batch_count CHECK (code_count > 0),
    CONSTRAINT ck_recovery_batch_version CHECK (batch_version > 0 AND row_version >= 0),
    CONSTRAINT ck_recovery_batch_expiry CHECK (expires_at IS NULL OR expires_at > generated_at)
);
COMMENT ON TABLE iam.recovery_code_batches IS '恢复码批次；生成、替换和失效规则由 AUTH 代码处理。';
COMMENT ON COLUMN iam.recovery_code_batches.id IS '应用生成的批次 UUIDv7。';
COMMENT ON COLUMN iam.recovery_code_batches.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.recovery_code_batches.batch_version IS '用户内递增批次版本。';
COMMENT ON COLUMN iam.recovery_code_batches.state IS '批次状态；代码维护合法转换。';
COMMENT ON COLUMN iam.recovery_code_batches.code_count IS '批次生成的恢复码数量。';
COMMENT ON COLUMN iam.recovery_code_batches.generated_at IS '恢复码生成业务时间。';
COMMENT ON COLUMN iam.recovery_code_batches.expires_at IS '可空；批次过期时间。';
COMMENT ON COLUMN iam.recovery_code_batches.invalidated_at IS '可空；批次整体失效时间。';
COMMENT ON COLUMN iam.recovery_code_batches.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.recovery_code_batches.row_version IS '乐观锁版本。';

CREATE TABLE iam.recovery_codes (
    id uuid PRIMARY KEY,
    batch_id uuid NOT NULL,
    code_hash varchar(256) NOT NULL,
    sequence_no integer NOT NULL,
    state varchar(40) NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_recovery_code_hash UNIQUE (code_hash),
    CONSTRAINT uq_recovery_code_sequence UNIQUE (batch_id, sequence_no),
    CONSTRAINT ck_recovery_code_sequence CHECK (sequence_no > 0)
);
COMMENT ON TABLE iam.recovery_codes IS '单次恢复码摘要；验证和原子消费由 AUTH 代码与条件更新共同完成。';
COMMENT ON COLUMN iam.recovery_codes.id IS '应用生成的恢复码记录 UUIDv7。';
COMMENT ON COLUMN iam.recovery_codes.batch_id IS '逻辑引用 iam.recovery_code_batches.id。';
COMMENT ON COLUMN iam.recovery_codes.code_hash IS '恢复码不可逆摘要，全库唯一，不保存原码。';
COMMENT ON COLUMN iam.recovery_codes.sequence_no IS '批次内正整数序号。';
COMMENT ON COLUMN iam.recovery_codes.state IS '恢复码状态；代码维护 UNUSED、USED 等语义。';
COMMENT ON COLUMN iam.recovery_codes.used_at IS '可空；成功消费业务时间。';
COMMENT ON COLUMN iam.recovery_codes.created_at IS '数据库插入时间。';

CREATE TABLE iam.auth_challenges (
    id uuid PRIMARY KEY,
    purpose varchar(80) NOT NULL,
    client_id uuid,
    subject_type varchar(40),
    subject_id uuid,
    target_digest varchar(128),
    token_hash varchar(256) NOT NULL,
    state varchar(40) NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL,
    context jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_auth_challenge_token UNIQUE (token_hash),
    CONSTRAINT ck_auth_challenge_attempts CHECK (attempt_count >= 0 AND max_attempts > 0 AND attempt_count <= max_attempts),
    CONSTRAINT ck_auth_challenge_version CHECK (row_version >= 0),
    CONSTRAINT ck_auth_challenge_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.auth_challenges IS '验证码、Magic Link、绑定确认等短时挑战；只保存 Token 摘要，发送和验证策略由 AUTH/MSG 代码执行。';
COMMENT ON COLUMN iam.auth_challenges.id IS '应用生成的 Challenge UUIDv7。';
COMMENT ON COLUMN iam.auth_challenges.purpose IS '挑战目的代码，决定验证处理器。';
COMMENT ON COLUMN iam.auth_challenges.client_id IS '可空；逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.auth_challenges.subject_type IS '可空；挑战主体类型。';
COMMENT ON COLUMN iam.auth_challenges.subject_id IS '可空；挑战主体逻辑 ID。';
COMMENT ON COLUMN iam.auth_challenges.target_digest IS '可空；目标联系方式的 HMAC 摘要。';
COMMENT ON COLUMN iam.auth_challenges.token_hash IS '验证码或链接秘密的不可逆摘要，不保存原值。';
COMMENT ON COLUMN iam.auth_challenges.state IS '挑战状态；代码控制签发、消费、锁定和过期。';
COMMENT ON COLUMN iam.auth_challenges.attempt_count IS '已失败或已验证尝试次数。';
COMMENT ON COLUMN iam.auth_challenges.max_attempts IS '签发时策略快照的最大尝试次数。';
COMMENT ON COLUMN iam.auth_challenges.context IS '挑战上下文；代码白名单化且不得包含秘密。';
COMMENT ON COLUMN iam.auth_challenges.expires_at IS '挑战过期时间，由代码按策略计算。';
COMMENT ON COLUMN iam.auth_challenges.consumed_at IS '可空；一次性挑战消费时间。';
COMMENT ON COLUMN iam.auth_challenges.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.auth_challenges.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.auth_challenges.row_version IS '乐观锁版本。';

CREATE TABLE iam.login_transactions (
    id uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    tenant_id uuid,
    user_id uuid,
    request_uri_digest char(64),
    redirect_uri_digest char(64),
    requested_scope text[] NOT NULL DEFAULT ARRAY[]::text[],
    requested_acr text[] NOT NULL DEFAULT ARRAY[]::text[],
    state varchar(40) NOT NULL,
    risk_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    context jsonb NOT NULL DEFAULT '{}'::jsonb,
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT ck_login_transaction_version CHECK (row_version >= 0),
    CONSTRAINT ck_login_transaction_expiry CHECK (expires_at > created_at)
);
COMMENT ON TABLE iam.login_transactions IS 'OIDC/OAuth 登录过程的服务端权威事务；AUTH 持有事务与认证步骤，OAP 使用结果完成协议交互。';
COMMENT ON COLUMN iam.login_transactions.id IS '应用生成的登录事务 UUIDv7。';
COMMENT ON COLUMN iam.login_transactions.client_id IS '逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.login_transactions.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.login_transactions.user_id IS '可空；身份识别完成后逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.login_transactions.request_uri_digest IS '可空；授权请求规范化摘要。';
COMMENT ON COLUMN iam.login_transactions.redirect_uri_digest IS '可空；回调地址精确值摘要，实际匹配由代码完成。';
COMMENT ON COLUMN iam.login_transactions.requested_scope IS '请求 Scope 快照；授权代码校验和收敛。';
COMMENT ON COLUMN iam.login_transactions.requested_acr IS '请求 ACR 列表快照。';
COMMENT ON COLUMN iam.login_transactions.state IS '登录事务状态；合法转换由代码维护。';
COMMENT ON COLUMN iam.login_transactions.risk_snapshot IS '风险评估摘要，不作为数据库决策规则。';
COMMENT ON COLUMN iam.login_transactions.context IS '协议上下文；代码按版本化契约校验并脱敏。';
COMMENT ON COLUMN iam.login_transactions.expires_at IS '事务过期时间。';
COMMENT ON COLUMN iam.login_transactions.completed_at IS '可空；事务进入终态时间。';
COMMENT ON COLUMN iam.login_transactions.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.login_transactions.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.login_transactions.row_version IS '乐观锁版本。';

CREATE TABLE iam.login_transaction_steps (
    id uuid PRIMARY KEY,
    login_transaction_id uuid NOT NULL,
    step_code varchar(80) NOT NULL,
    factor_type varchar(40),
    state varchar(40) NOT NULL,
    evidence_digest char(64),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_version bigint NOT NULL DEFAULT 0,
    CONSTRAINT uq_login_transaction_step UNIQUE (login_transaction_id, step_code),
    CONSTRAINT ck_login_transaction_step_version CHECK (row_version >= 0)
);
COMMENT ON TABLE iam.login_transaction_steps IS '登录事务已要求或完成的认证、同意和安全步骤。';
COMMENT ON COLUMN iam.login_transaction_steps.id IS '应用生成的步骤 UUIDv7。';
COMMENT ON COLUMN iam.login_transaction_steps.login_transaction_id IS '逻辑引用 iam.login_transactions.id。';
COMMENT ON COLUMN iam.login_transaction_steps.step_code IS '事务内稳定步骤代码。';
COMMENT ON COLUMN iam.login_transaction_steps.factor_type IS '可空；认证因子类型。';
COMMENT ON COLUMN iam.login_transaction_steps.state IS '步骤状态；由登录编排器维护。';
COMMENT ON COLUMN iam.login_transaction_steps.evidence_digest IS '可空；证据规范化摘要。';
COMMENT ON COLUMN iam.login_transaction_steps.evidence IS '非秘密证据元数据；不得保存验证码、密码或完整 Token。';
COMMENT ON COLUMN iam.login_transaction_steps.completed_at IS '可空；步骤完成时间。';
COMMENT ON COLUMN iam.login_transaction_steps.created_at IS '数据库插入时间。';
COMMENT ON COLUMN iam.login_transaction_steps.updated_at IS '数据库更新时间；由技术 Trigger 自动刷新。';
COMMENT ON COLUMN iam.login_transaction_steps.row_version IS '乐观锁版本。';

CREATE TABLE iam.authentication_contexts (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    login_transaction_id uuid,
    ial varchar(40),
    aal varchar(40) NOT NULL,
    fal varchar(40),
    acr varchar(160) NOT NULL,
    amr text[] NOT NULL,
    authenticated_at timestamptz NOT NULL,
    risk_level varchar(40),
    mapping_version integer NOT NULL,
    evidence_digest char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_auth_context_mapping CHECK (mapping_version > 0)
);
COMMENT ON TABLE iam.authentication_contexts IS '一次成功认证的保证上下文快照，供会话和 Token 引用；映射和满足性判断由 AUTH 代码完成。';
COMMENT ON COLUMN iam.authentication_contexts.id IS '应用生成的认证上下文 UUIDv7。';
COMMENT ON COLUMN iam.authentication_contexts.user_id IS '逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.authentication_contexts.login_transaction_id IS '可空；逻辑引用 iam.login_transactions.id。';
COMMENT ON COLUMN iam.authentication_contexts.ial IS '可空；身份保证等级快照。';
COMMENT ON COLUMN iam.authentication_contexts.aal IS '认证保证等级快照。';
COMMENT ON COLUMN iam.authentication_contexts.fal IS '可空；联合保证等级快照。';
COMMENT ON COLUMN iam.authentication_contexts.acr IS '协议 ACR 值。';
COMMENT ON COLUMN iam.authentication_contexts.amr IS '实际认证方式列表，可写入 Token。';
COMMENT ON COLUMN iam.authentication_contexts.authenticated_at IS '认证完成业务时间。';
COMMENT ON COLUMN iam.authentication_contexts.risk_level IS '可空；认证时风险等级快照。';
COMMENT ON COLUMN iam.authentication_contexts.mapping_version IS '保证等级映射规则版本。';
COMMENT ON COLUMN iam.authentication_contexts.evidence_digest IS '认证证据链规范化摘要，不保存秘密。';
COMMENT ON COLUMN iam.authentication_contexts.created_at IS '数据库插入时间。';

CREATE TABLE iam.authentication_attempts (
    id uuid NOT NULL,
    client_id uuid,
    tenant_id uuid,
    user_id uuid,
    subject_hint_digest varchar(128),
    authenticator_type varchar(40),
    device_id uuid,
    source_ip inet,
    network_fingerprint varchar(128),
    result varchar(40) NOT NULL,
    reason_code varchar(100),
    risk_level varchar(40),
    trace_id varchar(64),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_authentication_attempts PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);
COMMENT ON TABLE iam.authentication_attempts IS '高容量认证尝试事实；按 occurred_at 月度 Range 分区，限速、锁定和风险计算由代码执行。';
COMMENT ON COLUMN iam.authentication_attempts.id IS '应用生成的尝试 UUIDv7。';
COMMENT ON COLUMN iam.authentication_attempts.client_id IS '可空；逻辑引用 iam.oauth_clients.id。';
COMMENT ON COLUMN iam.authentication_attempts.tenant_id IS '可空；逻辑引用 iam.tenants.id。';
COMMENT ON COLUMN iam.authentication_attempts.user_id IS '可空；已识别时逻辑引用 iam.global_users.id。';
COMMENT ON COLUMN iam.authentication_attempts.subject_hint_digest IS '可空；登录提示的 HMAC 摘要，不保存明文账号。';
COMMENT ON COLUMN iam.authentication_attempts.authenticator_type IS '可空；尝试使用的认证器类型。';
COMMENT ON COLUMN iam.authentication_attempts.device_id IS '可空；逻辑引用 iam.devices.id。';
COMMENT ON COLUMN iam.authentication_attempts.source_ip IS '可空；来源 IP，受限个人数据。';
COMMENT ON COLUMN iam.authentication_attempts.network_fingerprint IS '可空；网络环境不可逆指纹。';
COMMENT ON COLUMN iam.authentication_attempts.result IS '认证结果代码。';
COMMENT ON COLUMN iam.authentication_attempts.reason_code IS '可空；稳定失败或拒绝原因码。';
COMMENT ON COLUMN iam.authentication_attempts.risk_level IS '可空；当次风险等级快照。';
COMMENT ON COLUMN iam.authentication_attempts.trace_id IS '可空；跨服务追踪 ID。';
COMMENT ON COLUMN iam.authentication_attempts.occurred_at IS '尝试实际发生时间和月度分区键。';
COMMENT ON COLUMN iam.authentication_attempts.recorded_at IS '数据库落库时间。';

CREATE INDEX ix_authenticators_user ON iam.authenticators (user_id, state, authenticator_type);
CREATE INDEX ix_password_history_user ON iam.password_history (user_id, created_at DESC);
CREATE INDEX ix_auth_challenges_target ON iam.auth_challenges (purpose, target_digest, state, expires_at);
CREATE INDEX ix_auth_challenges_expiry ON iam.auth_challenges (state, expires_at);
CREATE INDEX ix_login_transactions_user ON iam.login_transactions (user_id, state, created_at DESC);
CREATE INDEX ix_login_transactions_expiry ON iam.login_transactions (state, expires_at);
CREATE INDEX ix_authentication_attempts_user ON iam.authentication_attempts (user_id, occurred_at DESC);
CREATE INDEX ix_authentication_attempts_network ON iam.authentication_attempts (network_fingerprint, occurred_at DESC);
COMMENT ON INDEX iam.ix_auth_challenges_target IS '按目的和目标摘要执行代码限速与有效挑战查询。';
