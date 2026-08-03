param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
)

$ErrorActionPreference = 'Stop'
$migrationPath = Join-Path $RepositoryRoot 'database/postgresql/migrations'
$seedPath = Join-Path $RepositoryRoot 'database/postgresql/seeds'
$verificationPath = Join-Path $RepositoryRoot 'database/postgresql/verification'
$outputPath = Join-Path $RepositoryRoot 'docs/database/generated'
$traceabilityPath = Join-Path $RepositoryRoot 'docs/database/需求编号与数据库持久化覆盖索引.md'
$logicalRelationPath = Join-Path $RepositoryRoot 'docs/database/逻辑关系与非数据库校验清单.md'
$businessModelBoundaryPath = Join-Path $RepositoryRoot 'docs/database/业务模型与持久化边界清单.md'
$domainDocumentationPath = Join-Path $RepositoryRoot 'docs/database/domains'
$capabilityMapPath = Join-Path $RepositoryRoot 'docs/能力地图.md'
$blueprintPath = Join-Path $RepositoryRoot 'docs/统一身份与访问平台建设与验收蓝图.md'
$domainFiles = Get-ChildItem -LiteralPath $migrationPath -Filter '*.sql' |
    Where-Object { $_.Name -match '^(010|020|030|040|050|060|070|080|090|100|110|120|130|140)_' } |
    Sort-Object Name
$allMigrationFiles = Get-ChildItem -LiteralPath $migrationPath -Filter '*.sql' | Sort-Object Name
$seedFiles = Get-ChildItem -LiteralPath $seedPath -Filter '*.sql' | Sort-Object Name

$tables = [System.Collections.Generic.List[object]]::new()
$allSql = ($allMigrationFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
$allSeedSql = ($seedFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"

foreach ($file in $domainFiles) {
    $sql = Get-Content -Raw -LiteralPath $file.FullName
    $tableMatches = [regex]::Matches($sql, '(?ms)^CREATE TABLE iam\.(?<table>[a-z0-9_]+)\s*\((?<body>.*?)^\)(?<suffix> PARTITION BY [^;]+)?;')
    foreach ($tableMatch in $tableMatches) {
        $tableName = $tableMatch.Groups['table'].Value
        $body = $tableMatch.Groups['body'].Value
        $tableCommentMatch = [regex]::Match($sql, "COMMENT ON TABLE iam\.$tableName IS '(?<comment>[^']*)';")
        $columns = [System.Collections.Generic.List[object]]::new()

        foreach ($line in ($body -split "`r?`n")) {
            $columnMatch = [regex]::Match($line, '^\s{4}(?<column>[a-z][a-z0-9_]*)\s+(?<definition>.+?)(?:,)?$')
            if (-not $columnMatch.Success) { continue }
            $columnName = $columnMatch.Groups['column'].Value
            $definition = $columnMatch.Groups['definition'].Value.TrimEnd(',').Trim()
            $commentMatch = [regex]::Match($sql, "COMMENT ON COLUMN iam\.$tableName\.$columnName IS '(?<comment>[^']*)';")
            $columns.Add([pscustomobject]@{
                Name = $columnName
                Definition = $definition
                Comment = if ($commentMatch.Success) { $commentMatch.Groups['comment'].Value } else { '' }
            })
        }

        $tables.Add([pscustomobject]@{
            Name = $tableName
            Source = $file.Name
            Comment = if ($tableCommentMatch.Success) { $tableCommentMatch.Groups['comment'].Value } else { '' }
            Partition = $tableMatch.Groups['suffix'].Value.Trim()
            Columns = $columns
        })
    }
}

$missingTableComments = @($tables | Where-Object { [string]::IsNullOrWhiteSpace($_.Comment) })
$missingColumnComments = @($tables | ForEach-Object {
    $tableName = $_.Name
    $_.Columns | Where-Object { [string]::IsNullOrWhiteSpace($_.Comment) } | ForEach-Object { "$tableName.$($_.Name)" }
})
$foreignKeyMatches = [regex]::Matches($allSql, '(?im)^\s*(?:CONSTRAINT\s+[a-z0-9_]+\s+)?FOREIGN\s+KEY\b|^\s*[a-z][a-z0-9_]*\s+[^\r\n,]*\bREFERENCES\s+iam\.').Count
$triggerMatches = [regex]::Matches($allSql, '(?i)\bCREATE\s+TRIGGER\b').Count
$routineMatches = [regex]::Matches($allSql, '(?i)\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\b').Count
$enumMatches = [regex]::Matches($allSql, '(?i)\bCREATE\s+TYPE\b[^;]*\bAS\s+ENUM\b').Count
$viewMatches = [regex]::Matches($allSql, '(?im)^\s*CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\b').Count
$forbiddenSeedTargets = [regex]::Matches($allSeedSql, '(?im)\bINSERT\s+INTO\s+iam\.(?:global_users|identifiers|identifier_bindings|tenants|organizations|memberships|oauth_clients|machine_credentials|credential_materials)\b').Count
$rawSecretSeedKeys = [regex]::Matches($allSeedSql, '(?i)"(?:plain_password|verification_code|private_key_value|client_secret_value|totp_secret)"\s*:').Count
$businessModelBoundaryContent = Get-Content -Raw -LiteralPath $businessModelBoundaryPath
$businessModelTablePatterns = @([regex]::Matches($businessModelBoundaryContent, '`(?<table>[a-z0-9_*]+)`') | ForEach-Object { $_.Groups['table'].Value } | Sort-Object -Unique)
$missingBusinessModelMappings = @($tables | Where-Object {
    $tableName = $_.Name
    @($businessModelTablePatterns | Where-Object { $tableName -like $_ }).Count -eq 0
})
$tableDomainUsage = @{}
foreach ($table in $tables) {
    $tableDomainUsage[$table.Name] = [System.Collections.Generic.List[string]]::new()
}
foreach ($domainDocument in (Get-ChildItem -LiteralPath $domainDocumentationPath -Filter '*.md')) {
    $scopeLine = Get-Content -LiteralPath $domainDocument.FullName | Where-Object { $_ -like '- 持久化范围：*' } | Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($scopeLine)) { throw "领域文档缺少持久化范围：$($domainDocument.Name)" }
    $scopePatterns = @([regex]::Matches($scopeLine, '`(?<table>[a-z0-9_*]+)`') | ForEach-Object { $_.Groups['table'].Value })
    foreach ($table in $tables) {
        $tableName = $table.Name
        if (@($scopePatterns | Where-Object { $tableName -like $_ }).Count -gt 0) {
            $tableDomainUsage[$tableName].Add($domainDocument.BaseName)
        }
    }
}
$sharedAuthoritySectionMatch = [regex]::Match($businessModelBoundaryContent, '(?ms)^## 4\. 共享表与跨域写入权威\s+(?<section>.*?)(?=^## 5\.)')
if (-not $sharedAuthoritySectionMatch.Success) { throw '业务模型与持久化边界清单缺少共享表权威章节。' }
$sharedAuthorityTablePatterns = @([regex]::Matches($sharedAuthoritySectionMatch.Groups['section'].Value, '`(?<table>[a-z0-9_*]+)`') | ForEach-Object { $_.Groups['table'].Value } | Sort-Object -Unique)
$sharedTables = @($tables | Where-Object { $tableDomainUsage[$_.Name].Count -gt 1 })
$missingDomainMappings = @($tables | Where-Object { $tableDomainUsage[$_.Name].Count -eq 0 })
$missingSharedAuthorityMappings = @($sharedTables | Where-Object {
    $tableName = $_.Name
    @($sharedAuthorityTablePatterns | Where-Object { $tableName -like $_ }).Count -eq 0
})

$columnDefinitionLookup = @{}
$columnSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($table in $tables) {
    foreach ($column in $table.Columns) {
        $key = "$($table.Name).$($column.Name)"
        $columnDefinitionLookup[$key] = $column.Definition
        [void]$columnSet.Add($key)
    }
}

$logicalRelations = [System.Collections.Generic.List[object]]::new()
$logicalCommentMatches = [regex]::Matches($allSql, "(?im)^COMMENT ON COLUMN iam\.(?<source_table>[a-z0-9_]+)\.(?<source_column>[a-z0-9_]+) IS '(?<comment>[^']*逻辑引用[^']*)';")
foreach ($logicalMatch in $logicalCommentMatches) {
    $sourceTable = $logicalMatch.Groups['source_table'].Value
    $sourceColumn = $logicalMatch.Groups['source_column'].Value
    $comment = $logicalMatch.Groups['comment'].Value
    $targetMatches = [regex]::Matches($comment, 'iam\.(?<target_table>[a-z0-9_]+)\.(?<target_column>[a-z0-9_]+)')
    $relationKind = 'POLYMORPHIC'
    $targetTable = ''
    $targetColumn = ''
    if ($targetMatches.Count -eq 1) {
        $targetTable = $targetMatches[0].Groups['target_table'].Value
        $targetColumn = $targetMatches[0].Groups['target_column'].Value
        $sourceDefinition = $columnDefinitionLookup["$sourceTable.$sourceColumn"]
        $relationKind = if ($sourceDefinition -match '\[\]') { 'ARRAY' } else { 'DIRECT' }
        if (-not $columnSet.Contains("$targetTable.$targetColumn")) {
            throw "逻辑引用目标不存在：$sourceTable.$sourceColumn -> $targetTable.$targetColumn"
        }
    }
    $logicalRelations.Add([pscustomobject]@{
        SourceTable = $sourceTable
        SourceColumn = $sourceColumn
        Kind = $relationKind
        TargetTable = $targetTable
        TargetColumn = $targetColumn
        Comment = $comment
    })
}

$logicalRelations = @($logicalRelations | Sort-Object SourceTable, SourceColumn -Unique)
$directRelations = @($logicalRelations | Where-Object { $_.Kind -in @('DIRECT','ARRAY') })
$polymorphicRelations = @($logicalRelations | Where-Object { $_.Kind -eq 'POLYMORPHIC' })

$requirementPattern = '\b(?:CAP|REQ|INV|API|EVT|AT|SLO|TTL|TERM)-[A-Z0-9]+(?:-[A-Z0-9]+)+\b'
$requirementIndex = @{}
foreach ($sourcePath in @($capabilityMapPath, $blueprintPath)) {
    $sourceName = Split-Path -Leaf $sourcePath
    $lineNo = 0
    foreach ($line in (Get-Content -LiteralPath $sourcePath)) {
        $lineNo++
        foreach ($requirementMatch in [regex]::Matches($line, $requirementPattern)) {
            $id = $requirementMatch.Value
            if (-not $requirementIndex.ContainsKey($id)) {
                $requirementIndex[$id] = $sourceName
            }
        }
    }
}
$requirementIds = @($requirementIndex.Keys | Sort-Object)

if ($tables.Count -ne 113) { throw "目标表数量应为 113，实际为 $($tables.Count)。" }
if ($missingTableComments.Count -gt 0) { throw "缺少表 Comment：$($missingTableComments.Name -join ', ')" }
if ($missingColumnComments.Count -gt 0) { throw "缺少字段 Comment：$($missingColumnComments -join ', ')" }
if ($missingBusinessModelMappings.Count -gt 0) { throw "业务模型与持久化边界清单缺少逻辑表映射：$($missingBusinessModelMappings.Name -join ', ')" }
if ($missingDomainMappings.Count -gt 0) { throw "领域文档持久化范围缺少逻辑表映射：$($missingDomainMappings.Name -join ', ')" }
if ($missingSharedAuthorityMappings.Count -gt 0) { throw "多领域复用表缺少共享写入权威：$($missingSharedAuthorityMappings.Name -join ', ')" }
if ($foreignKeyMatches -gt 0 -or $triggerMatches -gt 0 -or $routineMatches -gt 0 -or $enumMatches -gt 0 -or $viewMatches -gt 0) {
    throw "发现禁止对象：FK=$foreignKeyMatches Trigger=$triggerMatches Routine=$routineMatches Enum=$enumMatches View=$viewMatches"
}
if ($forbiddenSeedTargets -gt 0 -or $rawSecretSeedKeys -gt 0) {
    throw "Seed 安全检查失败：ForbiddenTargets=$forbiddenSeedTargets RawSecretKeys=$rawSecretSeedKeys"
}

$dictionary = [System.Text.StringBuilder]::new()
[void]$dictionary.AppendLine('# 数据字典')
[void]$dictionary.AppendLine()
[void]$dictionary.AppendLine('> 本文件由 `database/postgresql/verification/Generate-DatabaseDocs.ps1` 从 Migration 生成，请勿手工修改。')
[void]$dictionary.AppendLine()
[void]$dictionary.AppendLine("目标父表数量：$($tables.Count)。")
[void]$dictionary.AppendLine()
foreach ($table in $tables) {
    [void]$dictionary.AppendLine("## iam.$($table.Name)")
    [void]$dictionary.AppendLine()
    [void]$dictionary.AppendLine("- 来源：``$($table.Source)``")
    [void]$dictionary.AppendLine("- 说明：$($table.Comment)")
    if (-not [string]::IsNullOrWhiteSpace($table.Partition)) {
        [void]$dictionary.AppendLine("- 分区：``$($table.Partition)``")
    }
    [void]$dictionary.AppendLine()
    [void]$dictionary.AppendLine('| 字段 | SQL 定义 | Comment |')
    [void]$dictionary.AppendLine('|---|---|---|')
    foreach ($column in $table.Columns) {
        $definition = $column.Definition.Replace('|', '\|')
        $comment = $column.Comment.Replace('|', '\|')
        [void]$dictionary.AppendLine("| ``$($column.Name)`` | ``$definition`` | $comment |")
    }
    [void]$dictionary.AppendLine()
}

$indexMatches = [regex]::Matches($allSql, '(?im)^CREATE\s+(?<unique>UNIQUE\s+)?INDEX\s+(?<index>[a-z0-9_]+)\s+ON\s+iam\.(?<table>[a-z0-9_]+)\s+(?<definition>[^;]+);')
$constraintMatches = [regex]::Matches($allSql, '(?im)^\s*CONSTRAINT\s+(?<constraint>[a-z0-9_]+)\s+(?<definition>PRIMARY KEY|UNIQUE(?: NULLS NOT DISTINCT)?|CHECK)')
$inventory = [System.Text.StringBuilder]::new()
[void]$inventory.AppendLine('# 表、字段、索引与约束清单')
[void]$inventory.AppendLine()
[void]$inventory.AppendLine('> 本文件由 Migration 自动生成，请勿手工修改。')
[void]$inventory.AppendLine()
[void]$inventory.AppendLine("- 父表：$($tables.Count)")
[void]$inventory.AppendLine("- 字段：$((($tables | ForEach-Object { $_.Columns.Count }) | Measure-Object -Sum).Sum)")
[void]$inventory.AppendLine("- 显式索引：$($indexMatches.Count)")
[void]$inventory.AppendLine("- 命名约束：$($constraintMatches.Count)")
[void]$inventory.AppendLine("- 分区父表：$(@($tables | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Partition) }).Count)")
[void]$inventory.AppendLine()
[void]$inventory.AppendLine('## 按 Migration 统计')
[void]$inventory.AppendLine()
[void]$inventory.AppendLine('| Migration | 表数 | 字段数 |')
[void]$inventory.AppendLine('|---|---:|---:|')
foreach ($group in ($tables | Group-Object Source)) {
    $fieldCount = (($group.Group | ForEach-Object { $_.Columns.Count }) | Measure-Object -Sum).Sum
    [void]$inventory.AppendLine("| ``$($group.Name)`` | $($group.Count) | $fieldCount |")
}
[void]$inventory.AppendLine()
[void]$inventory.AppendLine('## 显式索引')
[void]$inventory.AppendLine()
[void]$inventory.AppendLine('| 索引 | 表 | 定义 |')
[void]$inventory.AppendLine('|---|---|---|')
foreach ($match in $indexMatches) {
    [void]$inventory.AppendLine("| ``$($match.Groups['index'].Value)`` | ``iam.$($match.Groups['table'].Value)`` | ``$($match.Groups['definition'].Value.Trim().Replace('|','\|'))`` |")
}

$domainStorage = @{
    'API' = '`idempotency_records`、`operations`、`operation_steps`'
    'ASR' = '`identity_assurance_assertions`、`delegations`、`approval_cases`、`approval_actions`'
    'AUTH' = '`authenticators`、`credential_materials`、`auth_challenges`、`login_transactions`、`authentication_contexts`、`authentication_attempts`'
    'AUTHZ' = '`permissions`、`roles`、`policy_versions`、`policy_bindings`、`authorization_decisions`、`relationship_tuples`'
    'CTRL' = '`configuration_versions`、`configuration_releases`、`configuration_release_items`、`security_exceptions`、`approval_cases`'
    'EVENT' = '`outbox_events`、`inbox_messages`、`event_schema_versions`、`webhook_*`、`consumer_checkpoints`'
    'FED' = '`identity_providers`、`directory_connectors`、`directory_sync_*`、`directory_object_mappings`'
    'ID' = '`global_users`、`user_subjects`、`identifiers`、`identifier_claims`、`identifier_bindings`、`user_identities`、`user_aliases`'
    'KEY' = '`cryptographic_keys`、`certificates`、`jwks_releases`、`jwks_release_keys`'
    'MACHINE' = '`machine_principals`、`machine_credentials`、`workload_trust_bundle_versions`、`workload_attestations`'
    'MSG' = '`message_providers`、`message_template_versions`、`message_requests`、`message_delivery_attempts`、`contact_reachability`、`message_suppressions`'
    'OAP' = '`oauth_clients`、`api_resources`、`oauth_scopes`、`authorization_codes`、`authorization_grants`、Token 元数据表'
    'OBS' = '`audit_events`、`risk_signals`、`usage_records`、投递和执行证据表'
    'OPS' = '`operations`、`operation_steps`、`audit_events`、风险与审批证据表'
    'PLT' = '`business_lines`、`applications`、`resource_quotas`、`usage_records`、配置与密钥元数据表'
    'PRIV' = '`agreement_*`、`consent_*`、`privacy_requests`、`legal_holds`、`data_export_artifacts`、`deletion_proofs`'
    'PROFILE' = '`user_profiles`、`profile_documents`、`identifiers`、`identifier_bindings`'
    'RISK' = '`risk_signals`、`risk_assessments`、`risk_cases`、`security_signals`、`restriction_entries`'
    'SESSION' = '`devices`、`sessions`、`session_participants`、Token/Grant 表、`revocation_entries`'
    'SSC' = '复用 `identifiers`、`authenticators`、`authentication_attempts`、`devices`、`sessions`、`authorization_grants`、`consents`、`privacy_requests`、`profile_documents`；不建立重复 SSC 权威表'
    'TENANT' = '`tenants`、`tenant_domains`、`organizations`、`memberships`、`invitations`、`groups`、`group_members`'
    'MIG' = '`legacy_systems`、`legacy_id_mappings`、`migration_batches`、`migration_items`、`migration_change_logs`'
    'COMMON' = '跨领域基础表、审计、Outbox/Inbox 与相关领域表'
}
$sloDomain = @{'AUTH'='AUTH';'API'='API';'TOKEN'='SESSION';'AUTHZ'='AUTHZ';'REVOKE'='SESSION';'EVENT'='EVENT';'PRIV'='PRIV';'ALERT'='OBS';'DR'='PLT';'HA'='PLT'}
$ttlDomain = @{'TOKEN'='SESSION';'CODE'='SESSION';'SESSION'='SESSION';'LOGINTX'='AUTH';'CHALLENGE'='AUTH';'STEPUP'='AUTH';'JWKS'='KEY'}
$termDomain = @{'DELETE'='PRIV';'REBIND'='ID';'IDENTIFIER'='ID';'RECOVERY'='ASR';'TENANT'='TENANT';'DORMANT'='ID';'EXCEPTION'='CTRL';'KEY'='KEY';'EXPORT'='PRIV'}
$requirementDomainOverrides = @{
    'INV-G-001'='ID';'INV-G-002'='ID';'INV-G-003'='ID';'INV-G-004'='FED';'INV-G-005'='TENANT';
    'INV-G-006'='AUTHZ';'INV-G-007'='AUTH';'INV-G-008'='OBS';'INV-G-009'='ID';'INV-G-010'='EVENT';
    'INV-G-011'='CTRL';'INV-G-012'='API';'INV-G-013'='SESSION';'INV-G-014'='SESSION';'INV-G-015'='TENANT';
    'INV-G-016'='AUTH';'INV-G-017'='ASR';'INV-G-018'='ASR'
}
$requirementStorageOverrides = @{
    'CAP-FED-012'='`identity_providers`、`directory_connectors`、`directory_sync_*`、`directory_object_mappings`、`legacy_systems`、`legacy_id_mappings`、`migration_batches`、`migration_items`、`migration_change_logs`'
    'CAP-FED-013'='`identity_providers`、`user_identities`、`credential_materials`、`password_history`、`legacy_systems`、`legacy_id_mappings`、`migration_batches`、`migration_items`、`migration_change_logs`'
}

function Resolve-RequirementDomain([string]$Id) {
    if ($requirementDomainOverrides.ContainsKey($Id)) { return $requirementDomainOverrides[$Id] }
    $parts = $Id -split '-'
    switch ($parts[0]) {
        'INV' { if ($domainStorage.ContainsKey($parts[1]) -and $parts[1] -ne 'G') { return $parts[1] }; return 'COMMON' }
        'API' { if ($domainStorage.ContainsKey($parts[1]) -and $parts[1] -ne 'G') { return $parts[1] }; return 'API' }
        'EVT' { if ($domainStorage.ContainsKey($parts[1]) -and $parts[1] -ne 'G') { return $parts[1] }; return 'EVENT' }
        'SLO' { if ($sloDomain.ContainsKey($parts[1])) { return $sloDomain[$parts[1]] }; return 'OBS' }
        'TTL' { if ($ttlDomain.ContainsKey($parts[1])) { return $ttlDomain[$parts[1]] }; return 'COMMON' }
        'TERM' { if ($termDomain.ContainsKey($parts[1])) { return $termDomain[$parts[1]] }; return 'COMMON' }
        default {
            if ($parts[0] -eq 'AT' -and $parts[1] -eq 'SLO') { return 'OBS' }
            if ($parts[0] -eq 'AT' -and $parts[1] -eq 'DR') { return 'PLT' }
            if ($domainStorage.ContainsKey($parts[1])) { return $parts[1] }
            return 'COMMON'
        }
    }
}

$atIdsByDomain = @{}
foreach ($atId in ($requirementIds | Where-Object { $_ -like 'AT-*' })) {
    $atDomain = Resolve-RequirementDomain $atId
    if (-not $atIdsByDomain.ContainsKey($atDomain)) {
        $atIdsByDomain[$atDomain] = [System.Collections.Generic.List[string]]::new()
    }
    $atIdsByDomain[$atDomain].Add($atId)
}

$traceability = [System.Text.StringBuilder]::new()
[void]$traceability.AppendLine('# 需求编号与数据库持久化覆盖索引')
[void]$traceability.AppendLine()
[void]$traceability.AppendLine('> 本文件由 `database/postgresql/verification/Generate-DatabaseDocs.ps1` 从能力地图和蓝图的编号生成，只回答需求可能使用哪些数据库持久化边界。它不是蓝图 §18.4 的正式代码实施与验收矩阵，不声明 Owner、Profile、Phase、具体接口、代码结构或逐条自动化测试绑定。')
[void]$traceability.AppendLine()
[void]$traceability.AppendLine("- 数据库覆盖编号总数：$($requirementIds.Count)")
foreach ($kindGroup in ($requirementIds | Group-Object { ($_ -split '-')[0] } | Sort-Object Name)) {
    [void]$traceability.AppendLine("- $($kindGroup.Name)：$($kindGroup.Count)")
}
[void]$traceability.AppendLine()
[void]$traceability.AppendLine('持久化边界列表示该编号可能使用的数据库事实，不表示每项能力都必须新建表。状态机、跨对象校验、业务授权求值、风险、审批、协议和流程属于非数据库职责，进入编码阶段后在单独的代码实施文档中展开。')
[void]$traceability.AppendLine()
[void]$traceability.AppendLine('| 编号 | 首次来源文档 | 领域 | 数据库持久化边界 | 非数据库职责提示 | 数据库验证与后续验收提示 |')
[void]$traceability.AppendLine('|---|---|---|---|---|---|')
foreach ($id in $requirementIds) {
    $parts = $id -split '-'
    $kind = $parts[0]
    $domain = Resolve-RequirementDomain $id
    $storage = if ($requirementStorageOverrides.ContainsKey($id)) { $requirementStorageOverrides[$id] }
        elseif ($kind -eq 'SLO') { '`configuration_versions` 的 `SLO_BASELINE`，运行指标进入监控系统' }
        elseif ($kind -in @('TTL','TERM')) { '`configuration_versions` 的 `DURATION_BASELINE`，对象表保存实际到期时间' }
        else { $domainStorage[$domain] }
    $nonDatabaseResponsibility = "$domain 领域的状态转换、跨对象有效性、业务授权求值、风险、审批、协议和流程属于非数据库职责；具体实现另行成册。"
    $domainAtEvidence = if ($atIdsByDomain.ContainsKey($domain)) {
        (($atIdsByDomain[$domain] | Sort-Object | ForEach-Object { "``$_``" }) -join '、')
    } else { 'SQL Verification 001–008 与领域负向测试' }
    $evidence = if ($kind -eq 'AT') { "``$id`` 可能包含数据库契约、权限、并发或审计验证；具体自动化实现以后续实施矩阵为准" }
        elseif ($kind -eq 'SLO') { "``$id`` 主要由指标、压测或演练验证；数据库只保存基线和必要证据；相关领域验收提示（非逐条绑定）：$domainAtEvidence" }
        else { "SQL Verification 验证持久化边界；相关领域验收提示（非逐条绑定）：$domainAtEvidence" }
    [void]$traceability.AppendLine("| ``$id`` | ``$($requirementIndex[$id])`` | ``$domain`` | $storage | $nonDatabaseResponsibility | $evidence |")
}

$relationDocument = [System.Text.StringBuilder]::new()
[void]$relationDocument.AppendLine('# 逻辑关系与非数据库校验清单')
[void]$relationDocument.AppendLine()
[void]$relationDocument.AppendLine('> 本文件由 Migration 的 Column Comment 生成，只登记数据库可识别的逻辑引用。在不创建 Foreign Key 的前提下，目标存在性、作用域、生命周期、删除行为和多态解析属于非数据库职责，具体实现以后续代码实施文档为准。')
[void]$relationDocument.AppendLine()
[void]$relationDocument.AppendLine("- 逻辑引用字段：$($logicalRelations.Count)")
[void]$relationDocument.AppendLine("- 可执行 SQL 孤儿检查：$($directRelations.Count)")
[void]$relationDocument.AppendLine("- 多态或代码解析引用：$($polymorphicRelations.Count)")
[void]$relationDocument.AppendLine()
[void]$relationDocument.AppendLine('| 来源字段 | 类型 | 目标 | 非数据库校验提示 | Comment |')
[void]$relationDocument.AppendLine('|---|---|---|---|---|')
foreach ($relation in $logicalRelations) {
    $target = if ($relation.Kind -eq 'POLYMORPHIC') { '由类型字段或代码注册表解析' } else { "``iam.$($relation.TargetTable).$($relation.TargetColumn)``" }
    $validation = if ($relation.Kind -eq 'POLYMORPHIC') { '校验类型白名单、目标存在、租户/业务线作用域和生命周期；负向测试未知类型与跨租户引用。' }
        elseif ($relation.Kind -eq 'ARRAY') { '逐项校验目标存在、作用域和生命周期；写入与删除前运行集合校验。' }
        else { '写入前校验目标存在、租户/业务线作用域和生命周期；删除或匿名化执行反向引用检查。' }
    [void]$relationDocument.AppendLine("| ``iam.$($relation.SourceTable).$($relation.SourceColumn)`` | ``$($relation.Kind)`` | $target | $validation | $($relation.Comment.Replace('|','\|')) |")
}

$orphanCheck = [System.Text.StringBuilder]::new()
[void]$orphanCheck.AppendLine('\set ON_ERROR_STOP on')
[void]$orphanCheck.AppendLine()
[void]$orphanCheck.AppendLine('-- 本文件由 Generate-DatabaseDocs.ps1 从 Column Comment 中的精确逻辑引用生成，请勿手工维护。')
[void]$orphanCheck.AppendLine('CREATE TEMP TABLE iam_orphan_scan AS')
[void]$orphanCheck.AppendLine('WITH orphan_scan(relation_name, orphan_count) AS (')
for ($i = 0; $i -lt $directRelations.Count; $i++) {
    $relation = $directRelations[$i]
    $prefix = if ($i -eq 0) { '    ' } else { '    UNION ALL ' }
    $relationName = "$($relation.SourceTable).$($relation.SourceColumn) -> $($relation.TargetTable).$($relation.TargetColumn)"
    if ($relation.Kind -eq 'ARRAY') {
        [void]$orphanCheck.AppendLine("${prefix}SELECT '$relationName', count(*) FROM iam.$($relation.SourceTable) s CROSS JOIN LATERAL unnest(s.$($relation.SourceColumn)) AS v(value) LEFT JOIN iam.$($relation.TargetTable) t ON t.$($relation.TargetColumn) = v.value WHERE t.$($relation.TargetColumn) IS NULL")
    } else {
        [void]$orphanCheck.AppendLine("${prefix}SELECT '$relationName', count(*) FROM iam.$($relation.SourceTable) s LEFT JOIN iam.$($relation.TargetTable) t ON t.$($relation.TargetColumn) = s.$($relation.SourceColumn) WHERE s.$($relation.SourceColumn) IS NOT NULL AND t.$($relation.TargetColumn) IS NULL")
    }
}
[void]$orphanCheck.AppendLine(')')
[void]$orphanCheck.AppendLine('SELECT relation_name, orphan_count FROM orphan_scan WHERE orphan_count > 0 ORDER BY relation_name;')
[void]$orphanCheck.AppendLine()
[void]$orphanCheck.AppendLine('DO $orphan_gate$')
[void]$orphanCheck.AppendLine('DECLARE details text;')
[void]$orphanCheck.AppendLine('BEGIN')
[void]$orphanCheck.AppendLine("    SELECT string_agg(format('%s=%s', relation_name, orphan_count), '; ' ORDER BY relation_name) INTO details FROM iam_orphan_scan;")
[void]$orphanCheck.AppendLine("    IF details IS NOT NULL THEN RAISE EXCEPTION '逻辑关系孤儿门禁失败：%', details; END IF;")
[void]$orphanCheck.AppendLine('END')
[void]$orphanCheck.AppendLine('$orphan_gate$;')
[void]$orphanCheck.AppendLine()
[void]$orphanCheck.AppendLine("SELECT 'PASS: 全部可解析逻辑引用无孤儿记录' AS result;")
[void]$orphanCheck.AppendLine('DROP TABLE iam_orphan_scan;')

$report = [System.Text.StringBuilder]::new()
[void]$report.AppendLine('# 数据库对象静态检查报告')
[void]$report.AppendLine()
[void]$report.AppendLine('> 本文件由 Migration 源码静态检查生成；数据库目录级验证仍须在 PostgreSQL 中执行 `verification/*.sql`。')
[void]$report.AppendLine()
[void]$report.AppendLine('| 检查项 | 结果 |')
[void]$report.AppendLine('|---|---|')
[void]$report.AppendLine("| 目标父表 | PASS：$($tables.Count)/113 |")
[void]$report.AppendLine("| 表 Comment | PASS：缺失 $($missingTableComments.Count) |")
[void]$report.AppendLine("| 字段 Comment | PASS：缺失 $($missingColumnComments.Count) |")
[void]$report.AppendLine("| Foreign Key 源码 | PASS：$foreignKeyMatches |")
[void]$report.AppendLine("| 业务 Trigger 源码 | PASS：$triggerMatches |")
[void]$report.AppendLine("| 持久化 Routine 源码 | PASS：$routineMatches |")
[void]$report.AppendLine("| PostgreSQL Enum 源码 | PASS：$enumMatches |")
[void]$report.AppendLine("| View / Materialized View 源码 | PASS：$viewMatches |")
[void]$report.AppendLine("| Seed 禁止业务数据目标 | PASS：$forbiddenSeedTargets |")
[void]$report.AppendLine("| Seed 敏感原文 JSON Key | PASS：$rawSecretSeedKeys |")
[void]$report.AppendLine("| 数据库需求覆盖编号 | PASS：$($requirementIds.Count)（仅编号与持久化边界索引，不代表代码实施或逐条测试覆盖） |")
[void]$report.AppendLine("| 业务模型逻辑表映射 | PASS：$($tables.Count)/113 |")
[void]$report.AppendLine("| 领域持久化范围映射 | PASS：$($tables.Count)/113 |")
[void]$report.AppendLine("| 多领域复用表权威映射 | PASS：$($sharedTables.Count)/$($sharedTables.Count) |")
[void]$report.AppendLine("| 逻辑引用字段 | PASS：$($logicalRelations.Count) |")
[void]$report.AppendLine("| 可执行孤儿检查 | PASS：$($directRelations.Count) |")
[void]$report.AppendLine("| 多态代码校验关系 | PASS：$($polymorphicRelations.Count) |")
[void]$report.AppendLine("| 分区父表定义 | PASS：$(@($tables | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Partition) }).Count)/13 |")
[void]$report.AppendLine('| PostgreSQL 实际执行 | 未验证：当前工作区未发现 `psql` 或容器运行时 |')

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$utf8 = [System.Text.UTF8Encoding]::new($false)
$finalNewLine = [Environment]::NewLine
[System.IO.File]::WriteAllText((Join-Path $outputPath '数据字典.md'), $dictionary.ToString().TrimEnd() + $finalNewLine, $utf8)
[System.IO.File]::WriteAllText((Join-Path $outputPath '表字段索引清单.md'), $inventory.ToString().TrimEnd() + $finalNewLine, $utf8)
[System.IO.File]::WriteAllText((Join-Path $outputPath '数据库对象检查报告.md'), $report.ToString().TrimEnd() + $finalNewLine, $utf8)
[System.IO.File]::WriteAllText($traceabilityPath, $traceability.ToString().TrimEnd() + $finalNewLine, $utf8)
[System.IO.File]::WriteAllText($logicalRelationPath, $relationDocument.ToString().TrimEnd() + $finalNewLine, $utf8)
[System.IO.File]::WriteAllText((Join-Path $verificationPath '006_logical_relation_orphan_check.sql'), $orphanCheck.ToString().TrimEnd() + $finalNewLine, $utf8)

Write-Output "Generated: $($tables.Count) tables; $($indexMatches.Count) indexes; $($constraintMatches.Count) constraints; $($requirementIds.Count) database coverage IDs; $($directRelations.Count) executable relations."
