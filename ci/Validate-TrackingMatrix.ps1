param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

# R0-010 门禁：实施追踪矩阵行级引用校验。
# 表头契约由 docs/代码实施/Validate-DocumentationContracts.ps1 守护；
# 本脚本负责数据行的字段完整性与引用可解析性（阶段 1a 入口要求“引用有效”）。

$ErrorActionPreference = 'Stop'
$codeRoot = Join-Path $RepositoryRoot 'docs/代码实施'
$matrixPath = Join-Path $codeRoot '实施追踪矩阵.csv'

$rows = @(Import-Csv -LiteralPath $matrixPath)
if ($rows.Count -eq 0) {
    Write-Output '实施追踪矩阵暂无数据行（阶段 1a 切片进入迭代前允许为空）。'
    exit 0
}

$requiredColumns = @('requirement_id','capability_id','owner','profile','phase','invariant_ids','api_event_ids','test_ids','slo_ids','evidence_uri','exception_id')
$blueprint = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs/统一身份与访问平台建设与验收蓝图.md') -Encoding UTF8 -Raw
$errorCodes = @(Import-Csv -LiteralPath (Join-Path $codeRoot '错误码注册表.csv')).code
$testSource = Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'k_user_center/tests') -Recurse -Filter '*.cs' |
    Get-Content -Encoding UTF8 -Raw | Join-String -Separator "`n"

function Split-Ids([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @($Value -split ';' | ForEach-Object Trim | Where-Object { $_ })
}

$problems = @()
$seenKeys = @{}
foreach ($row in $rows) {
    $rowKey = "$($row.requirement_id)|$($row.capability_id)"
    if ($seenKeys.ContainsKey($rowKey)) { $problems += "重复矩阵行：$rowKey"; continue }
    $seenKeys[$rowKey] = $true

    foreach ($column in @('requirement_id','capability_id','owner','profile','phase','evidence_uri')) {
        if ([string]::IsNullOrWhiteSpace($row.$column)) { $problems += "$rowKey 缺少必填列：$column" }
    }

    # requirement_id 必须可在验收蓝图中解析（REQ-### 形式）。
    if ($row.requirement_id -and $blueprint -notmatch [regex]::Escape($row.requirement_id)) {
        $problems += "$rowKey 的需求编号未在验收蓝图登记：$($row.requirement_id)"
    }

    # evidence_uri 仅接受仓库内相对路径且文件必须存在。
    if ($row.evidence_uri) {
        if ($row.evidence_uri -match '^(?:https?|file)://') {
            $problems += "$rowKey 证据必须是仓库内相对路径：$($row.evidence_uri)"
        } elseif (-not (Test-Path -LiteralPath (Join-Path $RepositoryRoot $row.evidence_uri))) {
            $problems += "$rowKey 证据文件不存在：$($row.evidence_uri)"
        }
    }

    # invariant_ids 中形如错误码的引用必须已在错误码注册表登记。
    foreach ($invariantId in (Split-Ids $row.invariant_ids)) {
        if ($invariantId -cmatch '^[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+$' -and $invariantId -cnotin $errorCodes) {
            $problems += "$rowKey 不变量引用未登记：$invariantId"
        }
    }

    # test_ids 必须能在测试源码中解析为类型或成员名。
    foreach ($testId in (Split-Ids $row.test_ids)) {
        if ($testSource -notmatch [regex]::Escape($testId)) {
            $problems += "$rowKey 测试引用无法解析：$testId"
        }
    }
}

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Output "矩阵问题：$_" }
    throw "实施追踪矩阵校验失败，共 $($problems.Count) 处问题。"
}

Write-Output "实施追踪矩阵校验通过：$($rows.Count) 行。"
