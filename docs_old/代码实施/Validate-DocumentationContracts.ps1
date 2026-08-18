param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
)

$ErrorActionPreference = 'Stop'

function Assert-Columns([object[]]$Rows, [string[]]$Expected, [string]$Name) {
    if ($Rows.Count -eq 0) { throw "$Name 不能为空。" }
    $actual = @($Rows[0].PSObject.Properties.Name)
    foreach ($column in $Expected) {
        if ($column -notin $actual) { throw "$Name 缺少列：$column" }
    }
}

$codeRoot = Join-Path $RepositoryRoot 'docs/代码实施'
$errorRegistry = @(Import-Csv -LiteralPath (Join-Path $codeRoot '错误码注册表.csv'))
$stateRegistry = @(Import-Csv -LiteralPath (Join-Path $codeRoot '状态机注册表.csv'))
$matrixPath = Join-Path $codeRoot '实施追踪矩阵.csv'

Assert-Columns $errorRegistry @('kind','code','http_status','scope','retryable','exposable','description','compatibility') '错误码注册表'
Assert-Columns $stateRegistry @('state_machine','state_field','owner_domain','initial_state','terminal_states','transition_source','phase','notes') '状态机注册表'

$duplicateCodes = @($errorRegistry | Group-Object code | Where-Object Count -gt 1)
if ($duplicateCodes.Count -gt 0) { throw "错误码重复：$($duplicateCodes.Name -join ', ')" }
$duplicateMachines = @($stateRegistry | Group-Object state_machine | Where-Object Count -gt 1)
if ($duplicateMachines.Count -gt 0) { throw "状态机重复：$($duplicateMachines.Name -join ', ')" }

$registeredCodes = @($errorRegistry.code)
$normativeFiles = @(
    (Join-Path $RepositoryRoot 'docs/统一身份与访问平台建设与验收蓝图.md'),
    (Join-Path $codeRoot '全局持久化与事务规范.md')
)
$usedCodes = [System.Collections.Generic.HashSet[string]]::new()
foreach ($file in $normativeFiles) {
    foreach ($line in (Get-Content -LiteralPath $file -Encoding UTF8)) {
        if ($line -notmatch '\b(?:400|401|403|409|412|422|423|429|500|503)\b' -and $line -notmatch 'reason_code\s*=') { continue }
        foreach ($match in [regex]::Matches($line, '`(?<code>[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)`|reason_code\s*=\s*(?<reason>[A-Z][A-Z0-9_]+)')) {
            $code = if ($match.Groups['code'].Success) { $match.Groups['code'].Value } else { $match.Groups['reason'].Value }
            [void]$usedCodes.Add($code)
        }
    }
}
$unregistered = @($usedCodes | Where-Object { $_ -notin $registeredCodes })
if ($unregistered.Count -gt 0) { throw "规范正文使用了未登记错误/原因码：$($unregistered -join ', ')" }

$queryPath = Join-Path $RepositoryRoot 'docs/database/查询与索引契约.md'
$queryRows = @(Select-String -LiteralPath $queryPath -Pattern '^\| `Q-')
if ($queryRows.Count -eq 0) { throw '查询与索引契约不能为空。' }
$allowedFreshness = @('TX_CURRENT','SECURITY_SLO','QUEUE_CURRENT','HISTORICAL')
foreach ($queryRow in $queryRows) {
    $cells = @($queryRow.Line.Trim('|').Split('|') | ForEach-Object Trim)
    if ($cells.Count -ne 10) { throw "查询契约第 $($queryRow.LineNumber) 行不是 10 列。" }
    $freshness = $cells[8].Trim('`')
    if ($freshness -notin $allowedFreshness) { throw "查询契约第 $($queryRow.LineNumber) 行新鲜度非法：$freshness" }
}

$expectedMatrixHeader = 'requirement_id,capability_id,owner,profile,phase,invariant_ids,api_event_ids,test_ids,slo_ids,evidence_uri,exception_id'
$actualMatrixHeader = (Get-Content -LiteralPath $matrixPath -Encoding UTF8 | Select-Object -First 1)
if ($actualMatrixHeader -ne $expectedMatrixHeader) { throw '实施追踪矩阵表头与蓝图契约不一致。' }

$coveragePath = Join-Path $RepositoryRoot 'docs/database/需求编号与数据库持久化覆盖索引.md'
$coverage = Get-Content -LiteralPath $coveragePath -Raw -Encoding UTF8
foreach ($exampleId in @('API-AUTH-001','EVT-USER-001','INV-SESSION-001')) {
    if ($coverage.Contains("``$exampleId``")) { throw "格式示例被错误计入正式覆盖索引：$exampleId" }
}

Write-Output "PASS: errors=$($errorRegistry.Count) states=$($stateRegistry.Count) queries=$($queryRows.Count)"
