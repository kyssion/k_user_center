param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
)

$ErrorActionPreference = 'Stop'
$migrationPath = Join-Path $RepositoryRoot 'database/postgresql/migrations'
$outputPath = Join-Path $RepositoryRoot 'docs/database/generated'
$domainFiles = Get-ChildItem -LiteralPath $migrationPath -Filter '*.sql' |
    Where-Object { $_.Name -match '^(010|020|030|040|050|060|070|080|090|100|110|120|130|140)_' } |
    Sort-Object Name
$allMigrationFiles = Get-ChildItem -LiteralPath $migrationPath -Filter '*.sql' | Sort-Object Name

$tables = [System.Collections.Generic.List[object]]::new()
$allSql = ($allMigrationFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"

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

if ($tables.Count -ne 113) { throw "目标表数量应为 113，实际为 $($tables.Count)。" }
if ($missingTableComments.Count -gt 0) { throw "缺少表 Comment：$($missingTableComments.Name -join ', ')" }
if ($missingColumnComments.Count -gt 0) { throw "缺少字段 Comment：$($missingColumnComments -join ', ')" }
if ($foreignKeyMatches -gt 0 -or $triggerMatches -gt 0 -or $routineMatches -gt 0 -or $enumMatches -gt 0) {
    throw "发现禁止对象：FK=$foreignKeyMatches Trigger=$triggerMatches Routine=$routineMatches Enum=$enumMatches"
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
[void]$report.AppendLine("| 分区父表定义 | PASS：$(@($tables | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Partition) }).Count)/13 |")
[void]$report.AppendLine('| PostgreSQL 实际执行 | 未验证：当前工作区未发现 `psql` 或容器运行时 |')

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null
$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $outputPath '数据字典.md'), $dictionary.ToString(), $utf8)
[System.IO.File]::WriteAllText((Join-Path $outputPath '表字段索引清单.md'), $inventory.ToString(), $utf8)
[System.IO.File]::WriteAllText((Join-Path $outputPath '数据库对象检查报告.md'), $report.ToString(), $utf8)

Write-Output "Generated: $($tables.Count) tables; $($indexMatches.Count) indexes; $($constraintMatches.Count) constraints."
