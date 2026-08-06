#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
migration_dir="$script_dir/migrations"
psql_args=("$@")

if ! command -v psql >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: 未找到 psql。' >&2
    exit 1
fi
if ! command -v shasum >/dev/null 2>&1 && ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: 未找到 shasum 或 sha256sum。' >&2
    exit 1
fi

sha256_file() {
    local file_path=$1

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_path" | awk '{print $1}'
    else
        printf '%s\n' 'ERROR: 未找到 shasum 或 sha256sum。' >&2
        return 1
    fi
}

export LC_ALL=C
shopt -s nullglob
migration_files=("$migration_dir"/*.sql)
shopt -u nullglob

if ((${#migration_files[@]} == 0)); then
    printf 'ERROR: 目录中没有 Migration：%s\n' "$migration_dir" >&2
    exit 1
fi

previous_version=''
for migration_file in "${migration_files[@]}"; do
    script_name=${migration_file##*/}
    if [[ ! $script_name =~ ^([0-9]{3})_[A-Za-z0-9_]+\.sql$ ]]; then
        printf 'ERROR: Migration 文件名不符合 NNN_name.sql：%s\n' "$script_name" >&2
        exit 1
    fi
    version=${BASH_REMATCH[1]}
    if [[ $version == "$previous_version" ]]; then
        printf 'ERROR: Migration 版本号重复：%s\n' "$version" >&2
        exit 1
    fi
    if grep -Eiq '^[[:space:]]*(BEGIN|COMMIT|ROLLBACK|START[[:space:]]+TRANSACTION)[[:space:]]*;' "$migration_file"; then
        printf 'ERROR: Migration 不得自行控制事务：%s\n' "$script_name" >&2
        exit 1
    fi
    previous_version=$version
done

psql "${psql_args[@]}" -X -v ON_ERROR_STOP=1 --single-transaction <<'SQL'
SET ROLE iam_owner;

CREATE SCHEMA IF NOT EXISTS iam_meta AUTHORIZATION iam_owner;
REVOKE ALL ON SCHEMA iam_meta FROM PUBLIC;

CREATE TABLE IF NOT EXISTS iam_meta.schema_migrations (
    version text PRIMARY KEY CONSTRAINT ck_schema_migrations_version CHECK (version ~ '^[0-9]{3}$'),
    script_name text NOT NULL UNIQUE CONSTRAINT ck_schema_migrations_script_name CHECK (script_name ~ '^[0-9]{3}_[A-Za-z0-9_]+[.]sql$'),
    checksum char(64) NOT NULL CONSTRAINT ck_schema_migrations_checksum CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_by name NOT NULL DEFAULT SESSION_USER,
    CONSTRAINT ck_schema_migrations_version_name CHECK (left(script_name, 3) = version)
);

ALTER TABLE iam_meta.schema_migrations OWNER TO iam_owner;
REVOKE ALL ON TABLE iam_meta.schema_migrations FROM PUBLIC;

COMMENT ON SCHEMA iam_meta IS 'IAM 数据库迁移等技术元数据；不属于业务模型。';
COMMENT ON TABLE iam_meta.schema_migrations IS '已成功提交的版本化 Migration 及其 SHA-256；脚本与登记在同一事务提交。';
SQL

recorded_rows=$(psql "${psql_args[@]}" -X -qAt -v ON_ERROR_STOP=1 \
    -c "SET ROLE iam_owner; SELECT version || '|' || script_name || '|' || checksum FROM iam_meta.schema_migrations ORDER BY version;")
while IFS='|' read -r recorded_version recorded_name recorded_checksum; do
    if [[ -z $recorded_version ]]; then
        continue
    fi
    if [[ ! $recorded_name =~ ^([0-9]{3})_[A-Za-z0-9_]+\.sql$ ]] || [[ ${BASH_REMATCH[1]} != "$recorded_version" ]]; then
        printf 'ERROR: 迁移账本存在非法版本或脚本名：%s|%s\n' "$recorded_version" "$recorded_name" >&2
        exit 1
    fi
    recorded_file="$migration_dir/$recorded_name"
    if [[ ! -f $recorded_file ]]; then
        printf 'ERROR: 迁移账本中的脚本已从仓库移除：%s\n' "$recorded_name" >&2
        exit 1
    fi
    actual_checksum=$(sha256_file "$recorded_file")
    if [[ $actual_checksum != "$recorded_checksum" ]]; then
        printf 'ERROR: Migration %s 的 SHA-256 与迁移账本不一致。\n' "$recorded_name" >&2
        exit 1
    fi
done <<< "$recorded_rows"

for migration_file in "${migration_files[@]}"; do
    script_name=${migration_file##*/}
    if [[ ! $script_name =~ ^([0-9]{3})_[A-Za-z0-9_]+\.sql$ ]]; then
        printf 'ERROR: Migration 文件名不符合 NNN_name.sql：%s\n' "$script_name" >&2
        exit 1
    fi

    version=${BASH_REMATCH[1]}
    checksum=$(sha256_file "$migration_file")
    recorded=$(psql "${psql_args[@]}" -X -qAt -v ON_ERROR_STOP=1 \
        -c "SET ROLE iam_owner; SELECT script_name || '|' || checksum FROM iam_meta.schema_migrations WHERE version = '$version';")

    if [[ -n $recorded ]]; then
        if [[ $recorded != "$script_name|$checksum" ]]; then
            printf 'ERROR: Migration %s 已登记但名称或 SHA-256 不一致：%s\n' "$version" "$recorded" >&2
            exit 1
        fi
        printf 'SKIP  %s\n' "$script_name"
        continue
    fi

    printf 'APPLY %s\n' "$script_name"
    psql "${psql_args[@]}" -X -v ON_ERROR_STOP=1 --single-transaction \
        -c 'SET ROLE iam_owner;' \
        -f "$migration_file" \
        -c "SET ROLE iam_owner; INSERT INTO iam_meta.schema_migrations (version, script_name, checksum) VALUES ('$version', '$script_name', '$checksum');"
done

printf '%s\n' 'PASS: 所有 Migration 已应用且 SHA-256 与迁移账本一致。'
