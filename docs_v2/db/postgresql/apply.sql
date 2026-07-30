\set ON_ERROR_STOP 1

\echo 'Applying IAM PostgreSQL migrations...'
\ir migrations/000_preflight.sql
\ir migrations/010_foundation.sql
\ir migrations/020_identity.sql
\ir migrations/030_tenancy_federation.sql
\ir migrations/040_authentication.sql
\ir migrations/050_oauth_sessions.sql
\ir migrations/060_clients_machine.sql
\ir migrations/070_privacy.sql
\ir migrations/080_authorization.sql
\ir migrations/090_risk_control.sql
\ir migrations/100_events_audit_ops.sql
\ir migrations/110_constraints_functions.sql
\ir migrations/120_roles_rls.sql
\ir migrations/130_reference_data.sql
\echo 'IAM PostgreSQL migrations applied.'
