-- Least-privilege setup for ONE Connect instance's compliance database
-- (run as the server admin). Repeat for every instance with its own names,
-- e.g. suffix _int / _ext / _qa / _dev:
--   database  <database>                 e.g. posit_compliance_int
--   logins    compliance_job_<suffix>, compliance_dashboard_<suffix>
-- Store passwords only in Connect "Vars". Never use Connect's own database or login.

-- 1) Logins
CREATE ROLE compliance_job_<suffix> LOGIN PASSWORD '<strong password>';
CREATE ROLE compliance_dashboard_<suffix> LOGIN PASSWORD '<different strong password>';
ALTER ROLE compliance_dashboard_<suffix> SET statement_timeout = '60s';
ALTER ROLE compliance_dashboard_<suffix> SET idle_in_transaction_session_timeout = '60s';

-- 2) Database access
GRANT CONNECT, CREATE ON DATABASE "<database>" TO compliance_job_<suffix>;
GRANT CONNECT ON DATABASE "<database>" TO compliance_dashboard_<suffix>;

-- 3) Schema (run while connected to <database>). The job creates its tables
--    inside it on first run; default privileges give the dashboard read access
--    to every table the job creates.
CREATE SCHEMA IF NOT EXISTS posit_compliance AUTHORIZATION compliance_job_<suffix>;
GRANT USAGE ON SCHEMA posit_compliance TO compliance_dashboard_<suffix>;
ALTER DEFAULT PRIVILEGES FOR ROLE compliance_job_<suffix> IN SCHEMA posit_compliance
    GRANT SELECT ON TABLES TO compliance_dashboard_<suffix>;
ALTER DEFAULT PRIVILEGES FOR ROLE compliance_job_<suffix> IN SCHEMA posit_compliance
    GRANT USAGE ON SEQUENCES TO compliance_dashboard_<suffix>;

-- 4) AFTER the job has run once (the tables then exist). The dashboard may:
--    add notes; record admin actions (append-only audit log);
--    add/remove apps on the Excluded / Enforce-only lists.
--    It can never edit or delete violations, history, notes or audit rows.
GRANT INSERT ON posit_compliance.branch_violation_notes TO compliance_dashboard_<suffix>;
GRANT INSERT ON posit_compliance.admin_actions TO compliance_dashboard_<suffix>;
GRANT INSERT, DELETE ON posit_compliance.scan_scope TO compliance_dashboard_<suffix>;
