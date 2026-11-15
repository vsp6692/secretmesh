-- Local development only: creates the SecretMesh database and its two roles.
--
--   secretmesh_migrator  owns the schema; used only by `secretmesh-api migrate`.
--   secretmesh_app       runtime role; DML only, never owns tables, NOBYPASSRLS,
--                        so Row-Level Security policies always apply to it.
--
-- Production installs must create equivalent roles with strong, unique passwords.

CREATE ROLE secretmesh_migrator LOGIN PASSWORD 'secretmesh_migrator_dev';
CREATE ROLE secretmesh_app LOGIN PASSWORD 'secretmesh_app_dev'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE DATABASE secretmesh OWNER secretmesh_migrator;

\connect secretmesh

ALTER SCHEMA public OWNER TO secretmesh_migrator;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO secretmesh_app;

ALTER DEFAULT PRIVILEGES FOR ROLE secretmesh_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO secretmesh_app;
ALTER DEFAULT PRIVILEGES FOR ROLE secretmesh_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO secretmesh_app;

-- Functions (including the SECURITY DEFINER functions of ADR-0008) are
-- executable by the runtime role only, not by PUBLIC.
ALTER DEFAULT PRIVILEGES FOR ROLE secretmesh_migrator
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE secretmesh_migrator IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO secretmesh_app;
