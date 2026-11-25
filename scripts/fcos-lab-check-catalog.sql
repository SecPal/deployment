-- SPDX-FileCopyrightText: 2026 SecPal Contributors
-- SPDX-License-Identifier: MIT

-- Run in a read-only session. Object addresses survive OID changes on restore.
SET search_path = pg_catalog;

WITH identities AS (
    SELECT c.*,
           jsonb_build_array(n.nspname,
                             CASE WHEN c.conrelid <> 0 THEN 'table' ELSE 'domain' END,
                             coalesce(t.relname, d.typname), c.conname) AS identity
    FROM pg_constraint AS c
    JOIN pg_namespace AS n ON n.oid = c.connamespace
    LEFT JOIN pg_class AS t ON t.oid = c.conrelid
    LEFT JOIN pg_type AS d ON d.oid = c.contypid
    WHERE c.contype = 'c' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
),
checks AS (
    SELECT c.identity, jsonb_build_object(
        'identity', c.identity,
        'parent', parent.identity,
        'enforced', c.conenforced,
        'validated', c.convalidated,
        'deferrable', c.condeferrable,
        'deferred', c.condeferred,
        'local', c.conislocal,
        'inheritance_count', c.coninhcount,
        'no_inherit', c.connoinherit,
        'columns', coalesce((
            SELECT jsonb_agg(jsonb_build_array(
                a.attname, format_type(a.atttypid, a.atttypmod), cn.nspname, col.collname
            ) ORDER BY k.ordinality)
            FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
            LEFT JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
            LEFT JOIN pg_collation AS col ON col.oid = a.attcollation
            LEFT JOIN pg_namespace AS cn ON cn.oid = col.collnamespace
        ), '[]'::jsonb),
        'dependencies', coalesce((
            SELECT jsonb_agg(dependency ORDER BY dependency::text COLLATE "C")
            FROM (
                SELECT jsonb_build_array(dep.deptype, target.type, target.object_names, target.object_args) AS dependency
                FROM pg_depend AS dep
                CROSS JOIN LATERAL pg_identify_object_as_address(
                    dep.refclassid, dep.refobjid, dep.refobjsubid
                ) AS target
                WHERE dep.classid = 'pg_constraint'::regclass AND dep.objid = c.oid
            ) AS edges
        ), '[]'::jsonb)
    ) AS signature
    FROM identities AS c
    LEFT JOIN identities AS parent ON parent.oid = c.conparentid
)
SELECT jsonb_build_object(
    'cluster', (SELECT system_identifier::text FROM pg_control_system()),
    'server_version_num', current_setting('server_version_num')::integer,
    'checks', coalesce(jsonb_agg(signature ORDER BY identity::text COLLATE "C"), '[]'::jsonb)
)
FROM checks;
