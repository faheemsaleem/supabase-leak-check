-- FIND RLS HOLES (read-only, changes nothing)
-- Paste into Supabase > SQL Editor > Run.
-- Every row in the result is a hole. No rows = this hole is closed.
--
--   A  table has RLS turned OFF              -> anyone with your public key can read it
--   B  policy lets EVERYONE in ("true")      -> RLS is on, but the door is still open
--   C  policy lets ANY signed-in user in     -> anyone who signs up can read/write every row
--   D  view ignores RLS                      -> it reads data with the owner's rights
--   E  materialized view in public           -> RLS never applies to these
--
-- Tables and views that belong to an extension (for example PostGIS's spatial_ref_sys)
-- are skipped: they aren't yours and you can't change them.

with mine as (
  select c.oid, c.relname, c.relkind, c.relrowsecurity, c.reloptions
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and not exists (
      select 1 from pg_depend d
      where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype = 'e'
    )
)
select 'A' as hole, relname as name, 'RLS is OFF on this table' as what_is_wrong
from mine
where relkind in ('r', 'p') and not relrowsecurity

union all

select 'B', tablename, 'Policy "' || policyname || '" lets everyone ' || lower(cmd)
from pg_policies
where schemaname = 'public'
  and (qual = 'true' or with_check = 'true')

union all

select 'C', tablename, 'Policy "' || policyname || '" lets ANY signed-in user ' || lower(cmd)
from pg_policies
where schemaname = 'public'
  and (
       -- only when that check is the WHOLE condition (a rule that adds "and user_id = auth.uid()" is fine)
       coalesce(qual, '')       ~* '^[(\s]*(select\s+)?auth\.role\(\)(\s+as\s+role)?[)\s]*=\s*''authenticated''(::text)?[)\s]*$'
    or coalesce(qual, '')       ~* '^[(\s]*(select\s+)?auth\.uid\(\)(\s+as\s+uid)?[)\s]*is\s+not\s+null[)\s]*$'
    or coalesce(with_check, '') ~* '^[(\s]*(select\s+)?auth\.role\(\)(\s+as\s+role)?[)\s]*=\s*''authenticated''(::text)?[)\s]*$'
    or coalesce(with_check, '') ~* '^[(\s]*(select\s+)?auth\.uid\(\)(\s+as\s+uid)?[)\s]*is\s+not\s+null[)\s]*$'
  )

union all

select 'D', relname, 'View ignores RLS'
from mine
where relkind = 'v'
  and coalesce(array_to_string(reloptions, ','), '') not like '%security_invoker=true%'

union all

select 'E', relname, 'Materialized view: RLS never applies'
from mine
where relkind = 'm'

order by 1, 2;
