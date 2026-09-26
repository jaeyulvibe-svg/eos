drop policy if exists "authenticated users manage assets" on public.assets;
drop policy if exists "authenticated users manage vulnerabilities" on public.vulnerabilities;
drop policy if exists "authenticated users manage tracking targets" on public.tracking_targets;

drop policy if exists "authenticated users read assets" on public.assets;
drop policy if exists "admin inserts assets" on public.assets;
drop policy if exists "admin updates assets" on public.assets;
drop policy if exists "admin deletes assets" on public.assets;
create policy "authenticated users read assets" on public.assets for select to authenticated
  using ((auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local'));
create policy "admin inserts assets" on public.assets for insert to authenticated
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');
create policy "admin updates assets" on public.assets for update to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local')
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');
create policy "admin deletes assets" on public.assets for delete to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local');

drop policy if exists "authenticated users read vulnerabilities" on public.vulnerabilities;
drop policy if exists "admin manages vulnerabilities" on public.vulnerabilities;
create policy "authenticated users read vulnerabilities" on public.vulnerabilities for select to authenticated
  using ((auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local'));
create policy "admin manages vulnerabilities" on public.vulnerabilities for all to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local')
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');

drop policy if exists "authenticated users read sync logs" on public.sync_logs;
create policy "authenticated users read sync logs" on public.sync_logs for select to authenticated
  using ((auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local'));

drop policy if exists "authenticated users read tracking targets" on public.tracking_targets;
drop policy if exists "admin inserts tracking targets" on public.tracking_targets;
drop policy if exists "admin updates tracking targets" on public.tracking_targets;
drop policy if exists "admin deletes tracking targets" on public.tracking_targets;
create policy "authenticated users read tracking targets" on public.tracking_targets for select to authenticated
  using ((auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local'));
create policy "admin inserts tracking targets" on public.tracking_targets for insert to authenticated
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');
create policy "admin updates tracking targets" on public.tracking_targets for update to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local')
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');
create policy "admin deletes tracking targets" on public.tracking_targets for delete to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local');
