create table if not exists public.notice_actions (
  id uuid primary key default gen_random_uuid(),
  notice_id text not null unique,
  product text not null,
  version text,
  notice_type text not null check (notice_type in ('보안 패치','EOS')),
  severity text not null default 'info',
  title text not null,
  summary text,
  detail text,
  fixed_version text,
  published_at date,
  source_url text,
  source_name text,
  acknowledged_by uuid not null default auth.uid(),
  acknowledged_email text not null,
  acknowledged_role text not null check (acknowledged_role in ('admin','viewer')),
  acknowledged_at timestamptz not null default now(),
  plan_start_date date,
  plan_end_date date,
  next_action_date date not null,
  action_status text not null default '검토 필요' check (action_status in ('검토 필요','계획 수립','대응 중','완료')),
  updated_at timestamptz not null default now()
);

alter table public.notice_actions enable row level security;

drop policy if exists "authenticated users read notice actions" on public.notice_actions;
drop policy if exists "authenticated users acknowledge notices" on public.notice_actions;
drop policy if exists "admin updates notice actions" on public.notice_actions;

create policy "authenticated users read notice actions" on public.notice_actions
  for select to authenticated using ((auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local'));
create policy "authenticated users acknowledge notices" on public.notice_actions
  for insert to authenticated with check (
    acknowledged_by = auth.uid()
    and acknowledged_email = (auth.jwt() ->> 'email')
    and (auth.jwt() ->> 'email') in ('admin@opswatch.local','viewer@opswatch.local')
  );
create policy "admin updates notice actions" on public.notice_actions
  for update to authenticated using ((auth.jwt() ->> 'email') = 'admin@opswatch.local') with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');

drop trigger if exists notice_actions_set_updated_at on public.notice_actions;
create trigger notice_actions_set_updated_at before update on public.notice_actions
for each row execute function public.set_updated_at();

alter table public.notice_actions add column if not exists plan_start_date date;
alter table public.notice_actions add column if not exists plan_end_date date;
update public.notice_actions
set plan_start_date = coalesce(plan_start_date, acknowledged_at::date),
    plan_end_date = coalesce(plan_end_date, next_action_date)
where plan_start_date is null or plan_end_date is null;
