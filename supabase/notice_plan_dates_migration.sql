alter table public.notice_actions add column if not exists plan_start_date date;
alter table public.notice_actions add column if not exists plan_end_date date;

update public.notice_actions
set plan_start_date = coalesce(plan_start_date, acknowledged_at::date),
    plan_end_date = coalesce(plan_end_date, next_action_date)
where plan_start_date is null or plan_end_date is null;
