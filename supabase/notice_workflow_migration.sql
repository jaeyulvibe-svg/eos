alter table public.notice_actions add column if not exists assignee_name text;
alter table public.notice_actions add column if not exists reviewer_name text;
alter table public.notice_actions add column if not exists approver_name text;

alter table public.notice_actions drop constraint if exists notice_actions_action_status_check;
update public.notice_actions
set action_status = case action_status
  when '검토 필요' then '인지'
  when '계획 수립' then '영향 분석'
  when '대응 중' then '작업'
  else action_status
end;
alter table public.notice_actions
  alter column action_status set default '인지';
alter table public.notice_actions
  add constraint notice_actions_action_status_check
  check (action_status in ('인지','영향 분석','계획 승인','작업','검증','완료'));
