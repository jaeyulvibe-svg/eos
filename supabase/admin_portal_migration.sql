create table if not exists public.software_master (
  id uuid primary key default gen_random_uuid(),
  product text not null,
  version text not null,
  lifecycle_slug text,
  lifecycle_url text,
  security_url text,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(product, version)
);

create table if not exists public.aa_managed_software (
  id uuid primary key default gen_random_uuid(),
  master_id uuid not null references public.software_master(id) on delete cascade,
  environment text not null default '운영',
  owner_name text,
  memo text,
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(master_id, environment)
);

alter table public.software_master enable row level security;
alter table public.aa_managed_software enable row level security;

drop policy if exists "authenticated users read software master" on public.software_master;
drop policy if exists "admin manages software master" on public.software_master;
create policy "authenticated users read software master" on public.software_master
  for select to authenticated using (true);
create policy "admin manages software master" on public.software_master
  for all to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local')
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');

drop policy if exists "authenticated users read managed software" on public.aa_managed_software;
drop policy if exists "admin manages managed software" on public.aa_managed_software;
create policy "authenticated users read managed software" on public.aa_managed_software
  for select to authenticated using (true);
create policy "admin manages managed software" on public.aa_managed_software
  for all to authenticated
  using ((auth.jwt() ->> 'email') = 'admin@opswatch.local')
  with check ((auth.jwt() ->> 'email') = 'admin@opswatch.local');

insert into public.software_master(product, version, lifecycle_slug, lifecycle_url, security_url)
values
  ('WebtoB','5',null,'https://www.tmaxsoft.com/kr/developer/notice/list','https://www.tmaxsoft.com/kr/developer/notice/list'),
  ('JEUS','7',null,'https://www.tmaxsoft.com/kr/developer/notice/list','https://www.tmaxsoft.com/kr/developer/notice/list'),
  ('JEUS','8',null,'https://www.tmaxsoft.com/kr/developer/notice/list','https://www.tmaxsoft.com/kr/developer/notice/list'),
  ('JEUS','9',null,'https://www.tmaxsoft.com/kr/developer/notice/list','https://www.tmaxsoft.com/kr/developer/notice/list'),
  ('Tomcat','7','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-7.html'),
  ('Tomcat','8.0','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-8.html'),
  ('Tomcat','8.5','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-8.html'),
  ('Tomcat','9.0','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-9.html'),
  ('Tomcat','10.0','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-10.html'),
  ('Tomcat','10.1','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-10.html'),
  ('Tomcat','11.0','tomcat','https://endoflife.date/tomcat','https://tomcat.apache.org/security-11.html'),
  ('PostgreSQL','12','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','13','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','14','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','15','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','16','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','17','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/'),
  ('PostgreSQL','18','postgresql','https://endoflife.date/postgresql','https://www.postgresql.org/support/security/')
on conflict(product, version) do update set
  lifecycle_slug=excluded.lifecycle_slug,
  lifecycle_url=excluded.lifecycle_url,
  security_url=excluded.security_url,
  enabled=true,
  updated_at=now();

