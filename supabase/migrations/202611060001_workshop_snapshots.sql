-- One shared workspace for the FORAGE ZOUHOUR mobile application.
-- The publishable client key is safe here because access is restricted by RLS.
create table if not exists public.workshop_snapshots (
  id text primary key check (id = 'main'),
  snapshot jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.workshop_snapshots enable row level security;

drop policy if exists "authenticated_read_workshop_snapshot"
  on public.workshop_snapshots;
create policy "authenticated_read_workshop_snapshot"
on public.workshop_snapshots
for select to authenticated
using (true);

drop policy if exists "staff_create_workshop_snapshot"
  on public.workshop_snapshots;
create policy "staff_create_workshop_snapshot"
on public.workshop_snapshots
for insert to authenticated
with check (public.is_staff());

drop policy if exists "staff_update_workshop_snapshot"
  on public.workshop_snapshots;
create policy "staff_update_workshop_snapshot"
on public.workshop_snapshots
for update to authenticated
using (public.is_staff())
with check (public.is_staff());
