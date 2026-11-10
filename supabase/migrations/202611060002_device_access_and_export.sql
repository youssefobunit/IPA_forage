-- FORAGE ZOUHOUR: device approval, daily access windows and export rights.
-- Run once in Supabase SQL Editor after the initial schema migration.

alter table public.profiles
  add column if not exists can_export boolean not null default false,
  add column if not exists login_start_time time,
  add column if not exists login_end_time time;

create table if not exists public.trusted_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  device_id text not null,
  device_label text not null default 'Appareil inconnu',
  is_primary boolean not null default false,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (user_id, device_id)
);

create table if not exists public.device_access_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  device_id text not null,
  device_label text not null default 'Appareil inconnu',
  request_nonce text not null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected')),
  requested_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by uuid references public.profiles(id),
  primary_on_approval boolean not null default false
);

alter table public.device_access_requests
  add column if not exists request_nonce text;

create index if not exists device_access_requests_pending_idx
  on public.device_access_requests (status, requested_at desc);

alter table public.trusted_devices enable row level security;
alter table public.device_access_requests enable row level security;

-- Supabase forwards client headers to PostgREST. The app sends only a random
-- app-installation ID, kept in encrypted device storage; no hardware serial is
-- collected because Android and iOS do not safely expose one to normal apps.
create or replace function public.current_forage_device_id()
returns text
language sql
stable
as $$
  select coalesce(
    current_setting('request.headers', true)::jsonb ->> 'x-forage-device-id',
    ''
  );
$$;

create or replace function public.current_forage_login_nonce()
returns text
language sql
stable
as $$
  select coalesce(
    current_setting('request.headers', true)::jsonb ->> 'x-forage-login-nonce',
    ''
  );
$$;

create or replace function public.is_within_login_schedule(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles p
    where p.id = p_user_id
      and p.status = 'active'
      and (
        p.login_start_time is null
        or p.login_end_time is null
        or (
          p.login_start_time <= p.login_end_time
          and timezone('Africa/Casablanca', now())::time
              between p.login_start_time and p.login_end_time
        )
        or (
          p.login_start_time > p.login_end_time
          and (
            timezone('Africa/Casablanca', now())::time >= p.login_start_time
            or timezone('Africa/Casablanca', now())::time <= p.login_end_time
          )
        )
      )
  );
$$;

create or replace function public.has_forage_app_access()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_within_login_schedule(auth.uid())
    and (
      public.is_admin()
      or exists (
        select 1
        from public.trusted_devices d
        where d.user_id = auth.uid()
          and d.device_id = public.current_forage_device_id()
          and d.is_primary
      )
      or exists (
        select 1
        from public.device_access_requests r
        where r.user_id = auth.uid()
          and r.device_id = public.current_forage_device_id()
          and r.status = 'approved'
          and r.request_nonce = public.current_forage_login_nonce()
      )
    );
$$;

-- Called after password validation. For a new device it creates one pending
-- request. A primary device enters immediately. A secondary device always
-- creates a fresh request when the app asks to log in.
create or replace function public.request_device_access(
  p_device_id text,
  p_device_label text,
  p_login_nonce text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing public.trusted_devices%rowtype;
  v_request public.device_access_requests%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if coalesce(p_device_id, '') = '' or coalesce(p_login_nonce, '') = '' then
    raise exception 'Device identifier required';
  end if;
  if not public.is_within_login_schedule(auth.uid()) then
    return jsonb_build_object('status', 'outside_schedule');
  end if;

  -- An administrator must never be locked out of the approval console.
  if public.is_admin() then
    return jsonb_build_object('status', 'approved', 'administrator', true);
  end if;

  select * into v_existing
  from public.trusted_devices
  where user_id = auth.uid() and device_id = p_device_id;

  if found and v_existing.is_primary then
    update public.trusted_devices
    set last_seen_at = now(), device_label = p_device_label
    where id = v_existing.id;
    return jsonb_build_object('status', 'approved', 'primary', true);
  end if;

  -- A secondary approval authorizes exactly one login attempt. The Flutter
  -- app sends a fresh nonce on every new password login and keeps that nonce
  -- only while polling for the administrator's decision.
  select * into v_request
  from public.device_access_requests
  where user_id = auth.uid()
    and device_id = p_device_id
    and request_nonce = p_login_nonce
  order by requested_at desc
  limit 1;

  if found then
    return jsonb_build_object('status', v_request.status, 'primary', false);
  end if;

  -- Pending and rejected rows are not silently changed. A new request is
  -- created after a rejection, so the administrator sees every attempt.
  select * into v_request
  from public.device_access_requests
  where user_id = auth.uid()
    and device_id = p_device_id
    and request_nonce = p_login_nonce
    and status = 'pending'
  order by requested_at desc
  limit 1;

  if found then
    return jsonb_build_object('status', 'pending', 'request_id', v_request.id);
  end if;

  insert into public.device_access_requests (
    user_id, device_id, device_label, request_nonce, primary_on_approval
  ) values (
    auth.uid(), p_device_id, p_device_label, p_login_nonce,
    not exists (
      select 1 from public.trusted_devices where user_id = auth.uid()
    )
  ) returning * into v_request;

  return jsonb_build_object('status', 'pending', 'request_id', v_request.id);
end;
$$;

-- Only an administrator can grant or reject a request. The first approved
-- device for a user becomes primary automatically. Each user may have at most
-- two primary devices; other approved devices require approval on each login.
create or replace function public.decide_device_access_request(
  p_request_id uuid,
  p_approve boolean,
  p_make_primary boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_request public.device_access_requests%rowtype;
  v_primary_count integer;
  v_primary boolean;
begin
  if not public.is_admin() then
    raise exception 'Administrator permission required';
  end if;

  select * into v_request
  from public.device_access_requests
  where id = p_request_id and status = 'pending'
  for update;
  if not found then
    raise exception 'Pending request not found';
  end if;

  if not p_approve then
    update public.device_access_requests
    set status = 'rejected', decided_at = now(), decided_by = auth.uid()
    where id = v_request.id;
    return jsonb_build_object('status', 'rejected');
  end if;

  select count(*) into v_primary_count
  from public.trusted_devices
  where user_id = v_request.user_id and is_primary;
  v_primary := v_request.primary_on_approval or p_make_primary;
  if v_primary and v_primary_count >= 2 then
    raise exception 'A user may have at most two primary devices';
  end if;

  insert into public.trusted_devices (
    user_id, device_id, device_label, is_primary, last_seen_at
  ) values (
    v_request.user_id, v_request.device_id, v_request.device_label,
    v_primary, now()
  ) on conflict (user_id, device_id) do update
  set device_label = excluded.device_label,
      is_primary = excluded.is_primary,
      last_seen_at = now();

  update public.device_access_requests
  set status = 'approved', decided_at = now(), decided_by = auth.uid()
  where id = v_request.id;

  return jsonb_build_object('status', 'approved', 'primary', v_primary);
end;
$$;

grant execute on function public.request_device_access(text, text, text) to authenticated;
grant execute on function public.decide_device_access_request(uuid, boolean, boolean)
  to authenticated;
grant execute on function public.has_forage_app_access() to authenticated;

-- Owners see their own requests/devices. Administrators see all requests.
drop policy if exists "users_read_own_devices" on public.trusted_devices;
create policy "users_read_own_devices"
on public.trusted_devices for select to authenticated
using (user_id = auth.uid() or public.is_admin());

drop policy if exists "admins_read_device_requests" on public.device_access_requests;
create policy "admins_read_device_requests"
on public.device_access_requests for select to authenticated
using (user_id = auth.uid() or public.is_admin());

-- Tighten the existing profile policies: team data is administrator-only,
-- while every signed-in user can still read their own profile.
drop policy if exists "read_profiles" on public.profiles;
drop policy if exists "admin_manage_profiles" on public.profiles;
create policy "read_own_or_admin_profiles"
on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());
create policy "admin_manage_profiles"
on public.profiles for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- The shared workspace is inaccessible until the account, time window and
-- approved device checks succeed. This replaces the old broad policies.
create table if not exists public.workshop_snapshots (
  id text primary key check (id = 'main'),
  snapshot jsonb not null,
  updated_at timestamptz not null default now()
);
alter table public.workshop_snapshots enable row level security;
drop policy if exists "authenticated_read_workshop_snapshot"
  on public.workshop_snapshots;
drop policy if exists "staff_create_workshop_snapshot"
  on public.workshop_snapshots;
drop policy if exists "staff_update_workshop_snapshot"
  on public.workshop_snapshots;
create policy "approved_read_workshop_snapshot"
on public.workshop_snapshots for select to authenticated
using (public.has_forage_app_access());
create policy "approved_create_workshop_snapshot"
on public.workshop_snapshots for insert to authenticated
with check (public.has_forage_app_access());
create policy "approved_update_workshop_snapshot"
on public.workshop_snapshots for update to authenticated
using (public.has_forage_app_access())
with check (public.has_forage_app_access());
