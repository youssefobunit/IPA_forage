-- Minimal identity and role layer required by the FORAGE ZOUHOUR application.
-- This migration must run before the workspace and device-access migrations.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null default '',
  full_name text not null default '',
  username text,
  role text not null default 'visitor'
    check (role in ('admin', 'operator', 'visitor', 'validation')),
  status text not null default 'active'
    check (status in ('active', 'on_leave', 'dismissed')),
  allowed_pages text[] not null default '{}',
  writable_pages text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists profiles_username_unique
  on public.profiles (lower(username))
  where username is not null and username <> '';

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin' and status = 'active'
  );
$$;

create or replace function public.is_staff()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and status = 'active'
      and role in ('admin', 'operator', 'validation')
  );
$$;

create or replace function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, full_name, username)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(
      nullif(new.raw_user_meta_data ->> 'full_name', ''),
      split_part(coalesce(new.email, ''), '@', 1)
    ),
    nullif(new.raw_user_meta_data ->> 'username', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists create_profile_after_signup on auth.users;
create trigger create_profile_after_signup
  after insert on auth.users
  for each row execute procedure public.create_profile_for_new_user();

alter table public.profiles enable row level security;

drop policy if exists "read_profiles" on public.profiles;
create policy "read_profiles"
on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());

drop policy if exists "admin_manage_profiles" on public.profiles;
create policy "admin_manage_profiles"
on public.profiles for update to authenticated
using (public.is_admin()) with check (public.is_admin());

grant execute on function public.is_admin() to authenticated;
grant execute on function public.is_staff() to authenticated;
