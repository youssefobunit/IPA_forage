-- Per-device login history visible to administrators.
create table if not exists public.forage_device_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  device_id text not null,
  device_label text not null,
  login_nonce text not null,
  logged_in_at timestamptz not null default now(),
  logged_out_at timestamptz
);
create index if not exists forage_device_sessions_latest_idx
  on public.forage_device_sessions(user_id, device_id, logged_in_at desc);
alter table public.forage_device_sessions enable row level security;
create policy "admins_read_device_sessions" on public.forage_device_sessions
  for select to authenticated using (public.is_admin());

create or replace function public.record_forage_device_login(p_label text, p_nonce text)
returns void language plpgsql security definer set search_path = public as $$
begin
  insert into public.forage_device_sessions(user_id, device_id, device_label, login_nonce)
  values(auth.uid(), public.current_forage_device_id(), coalesce(p_label,'Appareil inconnu'), p_nonce);
end;
$$;

create or replace function public.record_forage_device_logout()
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.forage_device_sessions set logged_out_at=now()
  where id=(select id from public.forage_device_sessions
    where user_id=auth.uid() and device_id=public.current_forage_device_id()
      and logged_out_at is null order by logged_in_at desc limit 1);
end;
$$;

create or replace function public.list_forage_device_activity()
returns table(id uuid, user_id uuid, email text, device_label text, is_primary boolean,
  access_status text, last_login_at timestamptz, last_logout_at timestamptz)
language sql stable security definer set search_path = public as $$
  select d.id,d.user_id,p.email,d.device_label,d.is_primary,d.access_status,
    (select s.logged_in_at from public.forage_device_sessions s where s.user_id=d.user_id and s.device_id=d.device_id order by s.logged_in_at desc limit 1),
    (select s.logged_out_at from public.forage_device_sessions s where s.user_id=d.user_id and s.device_id=d.device_id order by s.logged_in_at desc limit 1)
  from public.trusted_devices d join public.profiles p on p.id=d.user_id
  where public.is_admin() order by 7 desc nulls last;
$$;
grant execute on function public.record_forage_device_login(text,text) to authenticated;
grant execute on function public.record_forage_device_logout() to authenticated;
grant execute on function public.list_forage_device_activity() to authenticated;
