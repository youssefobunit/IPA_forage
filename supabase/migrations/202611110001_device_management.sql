-- Persistent primary/secondary device access and administrator controls.
alter table public.trusted_devices
  add column if not exists access_status text not null default 'active'
  check (access_status in ('active', 'suspended', 'blocked'));

create or replace function public.has_forage_app_access()
returns boolean language sql stable security definer set search_path = public as $$
  select public.is_within_login_schedule(auth.uid()) and (
    public.is_admin() or exists (
      select 1 from public.trusted_devices d
      where d.user_id = auth.uid()
        and d.device_id = public.current_forage_device_id()
        and d.access_status = 'active'
    )
  );
$$;

create or replace function public.request_device_access(
  p_device_id text, p_device_label text, p_login_nonce text
) returns jsonb language plpgsql security definer set search_path = public as $$
declare v_device public.trusted_devices%rowtype; v_request public.device_access_requests%rowtype;
begin
  if auth.uid() is null or coalesce(p_device_id, '') = '' or coalesce(p_login_nonce, '') = '' then
    raise exception 'Authentication required';
  end if;
  if not public.is_within_login_schedule(auth.uid()) then return jsonb_build_object('status','outside_schedule'); end if;
  if public.is_admin() then return jsonb_build_object('status','approved','administrator',true); end if;
  select * into v_device from public.trusted_devices where user_id=auth.uid() and device_id=p_device_id;
  if found then
    update public.trusted_devices set last_seen_at=now(), device_label=p_device_label where id=v_device.id;
    if v_device.access_status = 'active' then
      return jsonb_build_object('status','approved','primary',v_device.is_primary);
    end if;
    return jsonb_build_object('status','rejected');
  end if;
  select * into v_request from public.device_access_requests
   where user_id=auth.uid() and device_id=p_device_id and request_nonce=p_login_nonce limit 1;
  if found then return jsonb_build_object('status',v_request.status); end if;
  insert into public.device_access_requests(user_id,device_id,device_label,request_nonce,primary_on_approval)
  values(auth.uid(),p_device_id,p_device_label,p_login_nonce,
    not exists(select 1 from public.trusted_devices where user_id=auth.uid())) returning * into v_request;
  return jsonb_build_object('status','pending','request_id',v_request.id);
end;
$$;

create or replace function public.set_forage_device_status(
  p_device_id uuid, p_status text
) returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() or p_status not in ('active','suspended','blocked') then
    raise exception 'Administrator permission required';
  end if;
  update public.trusted_devices set access_status=p_status where id=p_device_id;
end;
$$;
grant execute on function public.set_forage_device_status(uuid,text) to authenticated;
