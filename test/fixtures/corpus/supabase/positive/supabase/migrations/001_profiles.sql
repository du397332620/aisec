create table public.profiles (
  id uuid primary key,
  owner_id uuid not null
);

create policy "all profiles" on public.profiles
  for all using (true);

create table public.documents (
  id uuid primary key,
  owner_id uuid not null,
  tenant_id uuid not null
);

alter table public.documents enable row level security;

create policy "every signed-in user can read documents" on public.documents
  for select to authenticated
  using ((select auth.uid()) is not null);

create policy "tenant from editable metadata" on public.documents
  for update to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'tenant_id')::uuid = tenant_id);
