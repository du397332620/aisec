create table public.profiles (
  id uuid primary key,
  owner_id uuid not null
);

alter table public.profiles enable row level security;

create policy "own profile" on public.profiles
  for select using (auth.uid() = owner_id);

create table public.documents (
  id uuid primary key,
  owner_id uuid not null,
  tenant_id uuid not null
);

alter table public.documents enable row level security;

create policy "own documents" on public.documents
  for all to authenticated
  using ((select auth.uid()) = owner_id);

create policy "trusted tenant membership" on public.documents
  for select to authenticated
  using ((auth.jwt() -> 'app_metadata' ->> 'tenant_id')::uuid = tenant_id);

create policy "restrictive signed-in gate" on public.documents
  as restrictive for select to authenticated
  using (auth.uid() is not null);

create policy "service maintenance" on public.documents
  for all to service_role using (true) with check (true);
