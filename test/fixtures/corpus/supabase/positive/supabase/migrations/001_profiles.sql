create table public.profiles (
  id uuid primary key,
  owner_id uuid not null
);

create policy "all profiles" on public.profiles
  for all using (true);
