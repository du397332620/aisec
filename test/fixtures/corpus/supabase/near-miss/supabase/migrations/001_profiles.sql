create table public.profiles (
  id uuid primary key,
  owner_id uuid not null
);

alter table public.profiles enable row level security;

create policy "own profile" on public.profiles
  for select using (auth.uid() = owner_id);
