create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  display_name text
);

alter table public.profiles enable row level security;

create policy "users read their profile"
on public.profiles for select to authenticated
using (auth.uid() = user_id);
