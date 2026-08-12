create table public.profiles (
  id uuid primary key,
  email text not null,
  display_name text
);

create policy "everybody can read profiles"
on public.profiles for select
using (true);
