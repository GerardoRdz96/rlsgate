create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  email text
);
alter table public.profiles enable row level security;
create policy "own profile read" on public.profiles
  for select to authenticated
  using (auth.uid() = user_id);
create policy "own profile write" on public.profiles
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- private bucket, served via signed URLs
insert into storage.buckets (id, name, public) values ('docs', 'docs', false);
