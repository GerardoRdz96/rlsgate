-- profiles holds PII but RLS is never enabled -> rls-disabled (CRITICAL)
create table public.profiles (
  id uuid primary key,
  user_id uuid,
  email text not null,
  full_name text
);

-- posts: any authenticated user can read everyone's rows -> rls-authenticated (CRITICAL)
create table public.posts (
  id uuid primary key,
  user_id uuid,
  body text
);
alter table public.posts enable row level security;
create policy "read all posts" on public.posts
  for select
  using (auth.role() = 'authenticated');

-- customers readable by the anonymous public -> anon-access (CRITICAL)
create table public.customers (
  id uuid primary key,
  user_id uuid,
  email text,
  content text
);
alter table public.customers enable row level security;
create policy "anyone can read" on public.customers
  for select to anon
  using (true);

-- public storage bucket -> public-bucket (HIGH)
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
