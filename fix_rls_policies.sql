-- Reset order policies to ONE clean, correct set.
-- Your orders table has accumulated several overlapping/conflicting policies
-- over time (some from supabase_setup.sql, some added later directly in the
-- dashboard), which no longer match what's in supabase_setup.sql. Rather than
-- trying to guess which one is blocking inserts, this drops every policy
-- found on public.orders (by exact name) and recreates a minimal, correct set.
--
-- Run this whole file in Supabase > SQL Editor > Run.

-- 1) Drop every policy currently known to exist on orders (safe if some don't exist)
drop policy if exists "public can create orders" on public.orders;
drop policy if exists "admins can read orders" on public.orders;
drop policy if exists "admins can update orders" on public.orders;
drop policy if exists "Customers can submit orders" on public.orders;
drop policy if exists "Admins can view orders" on public.orders;
drop policy if exists "Admins can update orders" on public.orders;
drop policy if exists "Admins can delete orders" on public.orders;
drop policy if exists "Allow public order inserts" on public.orders;
drop policy if exists "Allow public order select" on public.orders;

-- 2) Make sure RLS is on (it already is, this is just defensive)
alter table public.orders enable row level security;

-- 3) ONE insert policy: anyone (including anonymous customers) can create an
--    order, as long as it looks like a real new order (not pre-paid, not
--    already confirmed, and name/phone/address aren't blank).
create policy "orders_insert_public"
on public.orders
for insert
to anon, authenticated
with check (
  coalesce(customer_name, '') <> ''
  and coalesce(phone, '') <> ''
  and coalesce(address, '') <> ''
  and order_status = 'new'
  and payment_status = 'unpaid'
);

-- 4) Only logged-in admins (present in admin_users) can read orders.
create policy "orders_select_admin"
on public.orders
for select
to authenticated
using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

-- 5) Only logged-in admins can update orders (e.g. change status).
create policy "orders_update_admin"
on public.orders
for update
to authenticated
using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()))
with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

-- 6) Only logged-in admins can delete orders.
create policy "orders_delete_admin"
on public.orders
for delete
to authenticated
using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

-- 7) Table-level grants (RLS policies only apply if the role is also granted
--    the privilege at the table level).
grant usage on schema public to anon, authenticated;
grant insert on public.orders to anon, authenticated;
grant select, update, delete on public.orders to authenticated;
grant usage, select on sequence public.orders_id_seq to anon, authenticated;

-- 8) Sanity check: should show exactly 4 policies on orders afterwards.
select policyname, cmd, roles from pg_policies where tablename = 'orders';
