-- =========================================================================
-- ZIYAFAT RESTAURANT — SCHEMA MIGRATION
-- =========================================================================
-- Run this once in the Supabase SQL Editor (Project → SQL Editor → New Query).
-- Every statement is guarded with IF NOT EXISTS / OR REPLACE, so it is safe
-- to run against a database that already has customers / orders /
-- order_items / menu_items / admin_users tables. Nothing here drops or
-- truncates existing data.
--
-- WHAT THIS ADDS AND WHY
-- ---------------------------------------------------------------------
-- 1. menu_items   → adds the columns the admin "Add / Edit Menu Item"
--                    screen and the public menu page need
--                    (image_url, available, featured, created_at, category).
-- 2. admin_users   → links a Supabase Auth user to admin status, so RLS
--                    policies can check "is the currently logged-in user
--                    an admin" instead of trusting the anon key.
-- 3. discounts     → new table for coupon codes.
-- 4. reservations  → new table for the table-booking form.
-- 5. orders        → adds discount_code / discount_amount so a coupon
--                    actually affects the stored total.
-- 6. RLS policies  → menu_items becomes publicly READABLE (needed for the
--                    storefront) but only admin-WRITABLE. orders/
--                    order_items/reservations become admin-READABLE only
--                    — right now admin.html reads them with the anon key
--                    and no login, which means (if RLS currently allows
--                    anon SELECT) every customer's name/phone/address is
--                    publicly exposed via the Supabase REST API. This
--                    migration closes that.
-- 7. RPC functions → create_restaurant_order (updated to accept a coupon
--                    code and compute the discount server-side) and
--                    validate_coupon (used by the checkout page's "Apply"
--                    button). Both are SECURITY DEFINER so they can write
--                    to tables the anon key can no longer touch directly.
-- =========================================================================


-- -------------------------------------------------------------------------
-- 1. MENU_ITEMS — add missing columns
-- -------------------------------------------------------------------------
create table if not exists public.menu_items (
    id          bigint generated always as identity primary key,
    name        text not null,
    created_at  timestamptz not null default now()
);

alter table public.menu_items
    add column if not exists description  text        not null default '',
    add column if not exists price        numeric(10,2) not null default 0,
    add column if not exists category     text        not null default 'Main Course',
    add column if not exists image_url    text        not null default '',
    add column if not exists available    boolean     not null default true,
    add column if not exists featured     boolean     not null default false;

-- Keep category values consistent with the site's category pages.
alter table public.menu_items drop constraint if exists menu_items_category_check;
alter table public.menu_items add constraint menu_items_category_check
    check (category in (
        'Cold Drinks', 'Hot Drinks', 'Mocktails',
        'Starters', 'Salads & Soups', 'Main Course',
        'Rice & Kabab', 'Afghan Specialties', 'Bread & Sides', 'Desserts'
    ));

create index if not exists idx_menu_items_category on public.menu_items (category);
create index if not exists idx_menu_items_available on public.menu_items (available);


-- -------------------------------------------------------------------------
-- 2. ADMIN_USERS — links auth.users to admin status
-- -------------------------------------------------------------------------
create table if not exists public.admin_users (
    id          uuid primary key references auth.users (id) on delete cascade,
    email       text not null,
    full_name   text,
    role        text not null default 'admin',
    created_at  timestamptz not null default now()
);

-- Helper used inside RLS policies: "is the currently authenticated user an admin?"
create or replace function public.is_admin()
returns boolean
language sql
security definer
stable
as $$
    select exists (
        select 1 from public.admin_users where user_id = auth.uid()
    );
$$;

-- IMPORTANT MANUAL STEP:
-- Create the admin's login in Supabase Dashboard → Authentication → Users
-- → Add User (email + password), then run, substituting the real email:
--
--   insert into public.admin_users (id, email, full_name)
--   select id, email, 'Restaurant Manager'
--   from auth.users
--   where email = 'owner@ziyafatrestaurant.com'
--   on conflict (id) do nothing;


-- -------------------------------------------------------------------------
-- 3. DISCOUNTS
-- -------------------------------------------------------------------------
create table if not exists public.discounts (
    id                 bigint generated always as identity primary key,
    code               text not null unique,
    discount_type      text not null check (discount_type in ('percentage','fixed')),
    discount_value     numeric(10,2) not null check (discount_value > 0),
    min_order_amount   numeric(10,2) not null default 0,
    max_discount       numeric(10,2),
    start_date         date,
    end_date           date,
    usage_limit        integer,
    times_used         integer not null default 0,
    active             boolean not null default true,
    created_at         timestamptz not null default now()
);

create index if not exists idx_discounts_code on public.discounts (upper(code));


-- -------------------------------------------------------------------------
-- 4. RESERVATIONS
-- -------------------------------------------------------------------------
create table if not exists public.reservations (
    id                bigint generated always as identity primary key,
    customer_name     text not null,
    phone             text not null,
    reservation_date  date not null,
    reservation_time  text not null,
    guests            text not null,
    special_request   text,
    status            text not null default 'Pending'
                       check (status in ('Pending','Confirmed','Completed','Cancelled')),
    created_at        timestamptz not null default now()
);


-- -------------------------------------------------------------------------
-- 5. ORDERS — add discount tracking columns (only if the table exists)
-- -------------------------------------------------------------------------
do $$
begin
    if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'orders') then
        alter table public.orders add column if not exists discount_code   text;
        alter table public.orders add column if not exists discount_amount numeric(10,2) not null default 0;
    end if;
end $$;


-- -------------------------------------------------------------------------
-- 6. ROW LEVEL SECURITY
-- -------------------------------------------------------------------------

-- MENU_ITEMS: public can read only available-relevant fields (all columns,
-- since the customer menu needs to show "Out of Stock" too); only admins
-- can write.
alter table public.menu_items enable row level security;

drop policy if exists "menu_items_public_read" on public.menu_items;
create policy "menu_items_public_read"
    on public.menu_items for select
    using (true);

drop policy if exists "menu_items_admin_write" on public.menu_items;
create policy "menu_items_admin_write"
    on public.menu_items for all
    using (public.is_admin())
    with check (public.is_admin());


-- ADMIN_USERS: an admin can read their own row (needed for the login
-- screen to confirm admin status); nobody else can read this table.
alter table public.admin_users enable row level security;

drop policy if exists "admin_users_self_read" on public.admin_users;
create policy "admin_users_self_read"
    on public.admin_users for select
    using (user_id = auth.uid());


-- DISCOUNTS: never directly readable by anon (coupon codes are validated
-- through the validate_coupon() function below, which runs as SECURITY
-- DEFINER). Admins can manage them from the dashboard.
alter table public.discounts enable row level security;

drop policy if exists "discounts_admin_all" on public.discounts;
create policy "discounts_admin_all"
    on public.discounts for all
    using (public.is_admin())
    with check (public.is_admin());


-- RESERVATIONS: anyone can INSERT (the public booking form), but only
-- admins can SELECT/UPDATE — a stranger should not be able to browse or
-- edit other guests' reservations.
alter table public.reservations enable row level security;

drop policy if exists "reservations_public_insert" on public.reservations;
create policy "reservations_public_insert"
    on public.reservations for insert
    with check (true);

drop policy if exists "reservations_admin_read" on public.reservations;
create policy "reservations_admin_read"
    on public.reservations for select
    using (public.is_admin());

drop policy if exists "reservations_admin_update" on public.reservations;
create policy "reservations_admin_update"
    on public.reservations for update
    using (public.is_admin())
    with check (public.is_admin());


-- ORDERS / ORDER_ITEMS: lock down direct SELECT to admins only. Order
-- *creation* keeps working for customers because it goes through the
-- create_restaurant_order() RPC below, which is SECURITY DEFINER and
-- therefore bypasses these SELECT-only policies for its own INSERT.
do $$
begin
    if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'orders') then
        execute 'alter table public.orders enable row level security';
        execute 'drop policy if exists "orders_admin_read" on public.orders';
        execute 'create policy "orders_admin_read" on public.orders for select using (public.is_admin())';
        execute 'drop policy if exists "orders_admin_update" on public.orders';
        execute 'create policy "orders_admin_update" on public.orders for update using (public.is_admin()) with check (public.is_admin())';
    end if;

    if exists (select 1 from information_schema.tables where table_schema = 'public' and table_name = 'order_items') then
        execute 'alter table public.order_items enable row level security';
        execute 'drop policy if exists "order_items_admin_read" on public.order_items';
        execute 'create policy "order_items_admin_read" on public.order_items for select using (public.is_admin())';
    end if;
end $$;


-- -------------------------------------------------------------------------
-- 7. RPC — validate_coupon
-- -------------------------------------------------------------------------
-- Called from the checkout page's "Apply" button. Runs as SECURITY DEFINER
-- so it can read the discounts table even though anon cannot SELECT it
-- directly — this keeps coupon logic entirely server-side.
create or replace function public.validate_coupon(
    p_code text,
    p_subtotal numeric
)
returns table (
    valid boolean,
    discount_amount numeric,
    message text
)
language plpgsql
security definer
as $$
declare
    d public.discounts%rowtype;
    computed numeric;
begin
    select * into d
    from public.discounts
    where upper(code) = upper(trim(p_code))
    limit 1;

    if not found then
        return query select false, 0::numeric, 'Invalid or expired discount code.';
        return;
    end if;

    if not d.active then
        return query select false, 0::numeric, 'Invalid or expired discount code.';
        return;
    end if;

    if d.start_date is not null and current_date < d.start_date then
        return query select false, 0::numeric, 'Invalid or expired discount code.';
        return;
    end if;

    if d.end_date is not null and current_date > d.end_date then
        return query select false, 0::numeric, 'Invalid or expired discount code.';
        return;
    end if;

    if d.usage_limit is not null and d.times_used >= d.usage_limit then
        return query select false, 0::numeric, 'This discount code has reached its usage limit.';
        return;
    end if;

    if p_subtotal < d.min_order_amount then
        return query select false, 0::numeric,
            'Minimum order of AFN ' || d.min_order_amount::text || ' required for this code.';
        return;
    end if;

    if d.discount_type = 'percentage' then
        computed := round(p_subtotal * d.discount_value / 100, 2);
    else
        computed := d.discount_value;
    end if;

    if d.max_discount is not null and computed > d.max_discount then
        computed := d.max_discount;
    end if;

    if computed > p_subtotal then
        computed := p_subtotal;
    end if;

    return query select true, computed, 'Coupon applied.';
end;
$$;

grant execute on function public.validate_coupon(text, numeric) to anon, authenticated;


-- -------------------------------------------------------------------------
-- 8. RPC — create_restaurant_order (updated for coupons)
-- -------------------------------------------------------------------------
-- NOTE: This assumes the existing create_restaurant_order() already looks
-- up real prices from menu_items by name (per order_supabase.html, which
-- only sends {name, quantity}) and inserts into orders/order_items. This
-- replacement keeps that behaviour and adds coupon handling. If your
-- existing function's column names differ, adjust the INSERT below to
-- match before running.
create or replace function public.create_restaurant_order(
    p_customer_name text,
    p_customer_phone text,
    p_order_type text,
    p_delivery_address text,
    p_notes text,
    p_payment_method text,
    p_items jsonb,
    p_coupon_code text default null
)
returns jsonb
language plpgsql
security definer
as $$
declare
    v_order_id bigint;
    v_subtotal numeric := 0;
    v_delivery_fee numeric := 0;
    v_discount numeric := 0;
    v_total numeric := 0;
    v_item jsonb;
    v_menu_item public.menu_items%rowtype;
    v_line_total numeric;
    v_coupon_check record;
begin
    if p_items is null or jsonb_array_length(p_items) = 0 then
        raise exception 'Order must contain at least one item.';
    end if;

    -- Price every line item from menu_items — never trust a price sent
    -- from the browser.
    for v_item in select * from jsonb_array_elements(p_items)
    loop
        select * into v_menu_item
        from public.menu_items
        where name = (v_item->>'name')
          and available = true
        limit 1;

        if not found then
            raise exception 'Item "%" is not available.', (v_item->>'name');
        end if;

        v_line_total := v_menu_item.price * (v_item->>'quantity')::numeric;
        v_subtotal := v_subtotal + v_line_total;
    end loop;

    if lower(p_order_type) = 'delivery' then
        v_delivery_fee := 100;
    end if;

    if p_coupon_code is not null and trim(p_coupon_code) <> '' then
        select * into v_coupon_check from public.validate_coupon(p_coupon_code, v_subtotal);

        if v_coupon_check.valid then
            v_discount := v_coupon_check.discount_amount;

            update public.discounts
            set times_used = times_used + 1
            where upper(code) = upper(trim(p_coupon_code));
        else
            raise exception '%', v_coupon_check.message;
        end if;
    end if;

    v_total := v_subtotal + v_delivery_fee - v_discount;

    insert into public.orders (
        customer_name, customer_phone, order_type, delivery_address,
        notes, payment_method, subtotal, delivery_fee, discount_amount,
        discount_code, total, status, created_at
    )
    values (
        p_customer_name, p_customer_phone, p_order_type, p_delivery_address,
        p_notes, p_payment_method, v_subtotal, v_delivery_fee, v_discount,
        nullif(trim(p_coupon_code), ''), v_total, 'NEW', now()
    )
    returning id into v_order_id;

    for v_item in select * from jsonb_array_elements(p_items)
    loop
        select * into v_menu_item
        from public.menu_items
        where name = (v_item->>'name')
        limit 1;

        insert into public.order_items (order_id, item_name, price, quantity)
        values (v_order_id, v_menu_item.name, v_menu_item.price, (v_item->>'quantity')::numeric);
    end loop;

    return jsonb_build_object(
        'order_id', v_order_id,
        'subtotal', v_subtotal,
        'delivery_fee', v_delivery_fee,
        'discount', v_discount,
        'total', v_total
    );
end;
$$;

grant execute on function public.create_restaurant_order(
    text, text, text, text, text, text, jsonb, text
) to anon, authenticated;

-- =========================================================================
-- END OF MIGRATION
-- =========================================================================
