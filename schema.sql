-- ============================================================
-- عيادة تـحـدث — مخطط قاعدة البيانات (Supabase / Postgres)
-- شغّل هذا الملف كاملًا مرة واحدة من: Supabase Dashboard → SQL Editor → New query
-- ============================================================

create extension if not exists pgcrypto;

-- ============ PROFILES (حسابات الدكتور والموظفين) ============
-- كل صف مرتبط بحساب حقيقي في نظام المصادقة الخاص بـ Supabase (auth.users)
create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  name text not null,
  role text not null default 'staff' check (role in ('admin','staff')),
  must_change_password boolean not null default true,
  created_at timestamptz not null default now()
);

alter table profiles enable row level security;

-- كل مستخدم يقرأ ملفه الشخصي فقط...
create policy "read own profile" on profiles
  for select using (id = auth.uid());

-- ...والمدير (admin) يقرأ كل الحسابات لإدارتها
create policy "admins read all profiles" on profiles
  for select using (
    exists (select 1 from profiles p where p.id = auth.uid() and p.role = 'admin')
  );

-- كل مستخدم يعدّل صفه الشخصي فقط (الاسم / حالة "بانتظار أول دخول")
create policy "update own profile" on profiles
  for update using (id = auth.uid()) with check (id = auth.uid());

-- ============ CATEGORIES (تصنيفات المراجعين) ============
create table if not exists categories (
  id text primary key,
  name text not null,
  icon text,
  created_at timestamptz not null default now()
);
alter table categories enable row level security;
create policy "authenticated read categories"   on categories for select using (auth.role() = 'authenticated');
create policy "authenticated insert categories" on categories for insert with check (auth.role() = 'authenticated');
create policy "authenticated update categories" on categories for update using (auth.role() = 'authenticated');
create policy "authenticated delete categories" on categories for delete using (auth.role() = 'authenticated');

-- ============ PATIENTS (ملفات المراجعين) ============
create table if not exists patients (
  id text primary key,
  category_id text references categories(id) on delete set null,
  name text not null,
  phone text,
  status text not null default 'active' check (status in ('active','closed','inactive')),
  outcome text,
  close_note text,
  appointment jsonb,
  custom_fields jsonb not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table patients enable row level security;
create policy "authenticated read patients"   on patients for select using (auth.role() = 'authenticated');
create policy "authenticated insert patients" on patients for insert with check (auth.role() = 'authenticated');
create policy "authenticated update patients" on patients for update using (auth.role() = 'authenticated');
create policy "authenticated delete patients" on patients for delete using (auth.role() = 'authenticated');

-- ============================================================
-- ملاحظة: التصنيفات الافتراضية (زواج / أطفال / شخصية / مواعيد) تُضاف
-- تلقائيًا من الموقع نفسه أول مرة يُفتح فيها بحساب فيه صلاحية — لا حاجة لإدخالها هنا يدويًا.
-- ============================================================
