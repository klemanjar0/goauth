-- users
create table users (
    id uuid primary key default gen_random_uuid(),
    email text unique not null,
    password_hash text not null,
    is_active bool default true,
    email_confirmed bool default false,
    created_at timestamptz default now(),
    updated_at timestamptz default now()
);
create index idx_users_email on users(email);
create index idx_users_active on users(is_active)
where is_active = true;
-- roles and permissions
create table roles (
    id serial primary key,
    name text unique not null,
    description text
);
create table permissions (
    id serial primary key,
    name text unique not null,
    description text
);
create table role_permissions (
    role_id int references roles(id) on delete cascade,
    permission_id int references permissions(id) on delete cascade,
    primary key (role_id, permission_id)
);
create table user_roles (
    user_id uuid references users(id) on delete cascade,
    role_id int references roles(id) on delete cascade,
    primary key (user_id, role_id)
);
-- refresh tokens
create table refresh_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    device_info text,
    rotated_from uuid references refresh_tokens(id),
    revoked bool default false,
    created_at timestamptz default now(),
    expires_at timestamptz not null,
    last_used_at timestamptz
);
create index idx_refresh_tokens_user_id on refresh_tokens(user_id);
create index idx_refresh_tokens_expires on refresh_tokens(expires_at)
where revoked = false;
create index idx_refresh_tokens_rotated on refresh_tokens(rotated_from)
where rotated_from is not null;
-- email verification
create table email_verification_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    token_hash text not null,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz default now()
);
create index idx_email_tokens_user on email_verification_tokens(user_id);
-- password reset
create table password_reset_tokens (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references users(id) on delete cascade,
    token_hash text not null,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz default now()
);
create index idx_password_reset_user on password_reset_tokens(user_id);
-- audit
create table audit_logs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid null,
    event_type text not null,
    ip inet,
    ua text,
    payload jsonb,
    created_at timestamptz default now()
);
create index idx_audit_user_id on audit_logs(user_id);
create index idx_audit_created on audit_logs(created_at desc);
create index idx_audit_event_type on audit_logs(event_type);
-- triggers
create or replace function update_updated_at() returns trigger as $$ begin new.updated_at = now();
return new;
end;
$$ language plpgsql;
create trigger users_updated_at before
update on users for each row execute function update_updated_at();