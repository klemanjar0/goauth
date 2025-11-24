-- name: CreateUser :one
insert into users (email, password_hash, permissions)
values ($1, $2, $3)
returning *;
-- name: GetUserByID :one
select *
from users
where id = $1;
-- name: GetUserByEmail :one
select *
from users
where email = $1;
-- name: UpdateUser :one
update users
set email = coalesce(nullif($2, ''), email),
    password_hash = coalesce(nullif($3, ''), password_hash),
    permissions = coalesce($4, permissions),
    is_active = coalesce($5, is_active),
    email_confirmed = coalesce($6, email_confirmed)
where id = $1
returning *;
-- name: UpdateUserPermissions :one
update users
set permissions = $2
where id = $1
returning *;
-- name: UpdateUserPassword :one
update users
set password_hash = $2,
    updated_at = now()
where id = $1
returning *;