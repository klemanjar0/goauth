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
set email = coalesce(sqlc.narg('email'), email),
    password_hash = coalesce(sqlc.narg('password_hash'), password_hash),
    permissions = coalesce(sqlc.narg('permissions'), permissions),
    is_active = coalesce(sqlc.narg('is_active'), is_active),
    email_confirmed = coalesce(sqlc.narg('email_confirmed'), email_confirmed)
where id = $1
returning *;
-- name: UpdateUserPermissions :one
update users
set permissions = $2
where id = $1
returning *;