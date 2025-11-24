-- name: CreatePasswordResetToken :one
insert into password_reset_tokens (user_id, token_hash, expires_at)
values ($1, $2, $3)
returning *;
-- name: GetPasswordResetToken :one
select *
from password_reset_tokens
where id = $1
    and used_at is null
    and expires_at > now();
-- name: GetPasswordResetTokenByHash :one
select *
from password_reset_tokens
where token_hash = $1
    and used_at is null
    and expires_at > now();
-- name: MarkPasswordResetTokenUsed :exec
update password_reset_tokens
set used_at = now()
where id = $1;
-- name: CleanExpiredPasswordResetTokens :exec
delete from password_reset_tokens
where expires_at < now();