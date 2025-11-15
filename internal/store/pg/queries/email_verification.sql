-- name: CreateEmailVerificationToken :one
insert into email_verification_tokens (user_id, token_hash, expires_at)
values ($1, $2, $3)
returning *;
-- name: GetEmailVerificationToken :one
select *
from email_verification_tokens
where id = $1
    and used_at is null
    and expires_at > now();
-- name: MarkEmailVerificationTokenUsed :exec
update email_verification_tokens
set used_at = now()
where id = $1;
-- name: CleanExpiredEmailVerificationTokens :exec
delete from email_verification_tokens
where expires_at < now();