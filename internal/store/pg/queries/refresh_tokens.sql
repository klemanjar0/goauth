-- name: CreateRefreshToken :one
insert into refresh_tokens (user_id, device_info, expires_at, rotated_from)
values ($1, $2, $3, $4)
returning *;
-- name: GetRefreshToken :one
select *
from refresh_tokens
where id = $1
  and revoked = false
  and expires_at > now();
-- name: UpdateRefreshTokenLastUsed :exec
update refresh_tokens
set last_used_at = now()
where id = $1;
-- name: RevokeRefreshToken :exec
update refresh_tokens
set revoked = true
where id = $1;
-- name: RevokeAllUserTokens :exec
update refresh_tokens
set revoked = true
where user_id = $1
  and revoked = false;
-- name: RevokeTokenFamily :exec
with recursive token_family as (
  select id
  from refresh_tokens
  where refresh_tokens.id = $1
  union
  select rt.id
  from refresh_tokens rt
    join token_family tf on rt.rotated_from = tf.id
)
update refresh_tokens
set revoked = true
where refresh_tokens.id in (
    select token_family.id
    from token_family
  );
-- name: CleanExpiredTokens :exec
delete from refresh_tokens
where expires_at < now();
-- name: GetUserActiveTokens :many
select *
from refresh_tokens
where user_id = $1
  and revoked = false
  and expires_at > now()
order by created_at desc;
-- name: GetRefreshTokenForUpdate :one
SELECT * FROM refresh_tokens
WHERE id = $1 AND revoked = false AND expires_at > NOW()
FOR UPDATE;