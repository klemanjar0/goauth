-- name: CreateAuditLog :one
insert into audit_logs (user_id, event_type, ip, ua, payload)
values (
        sqlc.narg('user_id'),
        $1,
        sqlc.narg('ip'),
        sqlc.narg('ua'),
        sqlc.narg('payload')
    )
returning *;
-- name: GetAuditLogsByUser :many
select *
from audit_logs
where user_id = $1
order by created_at desc
limit $2 offset $3;
-- name: GetAuditLogsByEventType :many
select *
from audit_logs
where event_type = $1
order by created_at desc
limit $2 offset $3;
-- name: GetRecentAuditLogs :many
select *
from audit_logs
order by created_at desc
limit $1 offset $2;
-- name: CleanOldAuditLogs :exec
delete from audit_logs
where created_at < $1;