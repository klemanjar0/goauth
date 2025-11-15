drop trigger if exists users_updated_at on users;
drop function if exists update_updated_at();
drop table if exists audit_logs;
drop table if exists password_reset_tokens;
drop table if exists email_verification_tokens;
drop table if exists refresh_tokens;
drop table if exists users;