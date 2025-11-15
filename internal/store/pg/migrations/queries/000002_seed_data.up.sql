insert into roles (name, description) values
  ('user', 'Default user role'),
  ('admin', 'Administrator role'),
  ('moderator', 'Moderator role')
on conflict (name) do nothing;

insert into permissions (name, description) values
  ('users.read', 'Read user information'),
  ('users.write', 'Create and update users'),
  ('users.delete', 'Delete users'),
  ('roles.read', 'Read roles'),
  ('roles.write', 'Manage roles'),
  ('audit.read', 'View audit logs')
on conflict (name) do nothing;

insert into role_permissions (role_id, permission_id)
select r.id, p.id
from roles r
cross join permissions p
where r.name = 'admin'
on conflict do nothing;