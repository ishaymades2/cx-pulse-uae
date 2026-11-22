-- Employee profiles, role-based permissions, approval workflow and manager notes.
PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN job_title TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN department TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN access_role TEXT NOT NULL DEFAULT 'agent'
  CHECK (access_role IN ('admin', 'supervisor', 'developer', 'agent'));
ALTER TABLE users ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
  CHECK (is_active IN (0, 1));

UPDATE users
SET access_role = 'admin'
WHERE role = 'admin';

UPDATE users
SET display_name = CASE
  WHEN lower(email) = 'ishaymades2@gmail.com' THEN 'Shaima'
  ELSE substr(email, 1, instr(email, '@') - 1)
END
WHERE display_name = '';

CREATE TABLE IF NOT EXISTS approval_requests (
  id TEXT PRIMARY KEY,
  requester_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  request_type TEXT NOT NULL CHECK (request_type IN ('name_change', 'role_change', 'permissions_change', 'account_change')),
  payload_json TEXT NOT NULL DEFAULT '{}',
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  reviewed_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  review_note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER
);

CREATE TABLE IF NOT EXISTS employee_notes (
  id TEXT PRIMARY KEY,
  employee_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  note_text TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'manager_only' CHECK (visibility IN ('manager_only', 'employee_visible')),
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_status_created ON approval_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_target_created ON approval_requests(target_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_employee_notes_employee_created ON employee_notes(employee_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_access_role_active ON users(access_role, is_active);
