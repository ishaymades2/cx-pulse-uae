-- CX Pulse enterprise operations modules and immutable owner designation.
PRAGMA foreign_keys = ON;

ALTER TABLE users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0 CHECK (is_owner IN (0,1));
ALTER TABLE cases ADD COLUMN due_at INTEGER;
ALTER TABLE cases ADD COLUMN source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE cases ADD COLUMN customer_id TEXT;

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '', segment TEXT NOT NULL DEFAULT 'Standard',
  notes TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name);

CREATE TABLE IF NOT EXISTS case_comments (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id), body TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'internal' CHECK (visibility IN ('internal','customer')),
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS case_attachments (
  id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  uploaded_by TEXT NOT NULL REFERENCES users(id), file_name TEXT NOT NULL,
  content_type TEXT NOT NULL, object_key TEXT NOT NULL, size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','In progress','Done','Cancelled')),
  priority TEXT NOT NULL DEFAULT 'Normal' CHECK(priority IN ('Low','Normal','High','Urgent')),
  assigned_to TEXT REFERENCES users(id) ON DELETE SET NULL,
  team TEXT NOT NULL DEFAULT '', due_at INTEGER, created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_assignee_due ON tasks(assigned_to,due_at);
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'info',
  link TEXT NOT NULL DEFAULT '', read_at INTEGER, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user_created ON notifications(user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS knowledge_articles (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'General',
  body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Published','Archived')),
  author_id TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
  id TEXT PRIMARY KEY, case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
  customer_name TEXT NOT NULL DEFAULT '', rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  comment TEXT NOT NULL DEFAULT '', channel TEXT NOT NULL DEFAULT 'Internal',
  created_by TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '',
  manager_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  is_active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS integration_settings (
  id TEXT PRIMARY KEY, provider TEXT NOT NULL, display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Not configured', config_json TEXT NOT NULL DEFAULT '{}',
  updated_by TEXT REFERENCES users(id), updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS system_backup_log (
  id TEXT PRIMARY KEY, created_by TEXT NOT NULL REFERENCES users(id),
  backup_type TEXT NOT NULL, status TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_case_comments_case ON case_comments(case_id,created_at);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at);
CREATE INDEX IF NOT EXISTS idx_articles_status ON knowledge_articles(status,updated_at);
