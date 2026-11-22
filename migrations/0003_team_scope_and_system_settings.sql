-- Add team scope and safe technical settings for the developer role.
ALTER TABLE users ADD COLUMN assigned_team TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS system_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO system_settings (setting_key, setting_value, updated_at)
VALUES
  ('allow_new_cases', 'true', unixepoch()),
  ('default_case_team', 'Customer Service', unixepoch()),
  ('case_export_enabled', 'true', unixepoch());
