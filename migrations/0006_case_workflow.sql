ALTER TABLE cases ADD COLUMN first_response_at INTEGER;
ALTER TABLE cases ADD COLUMN resolved_at INTEGER;
ALTER TABLE cases ADD COLUMN reopen_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cases ADD COLUMN last_change_id TEXT;
CREATE INDEX idx_cases_team_due ON cases(team, status, due_at);
INSERT OR IGNORE INTO system_settings(setting_key, setting_value, updated_at)
VALUES ('case_sla_normal_hours','72',unixepoch()), ('case_sla_high_hours','24',unixepoch()), ('case_sla_urgent_hours','4',unixepoch());
ALTER TABLE approval_requests ADD COLUMN review_token TEXT;
ALTER TABLE case_attachments ADD COLUMN content_base64 TEXT;
