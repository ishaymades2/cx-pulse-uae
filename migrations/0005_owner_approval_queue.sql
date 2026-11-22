-- Owner approval queue for high-impact configuration and governance changes.
CREATE TABLE IF NOT EXISTS owner_approval_requests (
 id TEXT PRIMARY KEY, requester_id TEXT NOT NULL REFERENCES users(id),
 request_type TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}',
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
 CHECK(status IN ('pending','approved','rejected')),
 reviewed_by TEXT REFERENCES users(id), review_note TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_owner_approval_status ON owner_approval_requests(status,created_at DESC);
