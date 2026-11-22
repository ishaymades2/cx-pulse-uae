import {
  isAllowedEmail,
  normalizeEmail,
  parseEmailList,
  roleForEmail,
  STATUSES,
  validateCasePayload,
} from "./validation.js";
import { hasPermission, permissionsForUser, isSupportedAccessRole, VALID_PERMISSIONS } from "./permissions.js";

const SESSION_SECONDS = 60 * 60 * 24 * 7;
const OTP_SECONDS = 10 * 60;
const RATE_WINDOW_MS = 15 * 60 * 1000;

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cache-Control": "no-store",
};

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...SECURITY_HEADERS,
      ...extraHeaders,
    },
  });
}

function withCookie(response, cookie) {
  const headers = new Headers(response.headers);
  headers.append("Set-Cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function clearSessionCookie() {
  return "__Host-cxpulse_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}

function sessionCookie(token) {
  return `__Host-cxpulse_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }
  return "";
}

function randomToken(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...data))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function randomOtp() {
  const values = crypto.getRandomValues(new Uint32Array(1));
  return String(values[0] % 1_000_000).padStart(6, "0");
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function requireDatabase(env) {
  if (!env.DB) throw new Error("D1 database binding is missing.");
  return env.DB;
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return origin === new URL(request.url).origin;
}

async function readJson(request, maxBytes = 12_000) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return { ok: false, response: json({ error: "Content-Type must be application/json." }, 415) };
  }
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > maxBytes) {
    return { ok: false, response: json({ error: "Request body is too large." }, 413) };
  }
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return { ok: false, response: json({ error: "A JSON object is required." }, 400) };
    }
    return { ok: true, body };
  } catch {
    return { ok: false, response: json({ error: "Invalid JSON body." }, 400) };
  }
}

async function rateLimit(db, key, maxCount, now = Date.now()) {
  const row = await db.prepare(
    `INSERT INTO rate_limits (rate_key, window_started_at, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(rate_key) DO UPDATE SET
       request_count = CASE
         WHEN excluded.window_started_at - rate_limits.window_started_at >= ? THEN 1
         ELSE rate_limits.request_count + 1
       END,
       window_started_at = CASE
         WHEN excluded.window_started_at - rate_limits.window_started_at >= ? THEN excluded.window_started_at
         ELSE rate_limits.window_started_at
       END
     RETURNING request_count`,
  ).bind(key, now, RATE_WINDOW_MS, RATE_WINDOW_MS).first();
  return Number(row?.request_count || 0) <= maxCount;
}

async function sendOtpEmail(env, email, code) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to: [email],
      subject: "Your CX Pulse UAE sign-in code",
      text: `Your CX Pulse UAE verification code is ${code}. It expires in 10 minutes. If you did not request this code, you can ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;color:#14263d;max-width:520px;margin:auto;padding:28px"><h2>CX Pulse UAE</h2><p>Your one-time sign-in code is:</p><div style="font-size:32px;font-weight:700;letter-spacing:8px;padding:18px;background:#f4f1ea;border-radius:12px;text-align:center">${code}</div><p>This code expires in 10 minutes. If you did not request it, ignore this email.</p></div>`,
    }),
  });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    console.error("Email provider rejected OTP delivery:", response.status, detail.slice(0, 300));
    throw new Error("OTP email delivery failed.");
  }
  const result = await response.json().catch(() => ({}));
  if (result.id) {
    console.log("Resend accepted OTP email request:", result.id);
  } else {
    console.error("Resend returned success without an email ID.");
  }
  return result.id || null;
}

async function requestOtp(request, env) {
  const db = requireDatabase(env);
  if (!env.RESEND_API_KEY || !env.FROM_EMAIL || !env.OTP_PEPPER) {
    return json({ error: "Authentication is not configured. Set RESEND_API_KEY, FROM_EMAIL and OTP_PEPPER in Worker secrets/variables." }, 503);
  }
  const parsed = await readJson(request, 2_000);
  if (!parsed.ok) return parsed.response;
  const email = normalizeEmail(parsed.body.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return json({ error: "Enter a valid email address." }, 400);
  }

  const existingUser = await db.prepare("SELECT id, is_active FROM users WHERE email = ?").bind(email).first();
  const allowed = isAllowedEmail(email, env) || Boolean(existingUser?.is_active);
  if (existingUser && !existingUser.is_active) return json({ message: "If this email is authorised, a verification code will be sent." }, 202);
  if (!allowed) {
    // Do not disclose whether an email address is on the access list.
    return json({ message: "If this email is authorised, a verification code will be sent." }, 202);
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipKey = await sha256(`ip:${ip}`);
  const emailKey = await sha256(`email:${email}`);
  if (!(await rateLimit(db, `otp-ip:${ipKey}`, 10)) ||
      !(await rateLimit(db, `otp-email:${emailKey}`, 3))) {
    return json({ error: "Too many code requests. Please wait 15 minutes and try again." }, 429);
  }

  const code = randomOtp();
  const codeHash = await sha256(`${email}:${code}:${env.OTP_PEPPER}`);
  const now = Math.floor(Date.now() / 1000);
  await db.prepare("DELETE FROM otp_codes WHERE email = ?").bind(email).run();
  await db.prepare(
    "INSERT INTO otp_codes (email, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)",
  ).bind(email, codeHash, now + OTP_SECONDS, now).run();

  try {
    await sendOtpEmail(env, email, code);
  } catch {
    await db.prepare("DELETE FROM otp_codes WHERE email = ?").bind(email).run();
    return json({ error: "We could not submit the verification email. Check the Resend API response in Worker logs." }, 502);
  }

  return json({ message: "If this email is authorised, a verification code has been sent. Check your inbox and spam folder." }, 202);
}

async function verifyOtp(request, env) {
  const db = requireDatabase(env);
  if (!env.OTP_PEPPER) return json({ error: "Authentication is not configured." }, 503);
  const parsed = await readJson(request, 2_000);
  if (!parsed.ok) return parsed.response;
  const email = normalizeEmail(parsed.body.email);
  const code = String(parsed.body.code || "").trim();
  if (!isAllowedEmail(email, env) || !/^\d{6}$/.test(code)) {
    return json({ error: "The code is invalid or has expired." }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const record = await db.prepare(
    "SELECT code_hash, expires_at, attempts FROM otp_codes WHERE email = ?",
  ).bind(email).first();

  if (!record || record.expires_at < now || record.attempts >= 5) {
    await db.prepare("DELETE FROM otp_codes WHERE email = ?").bind(email).run();
    return json({ error: "The code is invalid or has expired. Request a new code." }, 400);
  }

  await db.prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ?").bind(email).run();
  const candidate = await sha256(`${email}:${code}:${env.OTP_PEPPER}`);
  if (!safeEqual(candidate, record.code_hash)) {
    return json({ error: "The code is invalid or has expired." }, 400);
  }

  await db.prepare("DELETE FROM otp_codes WHERE email = ?").bind(email).run();
  const role = roleForEmail(email, env);
  const userId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO users (id, email, role, display_name, access_role, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(email) DO UPDATE SET updated_at = excluded.updated_at`,
  ).bind(userId, email, role, email.split("@")[0], role === "admin" ? "admin" : "agent", now, now).run();

  const user = await db.prepare("SELECT id, email, role, display_name, job_title, department, access_role, permissions_json, is_active FROM users WHERE email = ?").bind(email).first();
  const token = randomToken();
  const tokenHash = await sha256(token);
  await db.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(tokenHash, user.id, now + SESSION_SECONDS, now, now).run();

  return withCookie(
    json({ user: { id: user.id, email: user.email, role: user.role } }),
    sessionCookie(token),
  );
}

async function getSessionUser(request, env) {
  const token = getCookie(request, "__Host-cxpulse_session");
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  const db = requireDatabase(env);
  const row = await db.prepare(
    `SELECT u.id, u.email, u.role, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`,
  ).bind(tokenHash).first();
  if (!row || row.expires_at < now) {
    if (row) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  await db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?").bind(now, tokenHash).run();
  if (row.is_active === 0) return null;
  return { id: row.id, email: row.email, role: row.role, displayName: row.display_name, jobTitle: row.job_title, department: row.department, accessRole: row.access_role, permissions: permissionsForUser(row) };
}

async function logout(request, env) {
  const token = getCookie(request, "__Host-cxpulse_session");
  if (token) {
    const hash = await sha256(token);
    await requireDatabase(env).prepare("DELETE FROM sessions WHERE token_hash = ?").bind(hash).run();
  }
  return withCookie(json({ ok: true }), clearSessionCookie());
}

function caseDto(row) {
  return {
    id: row.id,
    customerName: row.customer_name,
    category: row.category,
    priority: row.priority,
    status: row.status,
    team: row.team,
    summary: row.summary,
    assignedTo: row.assigned_to,
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listCases(user, env) {
  const db = requireDatabase(env);
  const query = user.role === "admin"
    ? await db.prepare(
        "SELECT * FROM cases ORDER BY updated_at DESC LIMIT 200",
      ).all()
    : await db.prepare(
        "SELECT * FROM cases WHERE created_by = ? OR assigned_to = ? ORDER BY updated_at DESC LIMIT 200",
      ).bind(user.id, user.id).all();
  return json({ cases: (query.results || []).map(caseDto) });
}

async function createCase(request, user, env) {
  const parsed = await readJson(request);
  if (!parsed.ok) return parsed.response;
  const validated = validateCasePayload(parsed.body);
  if (!validated.ok) return json({ error: validated.error }, 400);

  const db = requireDatabase(env);
  const now = Math.floor(Date.now() / 1000);
  const id = `CX-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const value = validated.value;
  await db.prepare(
    `INSERT INTO cases
     (id, customer_name, category, priority, status, team, summary, assigned_to, created_by, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'Open', ?, ?, NULL, ?, ?, ?)`,
  ).bind(id, value.customerName, value.category, value.priority, value.team, value.summary, user.id, now, now).run();

  await db.prepare(
    "INSERT INTO audit_log (id, actor_id, action, case_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), user.id, "case.created", id, JSON.stringify({ category: value.category, priority: value.priority }), now).run();

  const row = await db.prepare("SELECT * FROM cases WHERE id = ?").bind(id).first();
  return json({ case: caseDto(row) }, 201);
}

async function updateCase(request, user, env, caseId) {
  const parsed = await readJson(request, 4_000);
  if (!parsed.ok) return parsed.response;
  const status = String(parsed.body.status || "");
  if (!STATUSES.includes(status)) return json({ error: "Choose a valid case status." }, 400);

  const db = requireDatabase(env);
  const row = await db.prepare("SELECT * FROM cases WHERE id = ?").bind(caseId).first();
  if (!row) return json({ error: "Case not found." }, 404);
  if (user.role !== "admin" && row.created_by !== user.id && row.assigned_to !== user.id) {
    return json({ error: "You do not have permission to update this case." }, 403);
  }

  const now = Math.floor(Date.now() / 1000);
  await db.prepare("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?")
    .bind(status, now, caseId).run();
  await db.prepare(
    "INSERT INTO audit_log (id, actor_id, action, case_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(crypto.randomUUID(), user.id, "case.status_updated", caseId, JSON.stringify({ from: row.status, to: status }), now).run();

  const updated = await db.prepare("SELECT * FROM cases WHERE id = ?").bind(caseId).first();
  return json({ case: caseDto(updated) });
}

async function reportSummary(user, env) {
  const db = requireDatabase(env);
  const baseSql = user.role === "admin"
    ? "SELECT status, category, created_at FROM cases"
    : "SELECT status, category, created_at FROM cases WHERE created_by = ? OR assigned_to = ?";
  const stmt = db.prepare(baseSql);
  const result = user.role === "admin" ? await stmt.all() : await stmt.bind(user.id, user.id).all();
  const rows = result.results || [];
  const total = rows.length;
  const resolved = rows.filter((row) => row.status === "Resolved").length;
  const inProgress = rows.filter((row) => row.status === "In progress").length;
  const open = rows.filter((row) => row.status === "Open").length;
  const byCategory = {};
  for (const row of rows) byCategory[row.category] = (byCategory[row.category] || 0) + 1;
  const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60;
  const createdLast30Days = rows.filter((row) => row.created_at >= thirtyDaysAgo).length;
  return json({
    total,
    resolved,
    open,
    inProgress,
    resolutionRate: total ? Math.round((resolved / total) * 1000) / 10 : 0,
    createdLast30Days,
    byCategory,
    source: "database",
  });
}


function audit(db, actorId, action, details = {}) {
  const now = Math.floor(Date.now() / 1000);
  return db.prepare("INSERT INTO audit_log (id, actor_id, action, case_id, details_json, created_at) VALUES (?, ?, ?, NULL, ?, ?)")
    .bind(crypto.randomUUID(), actorId, action, JSON.stringify(details), now).run();
}
function profileDto(row) {
  return { id: row.id, email: row.email, displayName: row.display_name, jobTitle: row.job_title, department: row.department, accessRole: row.access_role, permissions: permissionsForUser(row), isActive: Boolean(row.is_active), createdAt: row.created_at };
}
async function profileMe(user, env) {
  const row = await requireDatabase(env).prepare("SELECT * FROM users WHERE id = ?").bind(user.id).first();
  return json({ profile: profileDto(row) });
}
async function createApproval(request, user, env) {
  const parsed = await readJson(request, 3000); if (!parsed.ok) return parsed.response;
  const type = String(parsed.body.type || "");
  const reason = String(parsed.body.reason || "").trim();
  if (!["name_change"].includes(type) || reason.length < 5 || reason.length > 500) return json({ error: "Provide a valid request and reason." }, 400);
  const name = String(parsed.body.displayName || "").trim();
  if (name.length < 2 || name.length > 80) return json({ error: "Name must be between 2 and 80 characters." }, 400);
  const db = requireDatabase(env), now = Math.floor(Date.now()/1000), id = crypto.randomUUID();
  await db.prepare("INSERT INTO approval_requests (id, requester_id, target_user_id, request_type, payload_json, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .bind(id,user.id,user.id,type,JSON.stringify({displayName:name}),reason,now).run();
  await audit(db,user.id,"approval.requested",{approvalId:id,type});
  return json({ ok:true, requestId:id },201);
}
async function listApprovals(user, env) {
  if (!hasPermission(user,"staff.view")) return json({error:"Permission denied."},403);
  const q=await requireDatabase(env).prepare(`SELECT a.*, u.email AS requester_email, u.display_name AS requester_name FROM approval_requests a JOIN users u ON u.id=a.requester_id ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END, a.created_at DESC LIMIT 200`).all();
  return json({requests:q.results||[]});
}
async function reviewApproval(request,user,env,id) {
  if (user.role!=="admin") return json({error:"Only the administrator can approve requests."},403);
  const parsed=await readJson(request,3000); if(!parsed.ok)return parsed.response;
  const db=requireDatabase(env), row=await db.prepare("SELECT * FROM approval_requests WHERE id=?").bind(id).first();
  if(!row)return json({error:"Request not found."},404);
  if(row.status!=="pending")return json({error:"This request has already been reviewed."},409);
  const decision=String(parsed.body.decision||""), note=String(parsed.body.note||"").trim();
  if(!["approved","rejected"].includes(decision))return json({error:"Choose approve or reject."},400);
  const now=Math.floor(Date.now()/1000);
  if(decision==="approved" && row.request_type==="name_change"){
    const payload=JSON.parse(row.payload_json||"{}");
    await db.prepare("UPDATE users SET display_name=?, updated_at=? WHERE id=?").bind(payload.displayName,now,row.target_user_id).run();
  }
  if(decision==="approved" && row.request_type==="role_change"){
    const payload=JSON.parse(row.payload_json||"{}");
    if(!isSupportedAccessRole(payload.accessRole))return json({error:"Invalid role."},400);
    await db.prepare("UPDATE users SET access_role=?, role='agent', permissions_json=?, updated_at=? WHERE id=?").bind(payload.accessRole,JSON.stringify(payload.permissions||[]),now,row.target_user_id).run();
  }
  await db.prepare("UPDATE approval_requests SET status=?, reviewed_by=?, review_note=?, reviewed_at=? WHERE id=?").bind(decision,user.id,note,now,id).run();
  await audit(db,user.id,"approval."+decision,{approvalId:id,type:row.request_type,targetUserId:row.target_user_id});
  return json({ok:true,status:decision});
}
async function listStaff(user,env) {
  if(user.role!=="admin")return json({error:"Only the administrator can view the staff directory."},403);
  const q=await requireDatabase(env).prepare("SELECT * FROM users ORDER BY created_at ASC").all();
  return json({staff:(q.results||[]).map(profileDto)});
}
async function createStaff(request,user,env) {
  if(user.role!=="admin")return json({error:"Only the administrator can add staff."},403);
  const parsed=await readJson(request,3000);if(!parsed.ok)return parsed.response;
  const email=normalizeEmail(parsed.body.email),name=String(parsed.body.displayName||"").trim(),role=String(parsed.body.accessRole||"agent");
  if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||name.length<2||name.length>80||!isSupportedAccessRole(role))return json({error:"Enter a valid email, name and staff role."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000),id=crypto.randomUUID();
  await db.prepare("INSERT INTO users (id,email,role,display_name,job_title,department,access_role,permissions_json,is_active,created_at,updated_at) VALUES (?,?,'agent',?,'','',?,'{}',1,?,?) ON CONFLICT(email) DO NOTHING").bind(id,email,name,role,now,now).run();
  const row=await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  if(row.id!==id)return json({error:"This email is already registered."},409);
  await audit(db,user.id,"staff.created",{staffId:id,email,accessRole:role});
  return json({staff:profileDto(row)},201);
}
async function addEmployeeNote(request,user,env,targetId) {
  if(user.role!=="admin")return json({error:"Only the administrator can add employee notes."},403);
  const parsed=await readJson(request,3000);if(!parsed.ok)return parsed.response;
  const note=String(parsed.body.note||"").trim(),visibility=parsed.body.visibility==="employee_visible"?"employee_visible":"manager_only";
  if(note.length<2||note.length>2000)return json({error:"Note must be between 2 and 2,000 characters."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000),id=crypto.randomUUID();
  await db.prepare("INSERT INTO employee_notes (id,employee_id,author_id,note_text,visibility,created_at) VALUES (?,?,?,?,?,?)").bind(id,targetId,user.id,note,visibility,now).run();
  await audit(db,user.id,"employee.note_added",{employeeId:targetId,visibility});
  return json({ok:true,id},201);
}
async function listEmployeeNotes(user,env,targetId) {
  if(user.role!=="admin"&&user.id!==targetId)return json({error:"Permission denied."},403);
  const q=await requireDatabase(env).prepare("SELECT n.*,u.display_name AS author_name FROM employee_notes n JOIN users u ON u.id=n.author_id WHERE n.employee_id=? AND (n.visibility='employee_visible' OR ?='admin') ORDER BY n.created_at DESC").bind(targetId,user.role).all();
  return json({notes:q.results||[]});
}
async function managerDashboard(user,env) {
  if(user.role!=="admin")return json({error:"Administrator access required."},403);
  const db=requireDatabase(env);
  const [staff,approvals,notes,auditRows]=await Promise.all([
    db.prepare("SELECT COUNT(*) AS total, SUM(is_active) AS active FROM users").first(),
    db.prepare("SELECT COUNT(*) AS total FROM approval_requests WHERE status='pending'").first(),
    db.prepare("SELECT COUNT(*) AS total FROM employee_notes").first(),
    db.prepare("SELECT COUNT(*) AS total FROM audit_log").first()
  ]);
  return json({staff:staff?.total||0,activeStaff:staff?.active||0,pendingApprovals:approvals?.total||0,notes:notes?.total||0,auditEvents:auditRows?.total||0});
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") return new Response(null, { status: 204, headers: SECURITY_HEADERS });
  if (method !== "GET" && !isSameOrigin(request)) return json({ error: "Cross-origin request blocked." }, 403);

  if (path === "/api/health" && method === "GET") {
    try {
      const db = requireDatabase(env);
      const probe = await db.prepare("SELECT 1 AS ok").first();
      return json({
        ok: probe?.ok === 1,
        service: "cx-pulse-uae",
        version: "1.0.0",
        databaseConfigured: true,
        databaseReachable: probe?.ok === 1,
      }, probe?.ok === 1 ? 200 : 503);
    } catch (error) {
      console.error("CX Pulse health check failed:", error?.message || error);
      return json({
        ok: false,
        service: "cx-pulse-uae",
        version: "1.0.0",
        databaseConfigured: Boolean(env.DB),
        databaseReachable: false,
      }, 503);
    }
  }

  try {
    if (path === "/api/auth/request-otp" && method === "POST") return await requestOtp(request, env);
    if (path === "/api/auth/verify-otp" && method === "POST") return await verifyOtp(request, env);
    if (path === "/api/auth/logout" && method === "POST") return await logout(request, env);
    if (path === "/api/auth/me" && method === "GET") {
      const me = await getSessionUser(request, env);
      return me ? json({user:me}) : json({user:null},401);
    }

    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "Sign in to access this workspace." }, 401);

    if (path === "/api/profile" && method === "GET") return await profileMe(user,env);
    if (path === "/api/profile/name-request" && method === "POST") return await createApproval(request,user,env);
    if (path === "/api/manager/summary" && method === "GET") return await managerDashboard(user,env);
    if (path === "/api/manager/staff" && method === "GET") return await listStaff(user,env);
    if (path === "/api/manager/staff" && method === "POST") return await createStaff(request,user,env);
    if (path === "/api/manager/approvals" && method === "GET") return await listApprovals(user,env);
    if (path === "/api/manager/approvals" && method === "POST") {
      const body=await request.clone().json().catch(()=>({}));
      if(!body.id)return json({error:"Approval ID required."},400);
      return await reviewApproval(request,user,env,String(body.id));
    }
    const noteMatch=path.match(/^\/api\/manager\/staff\/([A-Za-z0-9-]+)\/notes$/);
    if(noteMatch && method==="POST")return await addEmployeeNote(request,user,env,noteMatch[1]);
    if(noteMatch && method==="GET")return await listEmployeeNotes(user,env,noteMatch[1]);
    if (path === "/api/cases" && method === "GET") return await listCases(user, env);
    if (path === "/api/cases" && method === "POST") return await createCase(request, user, env);
    if (path === "/api/reports/summary" && method === "GET") return await reportSummary(user, env);

    const match = path.match(/^\/api\/cases\/([A-Za-z0-9-]+)$/);
    if (match && method === "PATCH") return await updateCase(request, user, env, match[1]);

    return json({ error: "Endpoint not found." }, 404);
  } catch (error) {
    console.error("CX Pulse API error:", error?.message || error);
    if (String(error?.message || "").includes("D1 database binding is missing")) {
      return json({ error: "Database is not connected yet. Create the Cloudflare D1 database and bind it as DB." }, 503);
    }
    return json({ error: "The request could not be completed. Check service configuration and try again." }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response("CX Pulse UAE assets are not configured.", {
      status: 503,
      headers: { "Content-Type": "text/plain; charset=utf-8", ...SECURITY_HEADERS },
    });
  },
};
