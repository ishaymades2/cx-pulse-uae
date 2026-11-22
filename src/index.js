import { handleEnterpriseApi } from "./enterprise.js";
import {
  isAllowedEmail,
  normalizeEmail,
  parseEmailList,
  roleForEmail,
  STATUSES,
  TEAMS,
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
    console.error("Email provider rejected OTP submission:", response.status);
    throw new Error("OTP email submission failed.");
  }
  const result = await response.json().catch(() => null);
  if (!result?.id) {
    console.error("Resend returned success without an email ID.");
    throw new Error("OTP email submission could not be confirmed.");
  }
  console.log("Resend accepted OTP email request:", result.id);
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
  const response = json({
    message: "If this email is authorised, check your inbox and spam folder for a verification code.",
  }, 202);
  // Use the same response for inactive, unknown and authorised addresses.
  if ((existingUser && !existingUser.is_active) || !allowed) return response;

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
  await db.prepare(
    `INSERT INTO otp_codes (email, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)
     ON CONFLICT(email) DO UPDATE SET code_hash = excluded.code_hash,
       expires_at = excluded.expires_at, attempts = 0, created_at = excluded.created_at`,
  ).bind(email, codeHash, now + OTP_SECONDS, now).run();

  try {
    await sendOtpEmail(env, email, code);
  } catch {
    await db.prepare("DELETE FROM otp_codes WHERE email = ? AND code_hash = ?").bind(email, codeHash).run();
    return json({ error: "We could not submit the verification email. Please try again later." }, 502);
  }

  return response;
}

async function verifyOtp(request, env) {
  const db = requireDatabase(env);
  if (!env.OTP_PEPPER) return json({ error: "Authentication is not configured." }, 503);
  const parsed = await readJson(request, 2_000);
  if (!parsed.ok) return parsed.response;
  const email = normalizeEmail(parsed.body.email);
  const code = String(parsed.body.code || "").trim();
  const eligible = isAllowedEmail(email, env) || Boolean(await db.prepare("SELECT id FROM users WHERE email = ? AND is_active = 1").bind(email).first());
  if (!eligible || !/^\d{6}$/.test(code)) {
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
  return issueSession(db, env, email, now);
}

async function issueSession(db, env, email, now = Math.floor(Date.now() / 1000)) {
  const role = roleForEmail(email, env);
  const isOwner = parseEmailList(env.OWNER_EMAILS || env.ADMIN_EMAILS).includes(email);
  const userId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO users (id, email, role, display_name, access_role, is_owner, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(email) DO UPDATE SET updated_at = excluded.updated_at, is_owner = excluded.is_owner,
       role = CASE WHEN excluded.is_owner = 1 THEN 'admin' ELSE users.role END,
       access_role = CASE WHEN excluded.is_owner = 1 THEN 'admin' ELSE users.access_role END`,
  ).bind(userId, email, role, role === "admin" ? "Shaima" : email.split("@")[0], role === "admin" ? "admin" : "agent", isOwner ? 1 : 0, now, now).run();

  const user = await db.prepare("SELECT id, email, role, display_name, job_title, department, access_role, permissions_json, is_active, is_owner, assigned_team FROM users WHERE email = ?").bind(email).first();
  if (!user?.is_active) return json({ error: "Account unavailable." }, 403);
  const token = randomToken();
  const tokenHash = await sha256(token);
  await db.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(tokenHash, user.id, now + SESSION_SECONDS, now, now).run();

  return withCookie(
    json({ user: { id: user.id, email: user.email, role: user.role, isOwner: Boolean(user.is_owner), displayName: user.display_name, accessRole: user.access_role, assignedTeam: user.assigned_team || "" } }),
    sessionCookie(token),
  );
}

const GOOGLE_COOKIE = "__Host-cxpulse_google";
const GOOGLE_CALLBACK = "/api/auth/google/callback";

function googleEnabled(env) {
  return Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.GOOGLE_REDIRECT_URI);
}

function googleCookie(value, maxAge) {
  return `${GOOGLE_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function redirect(location, cookie) {
  const response = new Response(null, { status: 303, headers: { ...SECURITY_HEADERS, Location: location } });
  return cookie ? withCookie(response, cookie) : response;
}

async function startGoogle(request, env) {
  if (!googleEnabled(env)) return redirect("/?signin=unavailable");
  const callback = new URL(env.GOOGLE_REDIRECT_URI);
  if (callback.origin !== new URL(request.url).origin || callback.pathname !== GOOGLE_CALLBACK) {
    return redirect("/?signin=unavailable");
  }
  const state = randomToken();
  const verifier = randomToken();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  }).toString();
  return redirect(url.href, googleCookie(`${state}.${verifier}`, 600));
}

async function finishGoogle(request, env) {
  const failure = () => redirect("/?signin=failed", googleCookie("", 0));
  const url = new URL(request.url);
  const [state, verifier] = getCookie(request, GOOGLE_COOKIE).split(".");
  const code = url.searchParams.get("code");
  if (!googleEnabled(env) || !state || !verifier || !code ||
      !safeEqual(state, url.searchParams.get("state") || "")) return failure();

  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: env.GOOGLE_REDIRECT_URI,
        code,
        code_verifier: verifier,
        grant_type: "authorization_code",
      }),
    });
    if (!tokenResponse.ok) return failure();
    const { access_token: accessToken } = await tokenResponse.json();
    if (!accessToken) return failure();
    const identityResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!identityResponse.ok) return failure();
    const identity = await identityResponse.json();
    const email = normalizeEmail(identity.email);
    const owners = parseEmailList(env.OWNER_EMAILS || env.ADMIN_EMAILS);
    if (identity.email_verified !== true || !email.endsWith("@gmail.com") || !owners.includes(email)) return failure();

    const session = await issueSession(requireDatabase(env), env, email);
    const cookie = session.headers.get("Set-Cookie");
    return cookie ? withCookie(redirect("/", googleCookie("", 0)), cookie) : failure();
  } catch {
    console.error("Google sign-in could not be completed.");
    return failure();
  }
}

async function getSessionUser(request, env) {
  const token = getCookie(request, "__Host-cxpulse_session");
  if (!token || token.length > 128) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  const db = requireDatabase(env);
  const row = await db.prepare(
    `SELECT u.id, u.email, u.role, u.display_name, u.job_title, u.department, u.access_role, u.permissions_json, u.is_active, u.is_owner, u.assigned_team, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?`,
  ).bind(tokenHash).first();
  if (!row || row.expires_at < now) {
    if (row) await db.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  await db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?").bind(now, tokenHash).run();
  if (row.is_active === 0) return null;
  return { id: row.id, email: row.email, role: row.role, isOwner: Boolean(row.is_owner), is_owner: row.is_owner, displayName: row.display_name, jobTitle: row.job_title, department: row.department, accessRole: row.access_role, assignedTeam: row.assigned_team, permissions_json: row.permissions_json, permissions: permissionsForUser(row) };
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
    dueAt: row.due_at,
    resolvedAt: row.resolved_at,
    revision: row.revision,
    assigneeName: row.assignee_name || "",
  };
}

const SLA_DEFAULTS = { Normal: 72, High: 24, Urgent: 4 };
const SLA_KEYS = Object.keys(SLA_DEFAULTS).map(priority => `case_sla_${priority.toLowerCase()}_hours`);

function teamList(user) {
  return String(user.assignedTeam || "").split(",").map(value => value.trim()).filter(Boolean);
}

function caseScope(user, action, alias = "") {
  if (user.isOwner || user.role === "admin" ||
      (user.accessRole !== "developer" && hasPermission(user, `cases.${action}_all`))) {
    return { sql: "1 = 1", args: [] };
  }
  const parts = [], args = [];
  const teams = teamList(user);
  if (teams.length && hasPermission(user, `cases.${action}_team`)) {
    parts.push(`${alias}team IN (${teams.map(() => "?").join(",")})`);
    args.push(...teams);
  }
  if (hasPermission(user, `cases.${action}_own`)) {
    parts.push(`(${alias}created_by = ? OR ${alias}assigned_to = ?)`);
    args.push(user.id, user.id);
  }
  return { sql: parts.length ? `(${parts.join(" OR ")})` : "0 = 1", args };
}

function scopedCase(db, user, id, action = "view") {
  const scope = caseScope(user, action);
  return db.prepare(`SELECT * FROM cases WHERE id = ? AND ${scope.sql}`).bind(id, ...scope.args).first();
}

async function slaHours(db) {
  const query = await db.prepare("SELECT setting_key, setting_value FROM system_settings WHERE setting_key IN (?, ?, ?)").bind(...SLA_KEYS).all();
  const stored = Object.fromEntries((query.results || []).map(row => [row.setting_key, Number(row.setting_value)]));
  return Object.fromEntries(Object.entries(SLA_DEFAULTS).map(([priority, fallback]) => [
    priority, stored[`case_sla_${priority.toLowerCase()}_hours`] || fallback,
  ]));
}

async function listCases(user, env) {
  const db = requireDatabase(env);
  const scope = caseScope(user, "view", "c.");
  const query = await db.prepare(
    `SELECT c.*, u.display_name AS assignee_name FROM cases c LEFT JOIN users u ON u.id=c.assigned_to
     WHERE ${scope.sql} ORDER BY c.updated_at DESC LIMIT 200`,
  ).bind(...scope.args).all();
  return json({ cases: (query.results || []).map(caseDto) });
}

function caseEvent(db, actor, action, id, details, now, guard = "") {
  return db.prepare(
    `INSERT INTO audit_log (id, actor_id, action, case_id, details_json, created_at)
     SELECT ?, ?, ?, ?, ?, ? ${guard ? "WHERE EXISTS (SELECT 1 FROM cases WHERE id=? AND last_change_id=?)" : ""}`,
  ).bind(crypto.randomUUID(), actor.id, action, id, JSON.stringify(details), now, ...(guard ? [id, guard] : []));
}

async function createCase(request, user, env) {
  if (!hasPermission(user, "cases.create")) return json({ error: "Permission denied." }, 403);
  const db = requireDatabase(env);
  const settings = await db.prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'allow_new_cases'").first();
  if (settings?.setting_value === "false") return json({ error: "New case creation is temporarily disabled." }, 423);
  const parsed = await readJson(request);
  if (!parsed.ok) return parsed.response;
  const validated = validateCasePayload(parsed.body);
  if (!validated.ok) return json({ error: validated.error }, 400);
  const value = validated.value;
  if (user.accessRole === "supervisor" && !teamList(user).includes(value.team)) {
    return json({ error: "Choose one of your assigned teams." }, 403);
  }

  const now = Math.floor(Date.now() / 1000);
  const id = `CX-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;
  const due = now + (await slaHours(db))[value.priority] * 3600;
  await db.batch([
    db.prepare(`INSERT INTO cases (id, customer_name, category, priority, status, team, summary, created_by, created_at, updated_at, due_at)
      VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)`)
      .bind(id, value.customerName, value.category, value.priority, value.team, value.summary, user.id, now, now, due),
    caseEvent(db, user, "case.created", id, { priority: value.priority, team: value.team, dueAt: due }, now),
  ]);
  return json({ case: caseDto(await scopedCase(db, user, id, "view") ||
    await db.prepare("SELECT * FROM cases WHERE id=?").bind(id).first()) }, 201);
}

async function prepareCaseChange(db, user, row, body, now) {
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  if (reason.length > 2000) return { error: "Reason is too long." };
  if (body.revision !== undefined && body.revision !== row.revision) return { error: "Case changed. Reload and try again.", status: 409 };
  const manage = user.isOwner || user.role === "admin" ||
    (hasPermission(user, "cases.assign_team") && teamList(user).includes(row.team));
  const status = body.status ?? row.status;
  const priority = body.priority ?? row.priority;
  const team = body.team ?? row.team;
  const assignee = body.assignedTo === "" ? null : (body.assignedTo === undefined ? row.assigned_to : body.assignedTo);
  let due = body.dueAt === undefined ? row.due_at : body.dueAt;
  if (priority !== row.priority && body.dueAt === undefined) due = row.created_at + (await slaHours(db))[priority] * 3600;
  if (!STATUSES.includes(status) || !Object.hasOwn(SLA_DEFAULTS, priority) ||
      (team !== row.team && !TEAMS.includes(team)) ||
      (due !== null && (!Number.isSafeInteger(due) || due < 1))) return { error: "Check status, priority, team and deadline." };
  const assignmentChanged = team !== row.team || assignee !== row.assigned_to;
  if ((assignmentChanged || priority !== row.priority || due !== row.due_at) && !manage) return { error: "Manager access required.", status: 403 };
  if (team !== row.team && user.role !== "admin" && !user.isOwner && !teamList(user).includes(team)) {
    return { error: "Choose one of your assigned teams.", status: 403 };
  }
  if (assignmentChanged && assignee !== null) {
    if (typeof assignee !== "string" || assignee.length > 80) return { error: "Invalid assignee." };
    const target = await db.prepare("SELECT is_active, role, assigned_team FROM users WHERE id=?").bind(assignee).first();
    if (!target?.is_active || (target.role !== "admin" && !teamList({assignedTeam: target.assigned_team}).includes(team))) {
      return { error: "Choose an active team member." };
    }
  }
  if (assignmentChanged && row.assigned_to && !reason) return { error: "Enter a reason for the transfer." };
  const reopening = row.status === "Resolved" && status !== "Resolved";
  const resolving = row.status !== "Resolved" && status === "Resolved";
  if ((reopening || resolving) && !reason) return { error: "Enter a reason to resolve or reopen this case." };
  const old = { status: row.status, priority: row.priority, team: row.team, assignedTo: row.assigned_to, dueAt: row.due_at };
  const next = { status, priority, team, assignedTo: assignee, dueAt: due };
  const changes = Object.fromEntries(Object.keys(next).filter(key => next[key] !== old[key]).map(key => [key, { from: old[key], to: next[key] }]));
  if (!Object.keys(changes).length) return { statements: [] };
  const changeId = crypto.randomUUID();
  const statements = [
    db.prepare(`UPDATE cases SET status=?, priority=?, team=?, assigned_to=?, due_at=?, updated_at=?,
      first_response_at=?, resolved_at=?, reopen_count=reopen_count+?, revision=revision+1, last_change_id=?
      WHERE id=? AND revision=?`)
      .bind(status, priority, team, assignee, due, now, row.first_response_at ?? (status !== "Open" ? now : null),
        resolving ? now : reopening ? null : row.resolved_at, reopening ? 1 : 0, changeId, row.id, row.revision),
    caseEvent(db, user, "case.updated", row.id, { changes, reason }, now, changeId),
  ];
  if (assignee && assignee !== row.assigned_to) {
    statements.push(db.prepare(`INSERT INTO notifications(id,user_id,title,body,kind,link,created_at)
      SELECT ?,?,?,?,'case',?,? WHERE EXISTS (SELECT 1 FROM cases WHERE id=? AND last_change_id=?)`)
      .bind(crypto.randomUUID(), assignee, "Case assigned", row.id, `/?case=${row.id}`, now, row.id, changeId));
  }
  return { statements };
}

async function updateCases(request, user, env, caseId) {
  const parsed = await readJson(request, 12_000);
  if (!parsed.ok) return parsed.response;
  const ids = caseId ? [caseId] : parsed.body.ids;
  if (!Array.isArray(ids) || !ids.length || ids.length > 20 || ids.some(id => typeof id !== "string" || !/^[A-Za-z0-9-]{1,80}$/.test(id))) {
    return json({ error: "Select between 1 and 20 cases." }, 400);
  }
  if (!caseId && !(user.isOwner || user.role === "admin" || hasPermission(user, "cases.assign_team"))) {
    return json({ error: "Manager access required." }, 403);
  }
  const db = requireDatabase(env), now = Math.floor(Date.now() / 1000);
  const batches = [];
  for (const id of new Set(ids)) {
    const row = await scopedCase(db, user, id, "update");
    if (!row) return json({ error: "Case not found or unavailable." }, 404);
    const change = await prepareCaseChange(db, user, row, parsed.body, now);
    if (change.error) return json({ error: change.error, caseId: id }, change.status || 400);
    if (change.statements.length) batches.push({ id, statements: change.statements });
  }
  if (batches.length) {
    const result = await db.batch(batches.flatMap(change => change.statements));
    const conflicted = [];
    let index = 0;
    for (const change of batches) {
      if (!result[index]?.meta?.changes) conflicted.push(change.id);
      index += change.statements.length;
    }
    if (conflicted.length) return json({ error: "Some cases changed before saving. Reload and review the results.", conflicted }, 409);
  }
  return caseId ? json({ case: caseDto(await db.prepare("SELECT * FROM cases WHERE id=?").bind(caseId).first()) }) : json({ updated: batches.length });
}

async function caseDetail(request, user, env, id, method) {
  const db = requireDatabase(env);
  const row = await scopedCase(db, user, id, method === "POST" ? "update" : "view");
  if (!row) return json({ error: "Case not found or unavailable." }, 404);
  if (method === "POST") {
    const parsed = await readJson(request, 6000);
    if (!parsed.ok) return parsed.response;
    const body = typeof parsed.body.note === "string" ? parsed.body.note.trim() : "";
    if (!body || body.length > 2000) return json({ error: "Enter a note up to 2,000 characters." }, 400);
    const now = Math.floor(Date.now() / 1000);
    await db.batch([
      db.prepare("INSERT INTO case_comments(id,case_id,author_id,body,created_at) VALUES(?,?,?,?,?)").bind(crypto.randomUUID(), id, user.id, body, now),
      db.prepare("UPDATE cases SET updated_at=?,first_response_at=COALESCE(first_response_at,?),revision=revision+1 WHERE id=?").bind(now, now, id),
      caseEvent(db, user, "case.note_added", id, {}, now),
    ]);
    return json({ ok: true }, 201);
  }
  const [events, notes, files] = await db.batch([
    db.prepare("SELECT a.action,a.details_json,a.created_at,u.display_name AS actor FROM audit_log a JOIN users u ON u.id=a.actor_id WHERE a.case_id=? ORDER BY a.created_at DESC LIMIT 100").bind(id),
    db.prepare("SELECT c.body,c.created_at,u.display_name AS author FROM case_comments c JOIN users u ON u.id=c.author_id WHERE c.case_id=? ORDER BY c.created_at DESC LIMIT 100").bind(id),
    db.prepare("SELECT id,file_name,content_type,size_bytes,created_at,content_base64 IS NOT NULL AS downloadable FROM case_attachments WHERE case_id=? ORDER BY created_at DESC LIMIT 100").bind(id),
  ]);
  return json({ case: caseDto(row), events: events.results || [], notes: notes.results || [], attachments: files.results || [] });
}

async function caseAttachment(request, user, env, caseId, attachmentId) {
  const db = requireDatabase(env);
  const row = await scopedCase(db, user, caseId, attachmentId ? "view" : "update");
  if (!row) return json({error:"Case not found or unavailable."},404);
  if (attachmentId) {
    const file = await db.prepare("SELECT file_name,content_base64 FROM case_attachments WHERE id=? AND case_id=?").bind(attachmentId,caseId).first();
    if (!file?.content_base64) return json({error:"Attachment content is unavailable."},404);
    const filename = encodeURIComponent(file.file_name).replace(/['()*]/g, char => "%" + char.charCodeAt(0).toString(16));
    return new Response(Uint8Array.from(atob(file.content_base64), char => char.charCodeAt(0)), {
      headers:{...SECURITY_HEADERS,"Content-Type":"application/octet-stream","Content-Disposition":"attachment; filename*=UTF-8''"+filename},
    });
  }
  const parsed = await readJson(request, 360_000);
  if (!parsed.ok) return parsed.response;
  const { name, type, content } = parsed.body;
  const allowedTypes = ["application/pdf","image/png","image/jpeg","text/plain"];
  if (typeof name !== "string" || !name.trim() || name.length > 180 || /[\u0000-\u001f]/.test(name) ||
      !allowedTypes.includes(type) || typeof content !== "string" || content.length > 350000 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(content)) {
    return json({error:"Choose a PDF, PNG, JPG or text file up to 256 KB."},400);
  }
  let bytes;
  try { bytes = atob(content).length; } catch { return json({error:"Invalid attachment."},400); }
  if (!bytes || bytes > 256 * 1024) return json({error:"Choose an attachment up to 256 KB."},400);
  const id = crypto.randomUUID(), now = Math.floor(Date.now()/1000);
  await db.batch([
    db.prepare(`INSERT INTO case_attachments(id,case_id,uploaded_by,file_name,content_type,object_key,size_bytes,created_at,content_base64)
      VALUES(?,?,?,?,?,?,?,?,?)`).bind(id,caseId,user.id,name,type,id,bytes,now,content),
    caseEvent(db,user,"case.attachment_added",caseId,{name},now),
  ]);
  return json({ok:true,id},201);
}

async function managerOperations(request, user, env) {
  if (!(user.isOwner || user.role === "admin" || hasPermission(user, "cases.assign_team"))) {
    return json({ error: "Manager access required." }, 403);
  }
  const db = requireDatabase(env);
  if (request.method === "PUT") {
    if (!user.isOwner) return json({ error: "Owner access required." }, 403);
    const parsed = await readJson(request, 1500);
    if (!parsed.ok) return parsed.response;
    const values = Object.keys(SLA_DEFAULTS).map(priority => parsed.body[priority]);
    if (values.some(value => !Number.isSafeInteger(value) || value < 1 || value > 720)) {
      return json({ error: "Set each deadline between 1 and 720 hours." }, 400);
    }
    const now = Math.floor(Date.now() / 1000);
    await db.batch([
      ...SLA_KEYS.map((key, index) => db.prepare("UPDATE system_settings SET setting_value=?,updated_by=?,updated_at=? WHERE setting_key=?").bind(String(values[index]), user.id, now, key)),
      audit(db, user.id, "case.sla_updated", parsed.body),
    ]);
    return json({ ok: true });
  }
  const scope = caseScope(user, "view", "c.");
  const now = Math.floor(Date.now() / 1000);
  const day = 86400, start = Math.floor((now + 14400) / day) * day - 14400;
  const [stats, workload, attention, staff] = await db.batch([
    db.prepare(`SELECT COUNT(CASE WHEN c.created_at>=? THEN 1 END) AS newToday,
      COUNT(CASE WHEN c.status!='Resolved' AND c.due_at<? THEN 1 END) AS overdue,
      COUNT(CASE WHEN c.status!='Resolved' AND c.due_at BETWEEN ? AND ? THEN 1 END) AS dueSoon,
      COUNT(CASE WHEN c.status!='Resolved' THEN 1 END) AS pending,
      COUNT(CASE WHEN c.resolved_at>=? THEN 1 END) AS resolvedToday FROM cases c WHERE ${scope.sql}`)
      .bind(start, now, now, now + day, start, ...scope.args),
    db.prepare(`SELECT u.display_name AS name,COUNT(*) AS active,SUM(c.priority='Urgent') AS urgent FROM cases c
      LEFT JOIN users u ON u.id=c.assigned_to WHERE ${scope.sql} AND c.status!='Resolved' GROUP BY c.assigned_to ORDER BY active DESC`).bind(...scope.args),
    db.prepare(`SELECT c.* FROM cases c WHERE ${scope.sql} AND c.status!='Resolved'
      AND (c.due_at<=? OR (c.priority='Urgent' AND c.assigned_to IS NULL) OR c.updated_at<=?)
      ORDER BY COALESCE(c.due_at,2147483647),c.updated_at LIMIT 50`).bind(...scope.args, now + day, now - 2 * day),
    db.prepare("SELECT id,display_name,assigned_team,role FROM users WHERE is_active=1 ORDER BY display_name"),
  ]);
  const teams = teamList(user), all = user.isOwner || user.role === "admin";
  return json({ stats: stats.results[0], workload: workload.results, attention: attention.results.map(caseDto),
    staff: staff.results.filter(row => all || teamList({assignedTeam: row.assigned_team}).some(team => teams.includes(team))),
    sla: user.isOwner ? await slaHours(db) : null });
}

async function reportSummary(user, env, url) {
  const db = requireDatabase(env);
  const scope = caseScope(user, "view");
  if (!["own", "team", "all"].some(level => hasPermission(user, `reports.view_${level}`)) && !user.isOwner) {
    return json({ error: "Permission denied." }, 403);
  }
  const team = url.searchParams.get("team") || "";
  const category = url.searchParams.get("category") || "";
  const date = name => {
    const value = url.searchParams.get(name);
    return value && /^\d{4}-\d{2}-\d{2}$/.test(value) ? Date.parse(`${value}T00:00:00+04:00`) / 1000 : null;
  };
  const from = date("from"), to = date("to");
  if ((url.searchParams.has("from") && !Number.isFinite(from)) ||
      (url.searchParams.has("to") && !Number.isFinite(to)) || (from !== null && to !== null && from > to)) {
    return json({ error: "Check report dates." }, 400);
  }
  const where = `${scope.sql} AND (?='' OR team=?) AND (?='' OR category=?)
    AND (? IS NULL OR created_at>=?) AND (? IS NULL OR created_at<?)`;
  const args = [...scope.args, team, team, category, category, from, from, to, to === null ? null : to + 86400];
  if (url.searchParams.get("format") === "csv") {
    const setting = await db.prepare("SELECT setting_value FROM system_settings WHERE setting_key='case_export_enabled'").first();
    if (setting?.setting_value === "false" || !hasPermission(user, "reports.export")) return json({ error: "Export is unavailable." }, 403);
    const result = await db.prepare(`SELECT id,customer_name,category,priority,status,team,created_at,due_at,first_response_at,resolved_at,reopen_count FROM cases WHERE ${where} ORDER BY created_at DESC LIMIT 10001`).bind(...args).all();
    if (result.results.length > 10000) return json({ error: "Narrow the date range to export fewer than 10,001 cases." }, 400);
    const csv = value => '"' + String(value ?? "").replace(/^[\s]*[=+\-@\t\r]/, match => "'" + match).replaceAll('"','""') + '"';
    const columns = ["id","customer_name","category","priority","status","team","created_at","due_at","first_response_at","resolved_at","reopen_count"];
    const body = [columns, ...result.results.map(row => columns.map(key => row[key]))].map(row => row.map(csv).join(",")).join("\r\n");
    return new Response("\ufeff" + body, { headers: { ...SECURITY_HEADERS, "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="cx-pulse-report.csv"' } });
  }
  const recent = Math.floor(Date.now()/1000) - 30*86400;
  const [summary, categories, teams] = await db.batch([
    db.prepare(`SELECT COUNT(*) AS total,COUNT(CASE WHEN status='Resolved' THEN 1 END) AS resolved,
      COUNT(CASE WHEN status='Open' THEN 1 END) AS open,COUNT(CASE WHEN status='In progress' THEN 1 END) AS inProgress,
      COUNT(CASE WHEN created_at>=? THEN 1 END) AS createdLast30Days,COUNT(first_response_at) AS firstResponseSample,
      AVG(first_response_at-created_at) AS firstResponseSeconds,COUNT(resolved_at) AS resolutionSample,
      AVG(resolved_at-created_at) AS resolutionSeconds,
      COUNT(CASE WHEN resolved_at IS NOT NULL AND due_at IS NOT NULL THEN 1 END) AS slaSample,
      COUNT(CASE WHEN resolved_at<=due_at THEN 1 END) AS metSla,COALESCE(SUM(reopen_count),0) AS reopened
      FROM cases WHERE ${where}`).bind(recent,...args),
    db.prepare(`SELECT category,COUNT(*) AS total FROM cases WHERE ${where} GROUP BY category ORDER BY total DESC`).bind(...args),
    db.prepare(`SELECT team,COUNT(*) AS total,COUNT(first_response_at) AS firstResponseSample,
      AVG(first_response_at-created_at) AS firstResponseSeconds,COUNT(resolved_at) AS resolutionSample,
      AVG(resolved_at-created_at) AS resolutionSeconds FROM cases WHERE ${where} GROUP BY team ORDER BY total DESC`).bind(...args),
  ]);
  const data = summary.results[0];
  return json({ ...data, resolutionRate: data.total ? Math.round(data.resolved / data.total * 1000) / 10 : 0,
    byCategory: Object.fromEntries(categories.results.map(row => [row.category,row.total])), byTeam: teams.results,
    canExport: hasPermission(user, "reports.export"), source: "database" });
}

function audit(db, actorId, action, details = {}) {
  const now = Math.floor(Date.now() / 1000);
  return db.prepare("INSERT INTO audit_log (id, actor_id, action, case_id, details_json, created_at) VALUES (?, ?, ?, NULL, ?, ?)")
    .bind(crypto.randomUUID(), actorId, action, JSON.stringify(details), now).run();
}
function profileDto(row) {
  return { id: row.id, email: row.email, displayName: row.display_name, jobTitle: row.job_title, department: row.department, accessRole: row.access_role, assignedTeam: row.assigned_team || "", permissions: permissionsForUser(row), isActive: Boolean(row.is_active), createdAt: row.created_at };
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
function inManagedTeam(user, assignedTeam) {
  return teamList({ assignedTeam }).some(team => teamList(user).includes(team));
}

async function listApprovals(user, env) {
  const all = user.role === "admin" || user.isOwner;
  if (!all && !hasPermission(user, "approvals.view_team")) return json({error:"Permission denied."},403);
  const db = requireDatabase(env);
  const rows = (await db.prepare(`SELECT a.*, u.email AS requester_email, u.display_name AS requester_name, u.assigned_team
    FROM approval_requests a JOIN users u ON u.id=a.requester_id
    ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END, a.created_at DESC`).all()).results;
  return json({requests:rows.filter(row => all || (row.request_type === "name_change" && inManagedTeam(user,row.assigned_team))).slice(0,200),
    canReview:all || hasPermission(user,"approvals.review_team")});
}
async function reviewApproval(request,user,env,id) {
  const all = user.role === "admin" || user.isOwner;
  if (!all && !hasPermission(user,"approvals.review_team")) return json({error:"Permission denied."},403);
  const parsed=await readJson(request,3000); if(!parsed.ok)return parsed.response;
  const db=requireDatabase(env);
  const row=await db.prepare(`SELECT a.*,u.assigned_team,u.role,u.is_owner FROM approval_requests a
    JOIN users u ON u.id=a.target_user_id WHERE a.id=?`).bind(id).first();
  if(!row || (!all && (row.request_type!=="name_change" || row.is_owner || row.role==="admin" || !inManagedTeam(user,row.assigned_team)))) {
    return json({error:"Request not found or unavailable."},404);
  }
  if(row.status!=="pending")return json({error:"This request has already been reviewed."},409);
  const decision=String(parsed.body.decision||""), note=String(parsed.body.note||"").trim();
  if(!["approved","rejected"].includes(decision) || note.length>2000)return json({error:"Choose approve or reject and check the review note."},400);
  const now=Math.floor(Date.now()/1000), reviewId=crypto.randomUUID();
  const guard="EXISTS (SELECT 1 FROM approval_requests WHERE id=? AND status=? AND reviewed_by=? AND review_token=?)";
  const bindGuard=[id,decision,user.id,reviewId];
  const statements=[db.prepare("UPDATE approval_requests SET status=?,reviewed_by=?,review_note=?,reviewed_at=?,review_token=? WHERE id=? AND status='pending'")
    .bind(decision,user.id,note,now,reviewId,id)];
  if(decision==="approved" && row.request_type==="name_change"){
    const payload=JSON.parse(row.payload_json||"{}");
    statements.push(db.prepare(`UPDATE users SET display_name=?,updated_at=? WHERE id=? AND ${guard}`).bind(payload.displayName,now,row.target_user_id,...bindGuard));
  }
  if(decision==="approved" && row.request_type==="role_change"){
    const payload=JSON.parse(row.payload_json||"{}");
    if(!user.isOwner || row.is_owner || !isSupportedAccessRole(payload.accessRole))return json({error:"Only an owner can approve a valid staff role change."},403);
    statements.push(db.prepare(`UPDATE users SET access_role=?,role='agent',permissions_json=?,updated_at=? WHERE id=? AND ${guard}`)
      .bind(payload.accessRole,JSON.stringify(payload.permissions||[]),now,row.target_user_id,...bindGuard));
  }
  statements.push(db.prepare(`INSERT INTO audit_log(id,actor_id,action,details_json,created_at)
    SELECT ?,?,?,?,? WHERE ${guard}`).bind(crypto.randomUUID(),user.id,"approval."+decision,JSON.stringify({approvalId:id}),now,...bindGuard));
  const [result]=await db.batch(statements);
  if(!result.meta.changes)return json({error:"This request has already been reviewed."},409);
  return json({ok:true,status:decision});
}
async function listStaff(user,env) {
  const all=user.role==="admin"||user.isOwner;
  if(!all&&!hasPermission(user,"staff.view_team"))return json({error:"Permission denied."},403);
  const q=await requireDatabase(env).prepare("SELECT * FROM users ORDER BY created_at ASC").all();
  return json({staff:(q.results||[]).filter(row=>all||(!row.is_owner&&row.role!=="admin"&&inManagedTeam(user,row.assigned_team))).map(profileDto),
    canManage:all||hasPermission(user,"staff.manage_team")});
}
async function createStaff(request,user,env) {
  if(user.role!=="admin")return json({error:"Only the administrator can add staff."},403);
  const parsed=await readJson(request,3000);if(!parsed.ok)return parsed.response;
  const email=normalizeEmail(parsed.body.email),name=String(parsed.body.displayName||"").trim(),role=String(parsed.body.accessRole||"agent");
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||name.length<2||name.length>80||!["agent","supervisor","developer"].includes(role))return json({error:"Enter a valid email, name and non-owner staff role."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000),id=crypto.randomUUID();
  const team=String(parsed.body.assignedTeam||"").trim();
  if(team.length>100)return json({error:"Team name is too long."},400);
  await db.prepare("INSERT INTO users (id,email,role,display_name,job_title,department,access_role,permissions_json,is_active,assigned_team,created_at,updated_at) VALUES (?,?,'agent',?,'','',?,'{}',1,?,?,?) ON CONFLICT(email) DO NOTHING").bind(id,email,name,role,team,now,now).run();
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


async function updateOwnProfile(request,user,env) {
  if(!user.isOwner) return json({error:"Only the system owner may edit this profile directly."},403);
  const parsed=await readJson(request,3000);if(!parsed.ok)return parsed.response;
  const name=String(parsed.body.displayName||"").trim();
  if(name.length<2||name.length>80)return json({error:"Display name must be between 2 and 80 characters."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000);
  await db.prepare("UPDATE users SET display_name=?,updated_at=? WHERE id=?").bind(name,now,user.id).run();
  await audit(db,user.id,"profile.admin_name_updated",{displayName:name});
  return json({ok:true,displayName:name});
}
async function managerUpdateStaff(request,user,env,targetId) {
  const all=user.role==="admin"||user.isOwner;
  if(!all&&!hasPermission(user,"staff.manage_team"))return json({error:"Manager access required."},403);
  const parsed=await readJson(request,5000);if(!parsed.ok)return parsed.response;
  const body=parsed.body,role=String(body.accessRole||"agent"),name=String(body.displayName||"").trim(),team=String(body.assignedTeam||"").trim();
  if((!["agent","supervisor","developer"].includes(role)&&!(role==="admin"&&user.isOwner))||name.length<2||name.length>80||team.length>100)return json({error:"Enter a valid name, role and team. Only the owner may appoint an administrator."},400);
  const custom=body.permissions;
  if(custom!==undefined && (!Array.isArray(custom)||custom.some(p=>!VALID_PERMISSIONS.includes(p))))return json({error:"One or more permissions are not supported."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000);
  const current=await db.prepare("SELECT * FROM users WHERE id=?").bind(targetId).first();
  if(!current)return json({error:"Employee not found."},404);
  if(current.is_owner || (!user.isOwner && (current.role==="admin" || role !== current.access_role || custom !== undefined && !all))) {
    return json({error:"This profile or permission change requires the owner."},403);
  }
  if(!all && (!inManagedTeam(user,current.assigned_team) ||
      teamList({assignedTeam:current.assigned_team}).some(value=>!teamList(user).includes(value)) ||
      !teamList({assignedTeam:team}).length || teamList({assignedTeam:team}).some(value=>!teamList(user).includes(value)))) {
    return json({error:"This employee is outside your managed teams."},403);
  }

  const perms=custom===undefined?current.permissions_json:JSON.stringify([...new Set(custom)]);
  await db.prepare("UPDATE users SET display_name=?,access_role=?,permissions_json=?,assigned_team=?,updated_at=? WHERE id=?").bind(name,role,perms,team,now,targetId).run();
  await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(targetId).run();
  await audit(db,user.id,"staff.updated",{targetUserId:targetId,accessRole:role,assignedTeam:team});
  const updated=await db.prepare("SELECT * FROM users WHERE id=?").bind(targetId).first();
  return json({staff:profileDto(updated)});
}
async function managerDeactivateStaff(user,env,targetId) {
  if(user.role!=="admin")return json({error:"Administrator access required."},403);
  if(user.id===targetId)return json({error:"You cannot disable your own administrator account."},400);
  const db=requireDatabase(env),now=Math.floor(Date.now()/1000);
  const row=await db.prepare("SELECT id,email,is_owner FROM users WHERE id=?").bind(targetId).first();
  if(!row)return json({error:"Employee not found."},404);
  if(row.is_owner)return json({error:"Owner accounts cannot be disabled here."},403);
  await db.prepare("UPDATE users SET is_active=0,updated_at=? WHERE id=?").bind(now,targetId).run();
  await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(targetId).run();
  await audit(db,user.id,"staff.disabled",{targetUserId:targetId,email:row.email});
  return json({ok:true});
}
async function managerAudit(user,env) {
  if(user.role!=="admin" && !hasPermission(user,"system.view_audit"))return json({error:"Permission denied."},403);
  const q=await requireDatabase(env).prepare("SELECT a.*,u.email,u.display_name FROM audit_log a JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 200").all();
  return json({events:q.results||[]});
}
async function developerSettings(user,env,method,request) {
  if(!hasPermission(user,"system.view_integrations"))return json({error:"Permission denied."},403);
  const db=requireDatabase(env);
  if(method==="GET"){
    const q=await db.prepare("SELECT setting_key,setting_value,updated_at FROM system_settings ORDER BY setting_key").all();
    return json({settings:q.results||[]});
  }
  if(method==="PUT"){
    if(!hasPermission(user,"system.manage_settings"))return json({error:"Permission denied."},403);
    const parsed=await readJson(request,3000);if(!parsed.ok)return parsed.response;
    const key=String(parsed.body.key||""),value=String(parsed.body.value||"");
    const allowed=new Set(["allow_new_cases","default_case_team","case_export_enabled"]);
    if(!allowed.has(key)||value.length>100)return json({error:"Unsupported setting."},400);
    const now=Math.floor(Date.now()/1000);
    if(user.isOwner){await db.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=excluded.updated_at").bind(key,value,user.id,now).run();await audit(db,user.id,"system.setting_updated",{key,value});return json({ok:true})}const approvalId=crypto.randomUUID();await db.prepare("INSERT INTO owner_approval_requests(id,requester_id,request_type,payload_json,reason,created_at) VALUES(?,?,?,?,?,?)").bind(approvalId,user.id,"sensitive_setting",JSON.stringify({key,value}),"Developer requested a protected system setting change.",now).run();await audit(db,user.id,"owner_approval.requested",{approvalId,key});return json({ok:true,pendingOwnerApproval:true,approvalId},202);
  }
  return json({error:"Method not allowed."},405);
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
    if (path === "/api/auth/google/status" && method === "GET") return json({ enabled: googleEnabled(env) });
    if (path === "/api/auth/google" && method === "GET") return await startGoogle(request, env);
    if (path === GOOGLE_CALLBACK && method === "GET") return await finishGoogle(request, env);
    if (path === "/api/auth/request-otp" && method === "POST") return await requestOtp(request, env);
    if (path === "/api/auth/verify-otp" && method === "POST") return await verifyOtp(request, env);
    if (path === "/api/auth/logout" && method === "POST") return await logout(request, env);
    if (path === "/api/auth/me" && method === "GET") {
      const me = await getSessionUser(request, env);
      return me ? json({user:me}) : json({user:null},401);
    }

    const user = await getSessionUser(request, env);
    if (!user) return json({ error: "Sign in to access this workspace." }, 401);
    const enterpriseResponse = await handleEnterpriseApi(request, user, env);
    if (enterpriseResponse) return enterpriseResponse;

    if (path === "/api/profile" && method === "GET") return await profileMe(user,env);
    if (path === "/api/profile" && method === "PATCH") return await updateOwnProfile(request,user,env);
    if (path === "/api/manager/audit" && method === "GET") return await managerAudit(user,env);
    if (path === "/api/developer/settings" && (method === "GET" || method === "PUT")) return await developerSettings(user,env,method,request);
    const staffMatch=path.match(/^\/api\/manager\/staff\/([A-Za-z0-9-]+)$/);
    if(staffMatch && method==="PATCH")return await managerUpdateStaff(request,user,env,staffMatch[1]);
    if(staffMatch && method==="DELETE")return await managerDeactivateStaff(user,env,staffMatch[1]);
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
    if (path === "/api/reports/summary" && method === "GET") return await reportSummary(user, env, url);

    if (path === "/api/manager/operations" && ["GET","PUT"].includes(method)) return await managerOperations(request, user, env);
    if (path === "/api/cases/bulk" && method === "PATCH") return await updateCases(request, user, env);
    const attachment = path.match(/^\/api\/cases\/([A-Za-z0-9-]+)\/attachments(?:\/([A-Za-z0-9-]+))?$/);
    if (attachment && ((attachment[2] && method === "GET") || (!attachment[2] && method === "POST"))) {
      return await caseAttachment(request, user, env, attachment[1], attachment[2]);
    }
    const match = path.match(/^\/api\/cases\/([A-Za-z0-9-]+)$/);
    if (match && method === "PATCH") return await updateCases(request, user, env, match[1]);
    if (match && ["GET","POST"].includes(method)) return await caseDetail(request, user, env, match[1], method);

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
