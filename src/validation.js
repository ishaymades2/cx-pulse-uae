export const CATEGORIES = [
  "Account enquiry",
  "Service complaint",
  "Payment issue",
  "Document request",
  "General enquiry",
];

export const PRIORITIES = ["Normal", "High", "Urgent"];
export const STATUSES = ["Open", "In progress", "Resolved"];
export const TEAMS = [
  "Customer Service",
  "Branch Operations",
  "Administration",
  "Quality Assurance",
];

export function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function parseEmailList(value) {
  return String(value || "")
    .split(",")
    .map(normalizeEmail)
    .filter(Boolean);
}

export function isAllowedEmail(email, env) {
  const normalized = normalizeEmail(email);
  const admins = parseEmailList(env.ADMIN_EMAILS);
  const agents = parseEmailList(env.AGENT_EMAILS);
  return admins.includes(normalized) || agents.includes(normalized);
}

export function roleForEmail(email, env) {
  const normalized = normalizeEmail(email);
  return parseEmailList(env.ADMIN_EMAILS).includes(normalized) ? "admin" : "agent";
}

export function validateCasePayload(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "A JSON object is required." };
  }

  const customerName = typeof input.customerName === "string"
    ? input.customerName.trim()
    : "";
  const category = typeof input.category === "string" ? input.category : "";
  const priority = typeof input.priority === "string" ? input.priority : "Normal";
  const team = typeof input.team === "string" ? input.team : "Customer Service";
  const summary = typeof input.summary === "string" ? input.summary.trim() : "";

  if (customerName.length < 2 || customerName.length > 80) {
    return { ok: false, error: "Customer name must be between 2 and 80 characters." };
  }
  if (!CATEGORIES.includes(category)) {
    return { ok: false, error: "Choose a valid case category." };
  }
  if (!PRIORITIES.includes(priority)) {
    return { ok: false, error: "Choose a valid priority." };
  }
  if (!TEAMS.includes(team)) {
    return { ok: false, error: "Choose a valid assigned team." };
  }
  if (summary.length < 5 || summary.length > 1000) {
    return { ok: false, error: "Summary must be between 5 and 1,000 characters." };
  }

  return {
    ok: true,
    value: { customerName, category, priority, team, summary },
  };
}
