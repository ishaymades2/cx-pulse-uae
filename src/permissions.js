export const ROLE_PERMISSIONS = {
  owner: ["*"],
  admin: [
    "cases.view_all","cases.create","cases.update_all","cases.assign",
    "customers.view","customers.manage","tasks.view_all","tasks.manage",
    "teams.view","teams.manage","reports.view_all","staff.view","staff.manage",
    "approvals.view","approvals.review","notes.manage","notifications.view",
    "knowledge.view","knowledge.manage","feedback.view","feedback.manage",
    "system.view_health","system.view_audit","system.view_integrations",
    "profile.view","profile.request_name_change"
  ],
  supervisor: [
    "cases.view_team","cases.create","cases.update_team","cases.assign_team",
    "customers.view","tasks.view_team","tasks.manage_team","teams.view",
    "reports.view_team","staff.view_team","approvals.view_team","notes.manage_team",
    "notifications.view","knowledge.view","feedback.view_team","profile.view",
    "profile.request_name_change"
  ],
  developer: [
    "system.view_health","system.view_audit","system.view_integrations",
    "system.manage_settings","system.manage_feature_flags","system.manage_deployments",
    "system.manage_backups","system.view_data","system.manage_data",
    "cases.view_all","cases.create","cases.update_all","cases.assign",
    "customers.view","customers.manage","tasks.view_all","tasks.manage",
    "teams.view","teams.manage","reports.view_all","notifications.view",
    "knowledge.view","knowledge.manage","feedback.view","feedback.manage",
    "profile.view","profile.request_name_change"
  ],
  agent: [
    "cases.view_own","cases.create","cases.update_own",
    "customers.view","tasks.view_own","tasks.update_own","reports.view_own",
    "notifications.view","knowledge.view","feedback.create","profile.view",
    "profile.request_name_change"
  ],
};

export const VALID_PERMISSIONS = [...new Set(Object.values(ROLE_PERMISSIONS).flat().filter(p => p !== "*"))];

export function permissionsForUser(user) {
  if (!user) return [];
  if (user.is_owner === 1 || user.isOwner === true || user.access_role === "owner" || user.accessRole === "owner") return ["*"];
  if (user.role === "admin" || user.access_role === "admin" || user.accessRole === "admin") return [...ROLE_PERMISSIONS.admin];
  let custom;
  try { custom = JSON.parse(user.permissions_json || user.permissionsJson || "{}"); } catch { custom = null; }
  if (Array.isArray(custom)) return [...new Set(custom.filter(item => VALID_PERMISSIONS.includes(item)))];
  const role = user.access_role || user.accessRole || "agent";
  return [...(ROLE_PERMISSIONS[role] || ROLE_PERMISSIONS.agent)];
}
export function hasPermission(user, permission) {
  const permissions = permissionsForUser(user);
  return permissions.includes("*") || permissions.includes(permission);
}
export function isSupportedAccessRole(role) {
  return ["agent","supervisor","developer"].includes(role);
}
