export const ROLE_PERMISSIONS = {
  admin: ["*"],
  supervisor: [
    "cases.view_team",
    "cases.create",
    "cases.update_team",
    "cases.assign_team",
    "reports.view_team",
    "profile.view",
    "profile.request_name_change",
  ],
  developer: [
    "system.view_health",
    "system.view_audit",
    "system.view_integrations",
    "system.manage_settings",
    "system.manage_feature_flags",
    "profile.view",
    "profile.request_name_change",
  ],
  agent: [
    "cases.view_own",
    "cases.create",
    "cases.update_own",
    "reports.view_own",
    "profile.view",
    "profile.request_name_change",
  ],
};

export const VALID_PERMISSIONS = [
  "cases.view_team",
  "cases.view_own",
  "cases.create",
  "cases.update_team",
  "cases.update_own",
  "cases.assign_team",
  "reports.view_team",
  "reports.view_own",
  "system.view_health",
  "system.view_audit",
  "system.view_integrations",
  "system.manage_settings",
  "system.manage_feature_flags",
  "profile.view",
  "profile.request_name_change",
];

export function permissionsForUser(user) {
  if (!user) return [];
  if (user.role === "admin" || user.access_role === "admin") return ["*"];
  let custom;
  try {
    custom = JSON.parse(user.permissions_json || "{}");
  } catch {
    custom = null;
  }
  if (Array.isArray(custom)) {
    return [...new Set(custom.filter((item) => VALID_PERMISSIONS.includes(item)))];
  }
  const role = ROLE_PERMISSIONS[user.access_role] ? user.access_role : "agent";
  return [...ROLE_PERMISSIONS[role]];
}

export function hasPermission(user, permission) {
  const permissions = permissionsForUser(user);
  return permissions.includes("*") || permissions.includes(permission);
}

export function isSupportedAccessRole(role) {
  return ["agent", "supervisor", "developer"].includes(role);
}
