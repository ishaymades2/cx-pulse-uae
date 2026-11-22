import test from "node:test";
import assert from "node:assert/strict";
import { hasPermission, permissionsForUser, isSupportedAccessRole } from "../src/permissions.js";

test("administrator has full permissions", () => {
  assert.equal(hasPermission({ role: "admin", access_role: "admin" }, "staff.manage"), true);
  assert.equal(hasPermission({ role: "admin" }, "staff.manage"), true);
});

test("supervisor is scoped to team operations, not staff administration", () => {
  const user = { role: "agent", access_role: "supervisor", permissions_json: "{}" };
  assert.equal(hasPermission(user, "cases.view_team"), true);
  assert.equal(hasPermission(user, "cases.assign_team"), true);
  assert.equal(hasPermission(user, "cases.view_own"), false);
  assert.equal(hasPermission(user, "system.manage_settings"), false);
});

test("developer has broad technical permissions but no staff or customer case access", () => {
  const user = { role: "agent", access_role: "developer", permissions_json: "{}" };
  assert.equal(hasPermission(user, "system.view_health"), true);
  assert.equal(hasPermission(user, "system.manage_settings"), true);
  assert.equal(hasPermission(user, "system.manage_feature_flags"), true);
  assert.equal(hasPermission(user, "cases.view_team"), false);
  assert.equal(hasPermission(user, "staff.manage"), false);
});

test("custom permission list overrides role defaults and rejects unknown grants", () => {
  const user = { role: "agent", access_role: "supervisor", permissions_json: JSON.stringify(["cases.view_own", "unknown.permission"]) };
  assert.deepEqual(permissionsForUser(user), ["cases.view_own"]);
  assert.equal(hasPermission(user, "cases.view_team"), false);
});

test("only supported non-admin roles can be assigned to staff", () => {
  assert.equal(isSupportedAccessRole("agent"), true);
  assert.equal(isSupportedAccessRole("supervisor"), true);
  assert.equal(isSupportedAccessRole("developer"), true);
  assert.equal(isSupportedAccessRole("admin"), false);
});

test("owner has immutable full permissions", () => {
  const owner = { role: "admin", access_role: "admin", is_owner: 1 };
  assert.equal(hasPermission(owner, "staff.manage"), true);
  assert.equal(hasPermission(owner, "system.manage_backups"), true);
});

test("developer has broad operational access but is not owner", () => {
  const developer = { role: "agent", access_role: "developer", permissions_json: "{}" };
  assert.equal(hasPermission(developer, "cases.update_all"), true);
  assert.equal(hasPermission(developer, "customers.manage"), true);
  assert.equal(hasPermission(developer, "tasks.manage"), true);
  assert.equal(hasPermission(developer, "staff.manage"), false);
  assert.equal(hasPermission(developer, "ownership.transfer"), false);
});
