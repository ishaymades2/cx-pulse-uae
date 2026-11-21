import test from "node:test";
import assert from "node:assert/strict";
import {
  isAllowedEmail,
  normalizeEmail,
  parseEmailList,
  roleForEmail,
  validateCasePayload,
} from "../src/validation.js";

test("normalizes email addresses", () => {
  assert.equal(normalizeEmail("  SHAIMA@Example.COM "), "shaima@example.com");
  assert.equal(normalizeEmail(null), "");
});

test("parses comma-separated allowlists", () => {
  assert.deepEqual(parseEmailList("Admin@example.com, agent@example.com ,"), [
    "admin@example.com",
    "agent@example.com",
  ]);
});

test("only explicitly allowlisted users can request a sign-in code", () => {
  const env = {
    ADMIN_EMAILS: "admin@example.com",
    AGENT_EMAILS: "agent@example.com",
  };
  assert.equal(isAllowedEmail("ADMIN@example.com", env), true);
  assert.equal(isAllowedEmail("unknown@example.com", env), false);
  assert.equal(roleForEmail("admin@example.com", env), "admin");
  assert.equal(roleForEmail("agent@example.com", env), "agent");
});

test("accepts a valid customer case and trims user input", () => {
  const result = validateCasePayload({
    customerName: "  Aisha M. ",
    category: "Service complaint",
    priority: "High",
    team: "Customer Service",
    summary: "  Customer needs an update on the submitted request.  ",
  });
  assert.equal(result.ok, true);
  assert.equal(result.value.customerName, "Aisha M.");
  assert.equal(result.value.summary, "Customer needs an update on the submitted request.");
});

test("rejects invalid category, priority, team and oversized fields", () => {
  const base = {
    customerName: "Aisha M.",
    category: "Not a real category",
    priority: "Critical",
    team: "Unknown",
    summary: "This is a valid length summary.",
  };
  assert.equal(validateCasePayload(base).ok, false);
  assert.equal(validateCasePayload({ ...base, category: "General enquiry", priority: "Normal", team: "Administration", summary: "tiny" }).ok, false);
  assert.equal(validateCasePayload({ ...base, customerName: "A", category: "General enquiry", priority: "Normal", team: "Administration" }).ok, false);
});

test("rejects non-object payloads", () => {
  assert.equal(validateCasePayload(null).ok, false);
  assert.equal(validateCasePayload([]).ok, false);
});
