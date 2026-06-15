// Deep-link parser tests (doc 02 §Tests). Run with `bun test` from dashboard/.
// Pure module, no DOM — imports the parser directly.
import { expect, test } from "bun:test";
import { decisionStepSegments } from "./deepLinks";

test("step6 external maps clauses to What's Yours and Sharing", () => {
  const segments = decisionStepSegments("step6_approve_external");
  const tabs = segments.filter((s) => s.tab).map((s) => s.tab);
  expect(tabs).toEqual(["whats-yours", "sharing", "sharing"]);
});

test("step6 unknown-as-external also deep-links the three governing tabs", () => {
  const segments = decisionStepSegments("step6_approve_unknown_as_external");
  expect(segments.filter((s) => s.tab).map((s) => s.tab)).toEqual([
    "whats-yours",
    "sharing",
    "sharing",
  ]);
  expect(segments[0].text).toContain("unknown");
});

test("step3 intra-boundary links to What's Yours", () => {
  const segments = decisionStepSegments("step3_intra_boundary_self");
  expect(segments.find((s) => s.tab)?.tab).toBe("whats-yours");
});

test("step5 allow rule links to Sharing", () => {
  const segments = decisionStepSegments("step5_allow_rule:r12");
  expect(segments.find((s) => s.tab)?.tab).toBe("sharing");
});

test("step5 deny rule links to Sharing", () => {
  const segments = decisionStepSegments("step5_deny_rule");
  expect(segments.find((s) => s.tab)?.tab).toBe("sharing");
});

test("read and no-private-taint steps have no links", () => {
  expect(decisionStepSegments("step1_read").every((s) => !s.tab)).toBe(true);
  expect(decisionStepSegments("step4_no_private_taint").every((s) => !s.tab)).toBe(true);
});

test("source_default taint deep-links to Reading (ignores the :reason suffix)", () => {
  const segments = decisionStepSegments("source_default:undeclared_mcp_read");
  expect(segments.find((s) => s.tab)?.tab).toBe("reading");
  expect(segments[0].text).toContain("undeclared source");
});

test("unknown clause renders as plain text, never a link", () => {
  const segments = decisionStepSegments("step9_future_unknown_branch");
  expect(segments.length).toBe(1);
  expect(segments[0].tab).toBeUndefined();
  expect(segments[0].text).toBe("future unknown branch");
});

test("empty step yields no segments", () => {
  expect(decisionStepSegments("")).toEqual([]);
  expect(decisionStepSegments(null)).toEqual([]);
});
