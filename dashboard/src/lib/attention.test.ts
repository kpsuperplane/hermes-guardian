import { expect, test } from "bun:test";
import { buildAttentionItems } from "./attention";
import type { Policy } from "../types";

test("orders attention by approval state and suggestion category", () => {
  const policy: Policy = {
    risk_banners: [
      { id: "self_trust_grants", severity: "info", message: "Self trust is active." },
      { id: "taint_classification_relaxed", severity: "high", message: "Relaxed mode." },
    ],
    sharing_tool_inventory: [
      {
        row_type: "tool",
        match: "unknown_send",
        observed_egress_families: ["tool_unknown"],
        last_seen: 30,
        policy_state: "none",
      },
    ],
    reading_tool_inventory: [
      {
        row_type: "tool",
        match: "notes_read",
        observed_read_families: ["mcp_read"],
        last_seen: 20,
        policy_state: "none",
      },
    ],
  };

  const items = buildAttentionItems({
    policy,
    approvals: [
      { id: "covered", covered_by_rule: true, created_at: 300 },
      { id: "old", covered_by_rule: false, created_at: 100 },
      { id: "new", covered_by_rule: false, created_at: 200 },
    ],
    sourceSuggestions: [{ server: "crm", hits: 2, last_ts: 40 }],
  });

  expect(items.map((item) => item.id)).toEqual([
    "approval:new",
    "approval:old",
    "approval:covered",
    "risk:taint_classification_relaxed",
    "source:crm",
    "egress-tool:unknown_send",
    "read-tool:notes_read",
    "info:self_trust_grants",
  ]);
});

test("de-dupes banners, source suggestions, and source-covered read tools", () => {
  const policy: Policy = {
    risk_banners: [
      { id: "relaxed", severity: "high", message: "First." },
      { id: "relaxed", severity: "high", message: "Duplicate." },
    ],
    reading_tool_inventory: [
      {
        row_type: "tool",
        match: "crm_read_resource",
        mcp_server_prefix: "crm",
        observed_read_families: ["mcp_read"],
        last_seen: 20,
        policy_state: "none",
      },
      {
        row_type: "tool",
        match: "drive_read",
        observed_read_families: ["mcp_read"],
        last_seen: 10,
        policy_state: "none",
      },
    ],
    sharing_tool_inventory: [
      {
        row_type: "tool",
        match: "send_tool",
        observed_egress_families: ["tool_unknown"],
        last_seen: 30,
        policy_state: "none",
      },
      {
        row_type: "tool",
        match: "send_tool",
        observed_egress_families: ["tool_unknown"],
        last_seen: 10,
        policy_state: "none",
      },
    ],
  };

  const items = buildAttentionItems({
    policy,
    sourceSuggestions: [
      { server: "crm", hits: 3, last_ts: 40 },
      { server: "crm", hits: 1, last_ts: 30 },
    ],
  });

  expect(items.map((item) => item.id)).toEqual([
    "risk:relaxed",
    "source:crm",
    "egress-tool:send_tool",
    "read-tool:drive_read",
  ]);
});

test("returns an empty list when no attention metadata is present", () => {
  expect(buildAttentionItems({ policy: {}, approvals: [], sourceSuggestions: [] })).toEqual([]);
});

test("filters dismissed non-approval items but never generic-dismisses approvals", () => {
  const expires = 9_999_999_999;
  const items = buildAttentionItems({
    policy: {
      attention_dismissals: [
        { dismiss_key: "risk:relaxed", expires_at: expires },
        { dismiss_key: "approval:1234", expires_at: expires },
      ],
      risk_banners: [{ id: "relaxed", severity: "high", message: "Relaxed mode." }],
    },
    approvals: [{ id: "1234", covered_by_rule: false, created_at: 100 }],
  });

  expect(items.map((item) => item.id)).toEqual(["approval:1234"]);
});

test("source and tool dismissals resurface when evidence changes", () => {
  const expires = 9_999_999_999;
  const source = { server: "crm", hits: 2, last_ts: 40 };
  const tool = {
    row_type: "tool",
    match: "unknown_send",
    observed_egress_families: ["tool_unknown"],
    last_seen: 30,
    seen_count: 1,
    policy_state: "none",
  };
  const dismissed = buildAttentionItems({
    policy: {
      attention_dismissals: [
        { dismiss_key: "source:crm|last=40|hits=2", expires_at: expires },
        {
          dismiss_key: "egress-tool:unknown_send|last=30|seen=1|families=tool_unknown",
          expires_at: expires,
        },
      ],
      sharing_tool_inventory: [tool],
    },
    sourceSuggestions: [source],
  });

  expect(dismissed.map((item) => item.id)).toEqual([]);

  const resurfaced = buildAttentionItems({
    policy: {
      attention_dismissals: [
        { dismiss_key: "source:crm|last=40|hits=2", expires_at: expires },
        {
          dismiss_key: "egress-tool:unknown_send|last=30|seen=1|families=tool_unknown",
          expires_at: expires,
        },
      ],
      sharing_tool_inventory: [Object.assign({}, tool, { last_seen: 50, seen_count: 2 })],
    },
    sourceSuggestions: [Object.assign({}, source, { hits: 3, last_ts: 50 })],
  });

  expect(resurfaced.map((item) => item.id)).toEqual([
    "source:crm",
    "egress-tool:unknown_send",
  ]);
});
