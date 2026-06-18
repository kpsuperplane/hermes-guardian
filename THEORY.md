# Hermes Guardian Defense Theory

## Abstract

Hermes Guardian is a privacy-aware egress and declassification layer for Hermes Agent. Its distinctive contribution is the asset it protects: personal content that is private because of where it came from, not because it matches a recognizable pattern. Credentials, API keys, and many PII fields can be scanned for; an email body, contact list, calendar entry, or note may have no signature at all. Guardian calls this *provenance-private* data and governs it by source.

Guardian does not try to solve prompt injection by detecting malicious text. It assumes untrusted text may influence the model, then enforces policy where private information can leave: tools, messages, browser actions, and other mediated outbound channels.

Hermes provides lower-level controls such as sandboxing, credential scoping, private-network protections, gateway authorization, and dangerous-command checks. Guardian adds a semantic information-flow layer above them: it tracks when private context enters a session, classifies outbound actions, and blocks or approval-gates flows without a declassification rule.

The stack is defense in depth: Hermes limits what the agent and its tools can reach; Guardian limits where information the agent has learned can go. The narrative version is [When secrets don't look like secrets](https://kevinpei.com/posts/thoughts-on-agent-privacy); this document gives the threat model, guarantees, limitations, and field positioning.

## Executive summary

Guardian belongs to the family of dynamic information-flow and source/sink runtime inspection systems. It is not a formal noninterference system and it is not a sandbox. Its security property is narrower but still meaningful:

> For Hermes-mediated actions that Guardian classifies as outbound sinks, Guardian can block or approval-gate flows from sessions that have observed private data, unless an allow or declassification policy applies.

That property depends on several assumptions:

- Relevant actions are routed through Hermes hooks.
- Guardian correctly classifies the action as a sink.
- Guardian's policy store and hook code execute correctly.
- Security Module and language-pack configuration reflect the deployment's intended risk tolerance.
- Tools with their own filesystem or network capabilities are contained by Hermes and the operating system.
- The deployment does not give an untrusted tool broader access than Guardian can mediate.

Under those assumptions, Guardian provides a useful confidentiality boundary for mediated tool use. Outside those assumptions, the hard boundary comes from Hermes runtime isolation and the surrounding OS/container/network configuration.

The combined Hermes + Guardian stack has the same broad shape as current agent-security systems: containment and credential minimization below, source/sink inspection above, and user approval for ambiguous or sensitive flows. It is less formal than systems such as CaMeL, RTBAS, and GAAP, but aimed at a deployable local personal agent.

## Background: the agent exfiltration problem

Prompt injection is dangerous in personal agents because the agent often combines three capabilities:

1. Access to private data.
2. Exposure to untrusted input.
3. Ability to communicate externally.

This combination is sometimes called the “lethal trifecta.” A malicious email, page, calendar event, or document only has to steer the agent into encoding private information into a URL, search query, browser action, message, API call, file upload, or final response.

Guardian treats prompt injection as an expected failure mode and enforces at egress. The case against model-layer detection is threefold. Conceptually, data/instruction separation is incoherent for agents: memory, skills, tool results, and third-party content are all read as guidance, so separating "data" from "instructions" can break the workflows being protected (Abdelnabi & Bagdasarian, 2026). Formally, an LLM detector is as injectable as the model it guards: DataFlip drove known-answer detection to 0% while preserving 91% attack success (Choudhary et al., 2025). Empirically, a 78-study systematization finds adaptive attacks exceed 85% success against deployed defenses and traces the root cause to the conflation of code and data (Maloyan & Namiot, 2026). Unlike SQL injection, which was solvable by *separation*, LLM injection has no separate channel to separate into.

These results do not say the damage cannot be contained; they say the model cannot be counted on to stay unfooled. Guardian's response is to move the boundary outside the model and constrain what a fooled agent may do:

```text
Private source observed -> session becomes tainted -> outbound action requires policy
```

## Threat model

### Attacker-controlled inputs

The threat model includes indirect prompt-injection content embedded in sources the agent may read during normal operation:

- Email bodies and attachments.
- Calendar event titles, descriptions, locations, and attendees.
- Documents and notes.
- Web pages and search results.
- Contact records.
- Tool results.
- MCP tool descriptions, schemas, and outputs.
- Local project files.
- Agent memory, cron context, or durable instructions when writable by an attacker.

The attacker’s objective is unauthorized disclosure or unauthorized action. The attacker may attempt to influence:

- Tool choice.
- Tool arguments.
- Browser navigation.
- Search queries.
- Message recipients and message bodies.
- File uploads.
- MCP tool calls.
- Shell or code execution.

Final responses are outside the Privacy-module egress gate. They are still scanned
by the non-approvable Security Module for credentials, OTPs, reset links, security
alerts, private keys, and similar account-security content.

### Trusted components

The defense model treats these components as trusted for policy enforcement:

- Hermes hook dispatch for mediated actions.
- Guardian policy code.
- Guardian local privacy-rule, security-rule, language-pack, approval, and activity storage.
- The user’s explicit approval decisions.
- Hermes gateway identity and authorization metadata.
- Hermes runtime isolation and network controls, when configured.

The language model is not treated as a reliable security decision-maker. Guardian may use an LLM as one signal in some modes, but the core design does not rely on the primary model consistently rejecting malicious instructions.

### Trust boundary

Guardian’s product boundary places the model inside the practical trust boundary for many workflows. The model can see ordinary private context so that it can help the user reason over email, documents, calendar entries, and other personal data.

That choice differs from architectures that treat the model provider as untrusted and prevent some private data from reaching the model at all. Guardian instead focuses on mediated egress after private context is in session.

## Core security model

Guardian can be described as a coarse-grained dynamic information-flow-control layer over Hermes-mediated actions. The companion blog frames the same machinery as two classification problems — *ingress* (is this source private?) and *egress* (is sharing this OK?); those map directly onto the source-taint and sink-classification mechanisms developed below.

### Labels

Guardian assigns private data labels to source categories such as:

- `communications`
- `contacts`
- `documents`
- `calendar`
- `memory`
- `local_system`
- `browser_private_input`

These labels represent classes of private context that the agent has observed.

### Semantic detectors

Guardian uses deterministic detectors for credentials, sensitive account-security content, private-field hints, browser private-context hints, and sensitive links. Phrase-based semantic detectors are supplied by declarative language packs. English is required; other enabled packs extend recognition for terms such as auth-code labels, reset/recovery language, security alerts, redaction markers, and private-field names.

Language packs improve detection coverage but do not create a universal natural-language guarantee. Structural mechanisms such as source-based taint, credential-format scanning, URL/search/MCP egress classification, and final-response mediation remain separate from phrase coverage.

### Session taint

When a private source is observed, Guardian records coarse session taint. It marks that the session has seen private data; it does not prove which output strings depend on which source objects.

Egress decisions use that ambient taint. A payload is not allowed merely because it "looks clean"; absence of detected private content is not evidence of safety. Narrowing, such as distinguishing a freshly typed email address from a copied calendar event, happens only in `llm` mode, where the verifier reads the real payload and checks it against authorized intent.

Document reads are tiered by source. Provable reference reads, such as `skill_view` or paths under the skills tree, use a lenient scan so placeholder contacts in docs do not taint unrelated work. Operator-declared tools follow their declared source (`reference`, `private`, or `unknown`). Undeclared MCP document reads fail closed as `documents`, with a one-time classification suggestion. `source = unknown` remembers that review happened, but does not relax fallback taint.

For unknown non-MCP reads, Taint Classification sets the fallback. `balanced` uses best-effort source inference plus content signals. `strict` treats otherwise-unknown read results as `documents`. `relaxed` keeps balanced read inference but does not gate unrecognized non-MCP tools under taint, and is surfaced as a runtime risk.

Guardian can also classify otherwise-unknown, signalless reads with an enabled-by-default LLM source classifier. Unlike the egress verifier, it sees metadata only: tool name, matcher shape, argument keys/types, status, result type/size, and JSON keys. It writes a normal Reading tool classification as `reference`, `private`, or `unknown` so the same matcher is not reviewed repeatedly.

Coarse taint produces predictable tradeoffs: it can gate harmless outbound actions, and it can miss flows when the sink is not classified or when a tool reads and exfiltrates internally before taint is recorded.

### Sink classification

Guardian classifies tool calls by action family and destination, with purpose and pseudonymous recipient identity where available. Sinks include message sends, service posts, MCP writes, browser navigation or typing, terminal/code execution, and web or HTTP-capable calls.

The security property depends on correct sink classification. Unknown or open-ended tool ecosystems, especially MCP, are structurally harder to classify than closed built-in tool sets.

In balanced and strict modes, a tool that matches no known built-in family is treated as `tool_unknown` and gated under taint. Relaxed mode is the explicit opt-out.

Browser console eval is classified by behavior. Pure page-state reads are reads; writes into the page, form submissions, navigation, credential-store access, dynamic code, and network calls are sinks. The read allowance is fail-closed: every operation must be a known pure-read accessor, or the eval is gated. Page writes count as egress because attacker-controlled page script can read the mutation back out.

Cross-channel lockdown catches channel-shopping within a turn. Once a private export is withheld, Guardian records a volatile metadata-only reroute guard. A later action that overlaps the withheld flow by class and route metadata is downgraded to manual review even if it would otherwise auto-approve. High-risk denials and intrinsic exfiltration shapes arm a broader guard; ordinary ambiguity stays route-scoped. The guard clears on the next owner message, and explicit approvals or standing rules still apply.

Operators can reduce false positives with tool classifications. Reading classifications declare source classes and whether document reads are reference, private, or unknown. Sharing classifications declare whether a tool is a safe non-sink, forced-gate sink, or specific action family/destination. These affect Privacy-module classification only; they never bypass the Security Module or intrinsic same-call hard blocks.

### Declassification

Approvals and allow rules are declassification decisions: they allow particular private classes to flow through a particular action family, destination, purpose, recipient identity, and owner/session/cron scope. They may expire or carry remaining-use limits.

Guardian’s declassification model is operational, not mathematical. It is built for workflows where some private flows are intended, such as sending a calendar summary to a trusted personal notebook.

### Security-sensitive suppression

Guardian distinguishes ordinary private context from access-sensitive content: material that can grant account access or enable credential compromise. Examples include OTP/MFA codes, magic links, password reset links, verification links, security-sensitive account notifications, and upstream redaction markers.

These are blocked or suppressed categorically rather than handled through normal approval-based declassification.

The Security Module is configured through high-level rules enabled by default: account-security content, credential-shaped content, sensitive links, intrinsic same-call exfiltration, and terminal remote-read shortcuts targeting private-network or metadata hosts. Intrinsic same-call detection is structural: it looks for local/code secret reads, browser console/CDP state reads, or obvious MCP private-source tools combined with network, webhook, or share sinks. When a rule fires, the action, tool result, or final response is blocked or suppressed without approval. Privacy allow rules, Egress Safety changes, and approval commands do not declassify Security Module findings.

Credential suppression is directional. Hard secrets, such as private keys, cloud access keys, and password or private-key assignments, are suppressed on every surface. Account-security content is also suppressed inbound when it carries concrete access material such as OTPs, reset links, magic links, redaction markers, or security notifications. Provable reference material (`skill_view` and reads under the skills tree) gets a narrower relaxation for phrase-only account-security prose. API/service authentication tokens are blocked on egress but may be read inbound, because suppressing an integration's own token at read time would break legitimate use without preventing later exfiltration.

Security-rule toggles are administrative model changes, not declassification decisions. Disabling a rule removes that categorical hardening; Privacy-module gating may still apply, but it is not a substitute. Runtime policy snapshots, `/guardian status`, and the dashboard surface risk banners for risky configurations.

### Metadata and control surfaces

Guardian preserves policy semantics across slash commands, CLI helpers, and the dashboard. Dashboard mutation routes call the same mutation functions as command surfaces, and can be disabled or guarded by an admin token.

Persistent activity and dashboard state are metadata-only. Activity rows, policy snapshots, dashboard payloads, cron notifications, and standing rules should not contain raw private bodies, typed browser text, document contents, credentials, tokenized URLs, secret-bearing command payloads, raw message recipients, or other content-bearing arguments. Pending approvals have one narrow TTL-bound exception for bounded `mine`/`trust` permit candidates (`permit_recipient`, `permit_host`, `permit_command`), which are not exposed through the public dashboard payloads and are deleted on resolution or pruning. The LLM-verifier input is the model-visibility exception and is not persisted state.

## The mediated-flow property

Guardian's useful promise is a reference-monitor promise, not a detector promise:

> Once a Hermes-mediated session has observed private data, any later Hermes-visible action that Guardian classifies as outbound must have an explicit declassification reason, or it is blocked, suppressed, or routed to approval.

The guarantee depends on four qualifiers:

- **Hermes-mediated** means the action crosses a Hermes hook Guardian can inspect: tool calls, tool results, gateway dispatch, slash/dashboard mutations, and final-output security scanning. If a subprocess, browser profile, MCP server, or external service leaks internally before Hermes sees a classified action, Guardian is not the boundary; Hermes sandboxing and OS/network policy are.
- **Observed private data** means the session has source taint from a private source or stronger access-sensitive findings from the Security Module. The payload does not need to look private. The point is that the session has been exposed to private context.
- **Outbound** means Guardian can classify the proposed operation as a sink with an action family, destination, purpose, and recipient identity where available. Unknown tools under taint are treated as sinks unless the operator explicitly classifies them otherwise.
- **Explicit declassification** means a standing allow rule, trusted-recipient rule, scoped approval, read-only auto-approval with metadata support, or an `llm`-mode verifier allow that also passes the deterministic corroboration gate. Security Module findings are outside this path: credentials, OTPs, reset links, and intrinsic same-call exfiltration shapes are non-approvable.

The practical decision table is:

| Situation | Guardian behavior | Why |
|---|---|---|
| No private source has been observed | Allow ordinary actions unless the Security Module fires | There is no private flow in scope |
| Private source observed, later action is a known outbound sink | Require policy, approval, or verifier-backed declassification | A tainted session is trying to communicate out |
| Private source observed, later action is an unknown tool | Gate by default in balanced/strict modes | Unknown capability is treated as possible egress |
| Private source observed, destination is inside the owner's declared boundary | Allow when destination trust says it is still "yours" | The flow stays within the protected boundary |
| Action carries credential/account-security content | Block or suppress without approval | Access-sensitive content is not ordinary private data |
| Tool reads and leaks inside one opaque call | Out of scope for this property | Guardian cannot mediate what it cannot observe |

So the property is intentionally weaker than noninterference: Guardian does not prove an output has no semantic dependence on private input. It is also stronger than prompt-injection detection: Guardian does not need to decide whether an instruction was malicious. It only needs to notice that a tainted session is attempting a mediated outbound flow and then demand a declassification reason for that flow.

## Relationship to Hermes built-in security

Hermes and Guardian operate at different layers.

| Layer | Hermes role | Guardian role |
|---|---|---|
| OS/process containment | Containers, remote backends, whole-process wrapping, filesystem/process restrictions | Relies on this for hard containment; adds semantic policy above it |
| Credential scoping | Environment filtering and explicit credential passthrough for subprocesses, containers, code, and MCP | Treats credential exposure and private tool output as sensitive information-flow sources |
| Network target safety | SSRF and private-network protections for URL-capable tools | Gating of public destinations when tainted data may flow through URL, query, body, or message text |
| Gateway access | Platform allowlists, pairing, and authorization metadata | Actor/session/cron-aware approval and declassification policy |
| Command safety | Dangerous-command approval and destructive-command blocking | Confidentiality checks for commands that may leak data without being destructive |
| Prompt-injection hygiene | Scanning of context files, skills, memory-like surfaces, and suspicious patterns | Post-ingestion flow control that assumes malicious content may still enter |
| Audit and UX | Tool/runtime/dashboard surfaces | Metadata-only approval, privacy-rule, security-rule, language-pack, and activity trail for private-flow decisions |

Hermes’ security documentation identifies OS-level isolation as the load-bearing boundary against adversarial model behavior. In-process controls such as approval prompts, scanners, redaction, and allowlists are valuable but not equivalent to a sandbox.

Guardian fits naturally above Hermes containment. Hermes controls what the agent runtime can reach. Guardian controls whether information already visible to the agent may leave through a classified mediated action.

## Combined defense stack

Guardian assumes a broader Hermes deployment that contains tools below the hook layer:

| Layer | Main controls |
|---|---|
| OS / container / VM / network policy | Sandboxed or remote terminal/code backends, restricted mounts, minimal credentials, egress limits |
| Hermes platform access | Gateway allowlists, DM pairing, channel restrictions, unauthorized-user denial |
| Hermes tool hygiene | Dangerous-command approval, destructive-command blocks, environment and credential passthrough controls, MCP filtering, SSRF/private-network protections |
| Guardian information-flow policy | Security Module findings, source taint, sink classification, private-egress approval, destination/action/data-class rules |
| Guardian declassification UX | Short-lived approvals, persistent allow/deny rules, metadata-only audit trail, dashboard and slash-command controls |

A weak runtime configuration leaves Guardian carrying too much. If shell, code, MCP, browser, and plugins have broad host access and arbitrary network egress, one missed classifier can leak data. With sandboxed execution, limited host secrets, authenticated gateway users, private-network blocking, and consequential actions routed through Hermes hooks, Guardian becomes the semantic egress layer in a larger containment architecture.

## Limitations of the model

### Complete mediation

A reference monitor only controls actions it can observe. Guardian observes Hermes-mediated hooks. It does not automatically control arbitrary side effects inside an unsandboxed process, compromised external service, browser profile, plugin, or MCP server.

The combined architecture relies on Hermes and the operating system for containment below the hook layer.

### Same-call source and sink

Session taint works most directly for a two-step flow:

```text
read private data -> taint session -> later egress blocked
```

Some tools can combine both steps inside one invocation:

```text
read private data and exfiltrate it before returning a result
```

Shells, code execution, browser console/CDP, and some MCP servers fall into this category. Runtime sandboxing and network policy are the primary lower-layer controls for this class.

### Coarse taint

Session-level taint is not complete object-level provenance. It records that private data has entered the session, but it does not prove semantic dependency between a specific output and a specific source object. Destination trust removes a large class of false positives at the *destination* end (intra-boundary flows never gate), and the `llm`-mode verifier narrows at the *content* end, but the deterministic taint itself stays coarse and conservative.

This creates predictable tradeoffs:

- Benign outbound actions to an external destination may require approval because the session has private taint, with narrowing available only via the `llm`-mode verifier (not deterministically).
- Encoded or indirect flows can evade policy when the sink is not recognized.
- Approvals operate over action/destination/data-class context rather than a full proof of dependency.

### Detector and language coverage

Semantic scanning is finite. A language pack can improve coverage for a language or domain, but it cannot enumerate every phrase, euphemism, obfuscation, or future service-specific wording. Missing language coverage can therefore reduce pre-taint detection of account-security content, private-field hints, browser private-context hints, and sensitive links.

For that reason, language packs are not the primary confidentiality boundary. Source-based taint, conservative sink classification, credential-format scanning, Security Module hard blocks, and lower-layer Hermes containment remain load-bearing.

### Coarse declassification context

Guardian’s policy model reasons over actor, session, action family, destination, purpose token, pseudonymous recipient identity, data class, and scope. Human privacy norms can depend on more: recipient visibility, data subject, time, freshness, receiving context, and trusted user intent.

Contextual-integrity (CI) work frames privacy as appropriate information flow under the norms of the receiving context. Guardian uses some CI vocabulary, but it does not implement CI's normative rule. It enforces *owner authorization*: did the data owner authorize this flow, or is a third party laundering it out? That is the right anchor for a single-owner personal confidentiality tool, but it is narrower than CI and can disagree with CI in multi-party contexts.

`llm` mode partially recovers trusted intent without handing the verifier the full transcript. The verifier may receive `user_request_context`: sanitized owner-authored text captured from an authenticated CLI owner or configured gateway owner before the model or tools run, after Security Module screening. It excludes system prompts, assistant plans, tool results, web/email/calendar content, and model output; non-owners and unauthenticated senders cannot populate it. If the latest owner message is too elliptical, Guardian can retry once with bounded owner-message history; otherwise the decision falls back to manual approval.

The verifier's authorization and risk labels are still model output, so Guardian does not let them clear private exports alone. A private export to an `external` or `unknown` destination is auto-allowed only when the verifier rates authorization as `explicit` or `substantive` and Guardian independently has owner or cron authorization context for that session. Without that corroboration, the allow becomes manual approval. Low-risk public remote reads and terminal commands with no network target are narrow exceptions when structural checks prove the action is not carrying data to an external party.

Cron context is handled similarly but more conservatively. When enabled, it supplies the verifier with the cron job's sanitized stored instruction. Because cron runs unattended, a high-risk `allow` on a cron session is always downgraded to manual approval.

Authorization is scoped to the data being sent, not merely to the action. A request to subscribe to a newsletter can justify sending a freshly typed email address; it does not justify submitting a copied calendar event into the form. The verifier gets the live payload plus ambient classes and checks content/intent consistency. In `strict` mode, where the verifier is off, the human approval step is the laundering catch.

The verifier reads the real payload because it is normally the same model/provider trust boundary the agent already uses. Redacting the payload would not protect against that provider, but would break the laundering check. Guardian instead preserves the at-rest boundary: credentials, OTPs, reset links, and credential-shaped tokens are stripped or hard-blocked; verdict rationales are sanitized before display or storage; persistent rows, rules, dashboard payloads, and notifications remain sanitized or pseudonymous. The relaxation assumes the configured verifier LLM is inside the operator's chosen trust boundary.

### Model/provider visibility

Guardian allows private context to enter the model context for ordinary workflows. That gives the agent useful reasoning ability over personal data, but it places the model/provider inside the practical trust boundary.

Architectures that prevent private data from reaching the model/provider have a different and stronger privacy boundary, with different usability constraints.

### Side channels and non-obvious egress

Private information can leave through channels that do not look like ordinary “send message” actions:

- URL paths and query strings.
- Search queries.
- Redirects.
- Image or resource loads.
- DNS names.
- Timing and request size.
- File names.
- Browser form submissions.

OpenAI’s link-safety work highlights URL-based exfiltration as a distinct risk class for agentic browsing.

## The research field and where Guardian fits

The literature on private data in LLM agents mostly differs on one question: where does the decision about an appropriate flow live?

| Family | Where appropriateness lives | What enforces it | Examples |
|---|---|---|---|
| In-the-model | In the model's judgment | The model itself, prompted or trained | PrivacyChecker (prompt-time CI reasoning); CI-RL, CPPLM, GoldCoin (training-time) |
| Deterministic enforcement | In a policy outside the model | Deterministic code the model cannot influence | Conseca, CaMeL, RTBAS, GAAP, the information-flow-control lineage — **and Guardian** |
| Measurement-only | N/A (does not enforce) | Benchmarks that score whether appropriateness was achieved | ConfAIde → PrivacyLens → CI-Bench → PrivaCI-Bench → CIMemories |

Guardian is in the deterministic-enforcement family. If prompt injection cannot be solved at the model layer, then a defense whose final decision routes through model judgment inherits the weakness it is trying to defend against. Guardian can still use an LLM as a verifier signal, but the security boundary is the deterministic policy around that signal.

Guardian also takes a narrow position on contextual integrity. CI describes flows with parameters such as sender, receiver, subject, information type, and transmission principle, and its formal versions add governance concepts such as traces, policies, policy combination, and compliance. Guardian implements part of that governance side: session taint is a trace, allow/deny rules are policies, and `decide` is a compliance check over accumulated context. It does not implement receiver-context norms or policy combination. Instead, as a single-owner personal tool, it anchors on owner authorization.

The closest architectural neighbor is Conseca. Both assume the model can be fooled and enforce a policy outside it. Conseca generates policy from trusted context only, which keeps attacker-controlled content away from the policy model but makes data-dependent flows hard. Guardian allows its `llm` verifier to inspect the real payload for those flows, then constrains that judgment with deterministic corroboration. CaMeL, RTBAS, and GAAP are stronger or more formal in their stated models; Guardian is the more operational local-agent design.

The open problems Guardian does not solve are still real: live adversarial evaluation, policy combination across contexts, receiver-context norms, and theory-of-mind tracking across parties. Those are either field-wide research problems or outside a single-owner confidentiality tool.

## Boundary statement

Guardian is accurately described as:

> A privacy-aware egress and declassification layer for Hermes Agent. It tracks private context entering a session and blocks or approval-gates classified outbound actions through Hermes-mediated tools. It complements Hermes sandboxing, credential scoping, SSRF protection, gateway authorization, and dangerous-command approval.

Its primary protected asset is personal content that is confidential because of its source, not because it matches a sensitive pattern. That is the part signature-based scanners and DLP cannot see.

Guardian is not a complete prompt-injection solution or a proof of noninterference. It reduces prompt-injection data-exfiltration risk by enforcing a policy boundary at outbound tool use, assuming relevant actions are mediated and the Hermes runtime is appropriately constrained.

## References

- Pei, "When secrets don't look like secrets" (plain-language companion to this document; the "secrets that don't look like secrets" thesis and origin story): <https://kevinpei.com/posts/thoughts-on-agent-privacy>
- Hermes Agent Security Policy: <https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md>
- Hermes Security Guide: <https://hermes-agent.nousresearch.com/docs/user-guide/security>
- Hermes Configuration Guide: <https://hermes-agent.nousresearch.com/docs/user-guide/configuration>
- OpenAI, “Designing AI agents to resist prompt injection”: <https://openai.com/index/designing-agents-to-resist-prompt-injection/>
- OpenAI, “Keeping your data safe when an AI agent clicks a link”: <https://openai.com/index/ai-agent-link-safety/>
- OpenAI Lockdown Mode: <https://help.openai.com/articles/20001061>
- Anthropic, “making Claude Code more secure and autonomous”: <https://www.anthropic.com/engineering/claude-code-sandboxing>
- Anthropic, “How we contain Claude across products”: <https://www.anthropic.com/engineering/how-we-contain-claude>
- Microsoft Copilot Studio external security provider: <https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider>
- Microsoft Copilot Studio tool execution webhook: <https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-webhooks-interface-developers>
- Microsoft, “Detecting and mitigating common agent misconfigurations”: <https://www.microsoft.com/en-us/security/blog/2026/02/12/copilot-studio-agent-security-top-10-risks-detect-prevent/>
- Invariant Labs, Guardrails / Gateway / mcp-scan: <https://github.com/invariantlabs-ai/invariant>
- Snyk, “Snyk Acquires Invariant Labs to Accelerate Agentic AI Security Innovation”: <https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/>
- Pipelock (PipeLab), open-source AI agent firewall: <https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/>
- LLM Guard (Protect AI): <https://github.com/protectai/llm-guard>
- OpenClaw PRISM, “zero-fork runtime security for tool-augmented agents”: <https://arxiv.org/abs/2603.11853>

### Foundations: injection (in)solvability

- Abdelnabi, S., & Bagdasarian, E. (2026). *AI agents may always fall for prompt injections*. arXiv. <https://doi.org/10.48550/arXiv.2605.17634>
- Choudhary, S., Anshumaan, D., Palumbo, N., & Jha, S. (2025). *How not to detect prompt injections with an LLM*. arXiv. <https://doi.org/10.48550/arXiv.2507.05630>
- Maloyan, N., & Namiot, D. (2026). *Prompt injection attacks on agentic coding assistants: A systematic analysis of vulnerabilities in skills, tools, and protocol ecosystems*. arXiv. <https://doi.org/10.48550/arXiv.2601.17548>
- “Design Patterns for Securing LLM Agents against Prompt Injections” (dual-LLM / quarantined-LLM containment): <https://arxiv.org/abs/2506.08837>

### Foundations: deterministic enforcement (Guardian's family)

- CaMeL, “Defeating Prompt Injections by Design”: <https://arxiv.org/abs/2503.18813>
- RTBAS, “Defending LLM Agents Against Prompt Injection and Privacy Leakage”: <https://arxiv.org/abs/2502.08966>
- GAAP, “An AI Agent Execution Environment to Safeguard User Data”: <https://arxiv.org/abs/2604.19657>
- Conseca, “Contextual Agent Security: A Policy for Every Purpose” (just-in-time policies; deterministic enforcement; policy model isolated to trusted context): <https://arxiv.org/abs/2501.17070>
- Sandlock, “Confining AI Agent Code with Unprivileged Linux Primitives”: <https://arxiv.org/abs/2605.26298>

### Foundations: contextual integrity and its application to LLMs

- Nissenbaum, “Privacy as Contextual Integrity” (the source theory): Washington Law Review 79(1), 2004.
- Barth, Datta, Mitchell, Nissenbaum, “Privacy and Contextual Integrity: Framework and Applications” (the formal model; the nine parameters): IEEE S&P, 2006.
- Shvartzshnaider & Duddu, “Position: Contextual Integrity is Inadequately Applied to Language Models” (the CI-washing critique; why borrowing the term loosely is unsound): <https://arxiv.org/abs/2501.19173>
- Hassanpour & Yang, “Contextual Integrity in Large Language Models: A Review” (parameter-coverage gap map; governance parameters underaddressed): J. Cybersecurity and Privacy 6(2):74, 2026.
- “Privacy in Action / PrivacyChecker” (CI reasoning as in-model mitigation; the model-judgment family Guardian is a foil to): <https://aclanthology.org/2025.findings-emnlp.925/>

### Foundations: in-model mitigation (the family Guardian contrasts with)

- CI-RL, “Contextual Integrity in LLMs via Reasoning and Reinforcement Learning” (training-time CI alignment): <https://arxiv.org/abs/2506.04245>
- GoldCoin, “Grounding Large Language Models in Privacy Laws via Contextual Integrity Theory” (statute-grounded fine-tuning): <https://arxiv.org/abs/2406.11149>
- CPPLM, “Large Language Models Can Be Contextual Privacy Protection Learners” (instruction tuning with penalty-based loss): EMNLP 2024.
- AirGapAgent, “Protecting Privacy-Conscious Conversational Agents” (context-minimization / data minimizer): ACM CCS 2024.

### Foundations: evaluation lineage

- ConfAIde, “Can LLMs Keep a Secret? Testing Privacy Implications via Contextual Integrity Theory”: ICLR 2024.
- PrivacyLens, “Evaluating Privacy Norm Awareness of Language Models in Action”: <https://arxiv.org/abs/2409.00138>
- CI-Bench, “Benchmarking Contextual Integrity of AI Assistants on Synthetic Data”: <https://arxiv.org/abs/2409.13903>
- PrivaCI-Bench, “Evaluating Privacy with Contextual Integrity and Legal Compliance”: <https://arxiv.org/abs/2502.17041>
- CIMemories, “A Compositional Benchmark for Contextual Integrity of Persistent Memory in LLMs”: <https://arxiv.org/abs/2511.14937>
