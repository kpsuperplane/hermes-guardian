# Hermes Guardian Defense Theory

## Abstract

Hermes Guardian is a privacy-aware egress and declassification layer for Hermes Agent. Its distinctive contribution is the *asset* it protects, not only the mechanism it uses. Credentials, API keys, and most PII have a recognizable signature — they match patterns, which is what scanner, DLP, and secret-detection tools key on. The content a personal agent most needs to read — an email body, a contact list, a calendar, a Notion page — has no signature; it is private only because of where it came from. Guardian treats this *provenance-private* content as its primary protected asset, tracking it by origin so that data with no detectable shape is still governed at egress.

Its central security idea is not prompt-injection detection. Instead, Guardian assumes that untrusted text may influence the language model and places policy enforcement at the point where private information could leave the agent through tools, messages, browser actions, or other mediated outbound channels.

In this model, Hermes provides the lower-level runtime controls: sandboxing, credential scoping, private-network protections, gateway authorization, dangerous-command checks, and other hygiene mechanisms. Guardian adds a semantic information-flow layer above those controls: it tracks when private context has entered a session, classifies outbound actions, and blocks or approval-gates flows that lack an explicit declassification rule.

The result is best understood as a defense-in-depth architecture. Hermes reduces what the agent and its tools can reach. Guardian reduces where information the agent has legitimately learned can go.

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

The combined Hermes + Guardian stack is comparable in shape to modern industry agent-security systems: containment and credential minimization below, source/sink or action inspection above, and user approval for ambiguous or sensitive flows. It remains less formal than research systems such as CaMeL, RTBAS, and GAAP, but it is more directly deployable for a general-purpose local personal agent.

What most distinguishes Guardian among practical, local-first, default-configured personal-agent guards is the asset it makes primary. Pattern-based tools — DLP, PII and secret scanners, CodeShield — protect signature-detectable data; they are structurally blind to content whose only marker of privacy is its provenance, because there is no pattern for them to match. Guardian's source-based taint protects that provenance-private content by origin, which is why its data classes are email, contacts, calendar, and documents rather than secret patterns: a different protected asset, not a weaker secret scanner. Two caveats keep this calibrated. The goal is an instantiation, not an invention — the GAAP / RTBAS / contextual-integrity lineage already targets personal-data confidentiality, so Guardian is its deployable, default form rather than a new claim about what to protect. And other tools can express non-credential data-flow rules: Invariant Guardrails, for example, can encode the email `get_inbox -> send_email` shape, but only given user-authored flow rules and a proxy deployment with a telemetry path. Guardian's narrower claim is that it makes provenance-private personal content the default protected asset, locally and without authored flow rules.

## Background: the agent exfiltration problem

Prompt injection is dangerous in personal agents because the agent often combines three capabilities:

1. Access to private data.
2. Exposure to untrusted input.
3. Ability to communicate externally.

This combination is sometimes called the “lethal trifecta.” A malicious email, web page, calendar event, or document does not need to break the model in a dramatic way. It only has to influence the agent to encode private information into a URL, search query, browser action, message, API call, file upload, or final response.

Traditional prompt-injection defenses often focus on recognizing malicious instructions. That approach is useful as hygiene, but it is brittle. Attackers can paraphrase instructions, hide them in data, encode them, or frame them as legitimate workflow steps.

Guardian uses a different enforcement point. It treats prompt injection as an expected failure mode and focuses on egress:

```text
Private source observed -> session becomes tainted -> outbound action requires policy
```

This turns the problem from “Did the model understand the instruction hierarchy correctly?” into “Is this classified private context allowed to flow to this destination through this action?”

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
- Final responses delivered through gateways, cron, or shared channels.

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

Guardian can be described as a coarse-grained dynamic information-flow-control layer over Hermes-mediated actions.

### Labels

Guardian assigns private data labels to source categories such as:

- `email`
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

When a private source is observed, Guardian records taint on the session. Session taint is coarse: it marks the session as having seen private data, without proving which exact output strings depend on which exact source objects.

Guardian also keeps a volatile, metadata-only approximation of object-level provenance for copied text. For non-security-sensitive, medium-length strings in tainting tool results, it records keyed HMAC fingerprints with source labels and data classes in session memory only. When later tool arguments or final responses structurally contain a matching copied phrase, the policy can narrow the classes in scope to the matched source classes plus any private-looking argument classes. If there is no match, the text is too short, the output is paraphrased, the phrase was security-sensitive, or provenance is absent, Guardian falls back to the full session taint. Provenance is cleared on session reset and intentionally not persisted to activity, approvals, rules, or LLM verifier payloads.

This is conservative in one direction and imprecise in another:

- It can block flows even when the outgoing content is harmless, especially
  when volatile provenance cannot match a copied phrase.
- It can miss flows when the sink is not classified or when a tool reads and exfiltrates data internally before taint is recorded.

### Sink classification

Guardian classifies tool calls by action family and destination, with additive
context fields for purpose and pseudonymous recipient identity where available.
Examples include:

- Sending a message.
- Posting to a service.
- Writing through an MCP tool.
- Navigating a browser.
- Typing into a browser page.
- Running terminal or code commands.
- Calling a web or HTTP-capable tool.

The security property depends on correct sink classification. Unknown or open-ended tool ecosystems, especially MCP, are structurally harder to classify than closed built-in tool sets.

Guardian therefore classifies conservatively in both directions. A tool that matches no known built-in family is treated as an unrecognized sink and gated under taint (the `tool_unknown` family), mirroring the treatment of unknown MCP tools, rather than being allowed by default. This removes an earlier asymmetry in which unrecognized non-MCP tools failed open. The operator can revert to permissive handling globally, but that choice is explicit and surfaced as a runtime risk.

Because conservative classification produces false positives for genuinely benign custom tools, Guardian pairs it with an operator-managed tool override registry. An override is a trusted operator declaration about a specific tool or tool-name prefix: which private classes its results carry (a source declaration), and whether it is a safe non-sink, a forced-gate sink, or a specific action family (a sink declaration). Overrides are trusted for classification but are not declassification of access-sensitive content: they never bypass the non-approvable Security Module or the intrinsic same-call hard blocks.

### Declassification

Approvals and allow rules act as declassification decisions. A declassification
decision means that a particular class of private information is allowed to flow
to a particular route, and optionally a particular purpose or pseudonymous
recipient identity, through a particular kind of action under a particular
scope.

A typical decision includes:

- Owner or actor scope.
- Session or cron scope.
- Action family.
- Destination.
- Purpose token.
- Pseudonymous recipient identity.
- Data classes.
- Expiration or remaining-use limits.
- Decision reason and metadata.

Guardian’s declassification model is deliberately operational rather than mathematical. It is designed for real user workflows where some private flows are intended, such as sending a calendar summary to a trusted personal notebook.

### Security-sensitive suppression

Guardian distinguishes ordinary private context from access-sensitive content. Certain materials are not merely private; they can grant account access or enable credential compromise. Examples include:

- OTP and MFA codes.
- Magic links.
- Password reset links.
- Account verification links.
- Security-sensitive account notifications.
- Upstream redaction markers for sensitive authentication content.

These are treated differently from ordinary private information. In the Guardian model, they are candidates for categorical blocking or suppression rather than normal approval-based declassification.

The Security Module is configured through high-level rules that are enabled by default. These rules cover semantic account-security content, credential-shaped content, sensitive links, intrinsic same-call exfiltration shapes, and terminal remote-read shortcuts targeting private-network or metadata hosts. Intrinsic same-call detection is structural: it looks for local/code secret reads, browser console/CDP state reads, or obvious MCP private-source tools combined with network, webhook, or share sinks. When an enabled Security Module rule produces a finding, the action, tool result, or final response is blocked or suppressed without an approval path. Privacy allow rules, privacy mode changes, and approval commands do not declassify Security Module findings.

Security-rule toggles are administrative model changes, not declassification decisions. Disabling a Security Module rule means Guardian no longer categorically blocks that matching content or action shape. The privacy taint-and-egress layer can still gate classified private egress, but it is no substitute for the disabled non-approvable hardening category. Runtime policy snapshots, `/guardian status`, and the dashboard surface risk banners for concrete risky Guardian configuration such as disabled intrinsic same-call hardening.

### Metadata and control surfaces

Guardian's operational surfaces are designed to preserve the same policy semantics across slash commands, CLI helpers, and the dashboard. Dashboard mutation routes call the same policy mutation functions used by the command surfaces, and dashboard mutations can be disabled or guarded by an admin token.

The activity and dashboard model is metadata-only. Activity rows, approval records, policy snapshots, dashboard payloads, cron notifications, and LLM-verifier inputs should not contain raw private bodies, typed browser text, document contents, credentials, tokenized URL paths or queries, full command payloads carrying secrets, raw message recipients, or other raw content-bearing arguments. Intrinsic same-call blocks persist only bounded metadata such as action family, destination host or network class, purpose token, pseudonymous recipient identity, data classes, and sanitized reason; other action details are reduced to bounded summaries and redaction notes.

## The mediated-flow property

The most precise statement of Guardian’s current security property is:

> Guardian enforces a taint-and-approval policy over classified Hermes-mediated egress actions.

More formally:

- Let `L` be a set of private labels.
- Let `T(session)` be the set of labels observed in a session.
- Let `A(tool, args, session)` classify a proposed action as either no egress or an egress tuple `(action_family, destination, purpose, recipient_identity)`.
- Let `P(actor, session, action_family, destination, purpose, recipient_identity, labels, context)` represent allow, deny, and declassification policy.
- An action, result, or final response with an enabled Security Module finding is blocked or suppressed before ordinary privacy declassification applies.
- A mediated action is allowed when it is not classified as egress, when no private labels are in scope, or when policy allows the flow.
- A mediated action is blocked or routed to approval when it is classified as egress, private labels are in scope, and no policy allows the flow.

This is a mediated-flow guarantee rather than a universal confidentiality proof. The guarantee holds only across the actions Guardian sees and classifies.

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

A strong Hermes + Guardian deployment can be viewed as layered defense:

```text
Layer 0: OS / container / VM / network policy
  Whole-process sandboxing or isolated terminal/code backends.
  Restricted filesystem mounts.
  Minimal credential availability.
  Network egress limits or proxying.

Layer 1: Hermes platform access control
  Gateway allowlists.
  DM pairing.
  Channel and room restrictions.
  Unauthorized-user denial.

Layer 2: Hermes tool and runtime hygiene
  Dangerous-command approval.
  Hardline destructive-command blocks.
  Environment filtering.
  Credential-file passthrough controls.
  MCP environment filtering.
  SSRF and private-network protections.
  Website blocklist.

Layer 3: Guardian information-flow policy
  Non-approvable Security Module findings.
  Language-pack-backed semantic detectors.
  Source taint.
  Sink classification.
  Private-egress approval.
  Destination/action/data-class rules.
  Metadata-only policy evaluation and activity details.

Layer 4: Guardian declassification UX
  Short-lived approvals.
  Persistent allow and deny rules.
  Security-rule and language-pack controls.
  Metadata-only audit trail.
  Dashboard and slash-command controls.
```

The lower layers reduce the blast radius of compromised tools. The upper layers govern semantically meaningful data flows.

## Effect of a strong Hermes configuration

A weak runtime configuration leaves Guardian carrying too much of the security burden. If shell, code, MCP, browser, and plugins have broad host access and arbitrary network egress, a single missed classifier or bypass can become a full data leak.

A strong Hermes configuration changes the assumptions:

- Terminal and code execution occur in a sandbox or remote environment.
- Host secrets are not mounted into the tool runtime.
- Environment variables and credential files are forwarded only when explicitly configured.
- MCP subprocesses receive limited credentials.
- Private-network, loopback, and cloud-metadata URLs are blocked.
- Gateway users are authenticated and scoped.
- Most consequential actions are routed through Hermes tool mediation.

Under these assumptions, Guardian no longer functions as the sole safety layer. It functions as the semantic egress layer in a broader containment architecture.

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

Session-level taint is not complete object-level provenance. It records that private data has entered the session, and Guardian's volatile copied-phrase provenance can sometimes narrow which source classes are implicated, but it does not prove semantic dependency.

This creates predictable tradeoffs:

- Benign outbound actions may require approval because the session has private taint and no copied-phrase provenance match.
- Encoded or indirect flows can evade policy when the sink is not recognized.
- Approvals operate over action/destination/data-class context rather than a full proof of dependency.

### Detector and language coverage

Semantic scanning is finite. A language pack can improve coverage for a language or domain, but it cannot enumerate every phrase, euphemism, obfuscation, or future service-specific wording. Missing language coverage can therefore reduce pre-taint detection of account-security content, private-field hints, browser private-context hints, and sensitive links.

For that reason, language packs are not the primary confidentiality boundary. Source-based taint, conservative sink classification, credential-format scanning, Security Module hard blocks, and lower-layer Hermes containment remain load-bearing.

### Coarse declassification context

Guardian’s policy model primarily reasons over actor, session, action family,
destination, a safe purpose token, a stable pseudonymous recipient identity,
data class, and scope. Human privacy norms often depend on richer context:

- Recipient visibility.
- Destination entity.
- Data subject.
- Transmission principle.
- Time and freshness.
- Trusted user intent.

This is the central lesson of contextual-integrity approaches to privacy: information flow cannot be judged by data type and destination alone.

In `llm` mode, Guardian partially recovers the "trusted user intent" dimension without widening the metadata-only verifier surface to the full transcript. The verifier receives one additional field, `user_request_context`: a sanitized excerpt of the most recent inbound message from an authenticated session owner, captured at gateway dispatch before the model or any tool runs, and only after the Security Module clears that message. It is scoped to the CLI owner or a configured gateway owner, so group non-owners, cron, and unauthenticated senders never populate it; it carries the user turn only, not the system prompt, prior tool results, or model output; and it is sanitized, held in volatile owner-keyed state with a short TTL, and never persisted. Consistent with the egress-first thesis, the verifier treats this as authorization evidence rather than instruction: it can raise the assessed authorization level for actions the owner actually requested, but cannot override risk level or absolute deny rules, and a malicious party who is not an authenticated owner cannot inject it. This narrows the gap where an owner-requested declassification (for example, submitting a form the owner explicitly asked Guardian to submit) would otherwise be indistinguishable from attacker-driven exfiltration under metadata alone.

Both channels are operator-gated and default to the conservative posture. `llm_user_context` (default on) gates the owner channel above. `llm_cron_context` (default off) gates a parallel `cron_context` channel that, when enabled, supplies the verifier with a cron job's own sanitized stored instruction — the closest analog to "trusted user intent" for an unattended run, sourced from the owner-authored job record rather than live run context. Cron is treated more conservatively than a live owner for a structural reason: a live owner is present to catch a denied action and approve it manually, whereas a cron run is unattended and recurring. Guardian therefore caps the cron channel: a high-risk `allow` verdict on a cron session is always downgraded to manual approval, so a job can smooth routine low- and medium-risk egress but can never self-authorize a high-risk export. This keeps the human in the loop precisely where the blast radius is largest, while still reducing approval fatigue on the routine cron actions an operator has opted into.

Authorization evidence introduces a laundering risk: a request for one purpose ("subscribe to this newsletter") could be stretched to wave through an export of unrelated private data the agent happened to taint the session with ("submit my calendar event into the form"). Guardian closes this by scoping authorization to the data actually being sent, not merely to the action. The verifier input separates ambient scope (the classes the session has read) from object-level provenance over the current call's payload: each argument carries `source_classes`, and the call carries `exported_source_classes`, derived from the same volatile copied-content fingerprints used for declassification narrowing. A freshly typed email address matches no tracked source and reads as ordinary contact content; a calendar event copied from a prior read matches the calendar fingerprints and reads back as calendar-sourced. The policy then requires content/intent consistency: authorization covers only the data classes intrinsic to the request, and content whose provenance points to a source the request did not call for is a mismatch that must fall back to manual approval. Crucially, this is decided on what is provably exported rather than on ambient taint, so a broad session scope does not by itself block a narrow, authorized export.

Provenance narrowing is a structural backstop, but it is fingerprint-based and so misses short or paraphrased fragments. The more direct remedy, in `llm` mode, is to let the verifier read the real payload rather than a redacted shape of it. The justification is a trust-boundary identity: the verifier is the same model/provider the agent already uses to process all of the user's private content, so withholding that content from the verifier protects nothing against the provider while preventing it from noticing, for instance, that an "email subscription" field actually contains a calendar event. Guardian therefore relaxes the verifier-input minimization deliberately, but only there, and keeps the boundary that does independent work: at-rest exposure. Security-sensitive material (credentials, OTPs, reset links) is still stripped from the payload — and such arguments are hard-blocked before the approvable verifier runs in any case — credential-shaped tokens are removed, and the verdict rationale is sanitized before it is shown or persisted. Persistent state (activity rows, approval records, dashboard payloads, notifications) remains metadata-only. The relaxation assumes the configured verifier LLM shares the agent's trust boundary; because operators connect those LLMs themselves, that assumption is theirs to own, and it is surfaced in the documentation and dashboard.

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
- Final responses delivered to shared or automated contexts.

OpenAI’s link-safety work highlights URL-based exfiltration as a distinct risk class for agentic browsing.

## Comparison with industry systems

### OpenAI / ChatGPT agent defenses

OpenAI’s public agent-security framing emphasizes constraining risky actions, protecting sensitive data, and using source/sink-style analysis rather than relying exclusively on model obedience. OpenAI has also described URL-based data exfiltration as a concrete agent risk: a link path or query string can carry private information even when the chat transcript does not visibly display the data.

OpenAI’s Lockdown Mode further reduces exfiltration risk by limiting or disabling certain capabilities that connect to external services or the web.

| Dimension | OpenAI managed stack | Hermes + Guardian |
|---|---|---|
| Stack control | Product, model, connectors, browser, policy, and telemetry controlled by OpenAI | Strength depends on Hermes configuration and local operator choices |
| Transparency | Lower external visibility into implementation | Higher inspectability of plugin and policy |
| Containment | Product-level controls and managed execution environments | Hermes sandboxing, backend choice, and OS/container policy |
| Egress theory | Source/sink controls, link safety, lockdown-style capability reduction | Source taint, sink classification, approval/declassification |
| Operational model | Managed consumer/enterprise product | Local or self-managed personal agent |

Hermes + Guardian is conceptually similar to OpenAI’s source/sink direction, with less platform integration and more local transparency.

### Anthropic / Claude Code and Claude containment

Anthropic’s public security work emphasizes filesystem and network isolation for agentic coding environments. The core idea is that a compromised or manipulated agent cannot steal secrets it cannot read and cannot exfiltrate to destinations it cannot reach.

| Dimension | Anthropic containment | Hermes + Guardian |
|---|---|---|
| Hard boundary | Filesystem, network, and process sandboxing | Hermes sandboxing and OS/container configuration provide the hard boundary |
| Semantic data-flow policy | Less visible publicly | Guardian’s main contribution |
| Private connector egress | Product dependent | Explicit approval/rule model for mediated flows |
| Primary risk boundary | Sandbox correctness and configuration | Complete mediation, classifier accuracy, and runtime containment |

Anthropic-style containment and Guardian address different layers. Sandboxing limits reachability. Guardian governs semantically meaningful outbound flows after legitimate data access.

### Microsoft Copilot Studio / enterprise runtime protection

Microsoft Copilot Studio documents prompt-injection protections, cross-domain prompt-injection mitigations, and external security-provider mechanisms that inspect proposed tool execution and return allow/block decisions. Microsoft’s broader agent-security material also describes runtime scanning, goal-deviation detection, governance, and Defender-style integrations.

| Dimension | Microsoft enterprise stack | Hermes + Guardian |
|---|---|---|
| Identity and governance | Tenant, RBAC, admin policy, enterprise audit | Local owner/session/cron policy |
| Runtime inspection | External provider and Defender-style action inspection | Guardian hook-based action inspection |
| Detector input | May include rich execution context, depending on configuration | Designed around local, sanitized metadata |
| Deployment target | Enterprise managed agents | Personal/local Hermes agents |

Guardian sits in the same general family as enterprise runtime action inspection, but it is lighter-weight, local, and personal-agent oriented.

## Comparison with open-source agent guards

The industry comparisons above are mostly managed or enterprise products. Guardian also shares a quadrant with several open-source tools aimed at the same personal/self-hosted agent operator. These are the most directly comparable systems, and the two axes used elsewhere in this document — detection versus flow enforcement, and managed/enterprise versus local-first — separate them cleanly.

### Invariant Guardrails / Gateway

Invariant Labs' Guardrails (with its companion Gateway proxy) is the closest policy-model analog to Guardian. It is a contextual guardrail layer that sits as a proxy between an agent and its MCP servers or LLM provider, evaluating rules before and after each LLM and MCP request. Its defining feature is a Python-inspired DSL that expresses data-flow rules over the agent trace, including ordered tool-to-tool flow constraints. A canonical example raises a violation when a `send_email` call follows a `get_inbox` call, i.e. the `(ToolOutput) -> (ToolCall)` shape that Guardian approximates with coarse session taint. Invariant also ships `mcp-scan` (a scanner for prompt injection in tool descriptions, tool poisoning, and cross-origin escalation) and Explorer (a trace storage and visualization surface). Invariant Labs, an ETH Zurich spin-off, was acquired by Snyk in 2025; it coined widely used terminology such as "tool poisoning" and "MCP rug pulls."

| Dimension | Invariant Guardrails / Gateway | Hermes + Guardian |
|---|---|---|
| Policy expression | Explicit DSL with ordered tool-flow rules over the trace | Fixed taint/sink/declassification model; no user-authored flow DSL |
| Flow granularity | Rule can name specific source and sink tools in sequence | Coarse session taint with volatile copied-phrase provenance |
| Deployment shape | Proxy in front of MCP servers and the LLM provider | In-process Hermes hooks; no separate proxy |
| Observability | Explorer trace viewer and incident data | Metadata-only activity trail; no trace visualization |
| Locality and telemetry | Self-hostable, but `mcp-scan`'s remote scanning shares tool names and descriptions with the vendor's servers (invariantlabs.ai historically, Snyk after the acquisition) | Local-first; classification and policy evaluation do not call out to a vendor service |
| Track record | Published vulnerability research and named attack classes | No comparable public CVE or attack-discovery record |

Invariant is more mature and more expressive than Guardian on the policy axis: it offers a real flow DSL, a trace viewer, and a research and CVE track record Guardian does not have. Guardian's narrower contributions are that it is fully local-first with no vendor-telemetry path, and that it is integrated directly into Hermes hooks rather than relying on a separate proxy.

### Pipelock

Pipelock (by PipeLab) is an Apache-2.0 agent firewall distributed as a single Go binary. Its design is structural rather than detection-led: it separates capabilities so that the agent process holds secrets but has no direct network access, while a proxy holds network connectivity but stores no secrets, with a scanning boundary (including a DLP layer covering credential patterns) between the two. Isolation is enforced with network namespaces, iptables, Docker internal networks, or Kubernetes NetworkPolicy. Because the agent cannot reach the network directly, a compromised tool call cannot exfiltrate a secret without crossing the proxy's inspection.

| Dimension | Pipelock | Hermes + Guardian |
|---|---|---|
| Primary mechanism | Capability separation: secrets and network split across processes | Semantic taint and egress policy over mediated actions |
| Same-call source/sink | Structurally defended: the secret-holding process has no network path | Deferred to the Hermes/OS layer; Guardian does not itself break this case |
| Enforcement point | Network boundary between agent and proxy | Hermes hook layer above tool dispatch |
| Layer | Lower-layer containment | Upper-layer information-flow policy |

Pipelock directly addresses the same-call source-and-sink exfiltration shape that Guardian explicitly defers to the host runtime (see "Same-call source and sink"). It is best read as a complementary lower layer — a concrete implementation of the network-isolation assumption Guardian depends on — not a substitute for Guardian's semantic declassification, which Pipelock does not attempt. Its DLP boundary, moreover, keys on credential *patterns*: it can catch a secret crossing the proxy by its signature, but an email body or contact list crossing the same boundary has no signature to match. That provenance-private content — private by origin rather than by shape — is exactly what Guardian's source-based taint governs and what a pattern-based DLP is structurally blind to.

### LLM Guard

Protect AI's LLM Guard is an MIT-licensed, self-hosted toolkit of roughly 35 input and output scanners (15 input, 20 output) covering prompt injection, PII, secrets, toxicity, malicious URLs, and data-leakage detection. It runs locally, like Guardian, but operates by a different mechanism: it scans and sanitizes individual prompts and responses rather than tracking information flow across a session or enforcing source-to-sink policy.

| Dimension | LLM Guard | Hermes + Guardian |
|---|---|---|
| Mechanism | Per-message input/output scanning and sanitization | Session taint, sink classification, and declassification policy |
| State | Largely stateless per request | Session-scoped taint and policy state |
| Flow enforcement | None; detection and sanitization only | Blocks or approval-gates classified egress under taint |
| Locality | Local, self-hosted, offline-capable | Local-first, in-process |

LLM Guard and Guardian share the local-first axis but sit on opposite ends of the detection-versus-enforcement axis. LLM Guard's scanner breadth exceeds Guardian's deterministic and language-pack detectors, and the two are composable: scanners as pre-ingestion hygiene, Guardian as post-ingestion flow control. Neither replaces the other. Crucially, LLM Guard's PII and secret scanners detect content by signature — patterns for keys, tokens, and recognizable PII. Content with no signature, such as an email body or a calendar's contents, is invisible to them; it is private only by provenance. Guardian protects exactly that class by origin, which is the complementary half that a per-message scanner cannot reach.

### OpenClaw PRISM

OpenClaw PRISM is the closest research analog to Guardian for a personal-agent gateway. It is described as a zero-fork runtime security layer for tool-augmented agents that operates as an in-process plugin with optional accompanying services, distributing security checks across roughly ten decision points across the agent lifecycle. It combines hybrid heuristic-and-LLM scanning, risk accumulation with time-based decay, and policy-enforced restrictions on tools, file paths, network access, and secret patterns, and it explicitly targets real-world deployment with an evaluation framework over security effectiveness, false positives, and overhead.

| Dimension | OpenClaw PRISM | Hermes + Guardian |
|---|---|---|
| Position | Research system with deployment focus | Deployed Hermes plugin |
| Risk model | Accumulated risk score with time decay across lifecycle points | Per-action taint-and-policy decision at the hook |
| Scope of checks | Injection, unsafe tool execution, credential leakage, control-file tampering | Confidentiality egress and declassification over mediated sinks |
| Integration | In-process, zero-fork plugin | In-process Hermes hooks |

PRISM and Guardian occupy nearly the same niche — an in-process, local-first security layer for a tool-augmented personal agent — and overlap on several mechanisms (LLM-assisted scanning, policy-enforced restrictions). PRISM's risk-accumulation model and broader lifecycle coverage are more ambitious than Guardian's per-action egress focus; Guardian's contribution is the specific taint-and-declassification treatment of confidentiality flows rather than a general risk score.

## Comparison with theoretical systems

### CaMeL

CaMeL, “Defeating Prompt Injections by Design,” creates a protective layer around the LLM and extracts control/data flows from the trusted user query. In its model, untrusted data retrieved later cannot steer privileged program flow, and capabilities constrain unauthorized private-data flows.

| Dimension | CaMeL | Hermes + Guardian |
|---|---|---|
| Control-flow security | Trusted query determines control/data flow before untrusted data can steer it | Mixed trusted/untrusted/private context can influence the model; Guardian mediates later actions |
| Formal strength | Stronger in its stated model | Runtime-mediated guarantee over classified sinks |
| Deployability | Research/prototype constraints | Deployable as a Hermes plugin |
| Flexibility | More constrained | Better suited to general-purpose personal-agent workflows |

CaMeL is closer to secure-by-construction. Guardian is a runtime declassification layer over an existing general-purpose agent.

### RTBAS

RTBAS adapts information-flow control to tool-based LLM agents. It allows tool calls that preserve confidentiality and integrity and routes uncertain cases to user confirmation. Its dependency screeners attempt to determine whether a proposed action depends on private or untrusted inputs.

| Dimension | RTBAS | Hermes + Guardian |
|---|---|---|
| IFC granularity | Dependency screening over tool calls | Session taint plus action/destination/data-class policy |
| User involvement | Confirmation when safety cannot be established | Approval when tainted egress lacks policy |
| Attack model | Prompt injection and privacy leakage | Prompt injection leading to private egress |
| Implementation status | Research architecture | Local plugin implementation |

Guardian shares RTBAS’s information-flow intuition while using a simpler and more operational approximation.

### GAAP

GAAP proposes an execution environment for personal agents with an IFC core, private data database, permission database, disclosure log, and annotation framework. It treats disclosure to the model/provider as part of the privacy problem.

| Dimension | GAAP | Hermes + Guardian |
|---|---|---|
| Model/provider trust | Can place the model/provider outside the trust boundary | Usually places the model inside the practical trust boundary |
| Data storage | Private data database and permission database | Hermes tools plus Guardian taint, rules, and activity storage |
| Confidentiality claim | More ambitious deterministic confidentiality | Mediated egress control |
| Deployment model | Research architecture | Existing Hermes plugin |

GAAP is a broader confidentiality architecture. Guardian is focused on egress and declassification for an existing agent runtime.

### Contextual integrity approaches

Contextual-integrity analyses argue that instruction/data separation alone is insufficient because the legitimacy of an information flow depends on context: who sends what, to whom, for what purpose, under what norm.

Guardian’s policy tuple captures some of this context through actor, session,
action family, destination, purpose, pseudonymous recipient identity, data
class, and scope. It does not encode the full richness of contextual privacy
norms. This makes it practical but less expressive than a full
contextual-integrity policy system.

### Design-pattern approaches

Design-pattern research for secure LLM agents emphasizes constrained architectures such as action selectors, plan-then-execute flows, dual-LLM designs, map-reduce isolation, and context minimization. The common principle is that untrusted input is separated from consequential action selection.

Guardian provides a compensating runtime layer for a general-purpose agent. It does not impose a fixed application-specific workflow, but it can constrain outbound consequences of a workflow after private context has entered the session.

### Sandlock and low-level sandboxing

Sandboxing systems such as Sandlock focus on kernel-enforced filesystem, network, IPC, and syscall policy for AI-agent code execution.

Sandboxing and Guardian answer different questions:

- Sandboxing: “Can this process read this file, connect to this host, or perform this syscall?”
- Guardian: “Is this private-information flow authorized for this destination and action?”

The two layers are complementary: low-level confinement controls capabilities; Guardian controls semantic declassification.

## Positioning table

| Approach | Main defense | Formal strength | Practicality today | Primary gap |
|---|---|---:|---:|---|
| Prompt-only rules | Instructions telling the model not to leak | Very low | High | Model can be manipulated |
| Regex/scanner-only | Detection of malicious text or sensitive literals | Low | High | Paraphrase, encoding, and context manipulation |
| Hermes built-ins only | Containment, env filtering, SSRF, command approval, gateway auth | Medium for host/runtime containment | High | Semantic flows of legitimately observed private data |
| Guardian only | Taint and egress approval for mediated tools | Low-medium | Medium-high | Hard containment, complete mediation, same-call source/sink |
| Hermes + Guardian | Containment below, semantic policy above | Medium to medium-high for mediated flows | Medium-high | Configuration dependence and lack of formal noninterference |
| OpenAI / Anthropic / Microsoft managed stacks | Product-level sandboxing, runtime inspection, source/sink controls, governance | Medium | High | Lower transparency; platform-dependent details |
| Invariant Guardrails / Gateway | DSL flow rules over a proxy trace, plus MCP scanning and trace viz | Medium for stated flows | High | Not local-only; remote-scan telemetry path |
| Pipelock | Capability separation: secrets and network split across processes | Medium-high for the same-call case | Medium-high | No semantic declassification; DLP keys on credential signatures, not provenance |
| LLM Guard | ~35 local input/output scanners | Low | High | Detection/sanitization only, signature-based; blind to provenance-private content |
| OpenClaw PRISM | In-process risk accumulation plus policy-enforced restrictions | Medium for stated model | Medium | Research maturity; broad scope over deep confidentiality proof |
| CaMeL / RTBAS / GAAP | Formal or semi-formal control/data-flow or IFC architecture | High in stated model | Lower today | General-purpose product deployability |
| OS sandbox + formal IFC + contextual policy | Hard boundary plus precise flow control | Highest | Low today | Complexity and usability |

## Boundary statement

Guardian is accurately described as:

> A privacy-aware egress and declassification layer for Hermes Agent. It tracks private context entering a session and blocks or approval-gates classified outbound actions through Hermes-mediated tools. It complements Hermes sandboxing, credential scoping, SSRF protection, gateway authorization, and dangerous-command approval.

Its primary protected asset is provenance-private personal content — data that is confidential because of where it came from rather than because it matches a sensitive pattern — which is the half of the problem that signature-based scanners and DLP cannot see.

Guardian is not accurately described as a complete prompt-injection solution or a proof of noninterference. It reduces prompt-injection data-exfiltration risk by enforcing a policy boundary at outbound tool use, under the assumptions that relevant actions are mediated and the Hermes runtime is appropriately constrained.

## References

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
- CaMeL, “Defeating Prompt Injections by Design”: <https://arxiv.org/abs/2503.18813>
- RTBAS, “Defending LLM Agents Against Prompt Injection and Privacy Leakage”: <https://arxiv.org/abs/2502.08966>
- GAAP, “An AI Agent Execution Environment to Safeguard User Data”: <https://arxiv.org/abs/2604.19657>
- “AI Agents May Always Fall for Prompt Injections”: <https://arxiv.org/abs/2605.17634>
- “Design Patterns for Securing LLM Agents against Prompt Injections”: <https://arxiv.org/abs/2506.08837>
- Sandlock, “Confining AI Agent Code with Unprivileged Linux Primitives”: <https://arxiv.org/abs/2605.26298>
