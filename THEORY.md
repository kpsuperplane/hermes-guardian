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

## Background: the agent exfiltration problem

Prompt injection is dangerous in personal agents because the agent often combines three capabilities:

1. Access to private data.
2. Exposure to untrusted input.
3. Ability to communicate externally.

This combination is sometimes called the “lethal trifecta.” A malicious email, web page, calendar event, or document does not need to break the model in a dramatic way. It only has to influence the agent to encode private information into a URL, search query, browser action, message, API call, file upload, or final response.

Guardian treats prompt injection as an expected failure mode and enforces at egress instead of trying to recognize malicious instructions (see the Abstract). This is a forced move, not a stylistic preference: there are independent arguments that injection cannot be solved at the model layer, attacking three different defense families. Conceptually, data/instruction separation is incoherent for an agent — an agent's context is instructional everywhere by design (memory, skills, tool results, third-party content are all read as guidance), so a defense cannot separate "data" from "instructions" without breaking the workflows it protects. Formally, an LLM-based detector is as injectable as the model it guards: known-answer detection has been shown to be structurally unsound, with an adaptive attack driving detection to 0% while keeping a 91% attack success rate, because the detector executes the injected task as its own signal. Empirically, a systematization across dozens of studies finds adaptive attacks exceed 85% success against deployed defenses, with the root cause named as the architectural conflation of code and data — the same property that made SQL injection solvable by *separation* makes LLM injection unsolvable, because the model has no separate channel to separate into.

None of these results says the *damage* cannot be contained — only that the model cannot be kept from being fooled. The constructive response shared by the design-pattern literature, by control-flow systems like CaMeL, and by Guardian is the same: concede the model will be fooled, and move the security boundary outside it, onto deterministic constraints on what a fooled agent is permitted to *do*. Guardian's choice of boundary is egress:

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

Guardian can be described as a coarse-grained dynamic information-flow-control layer over Hermes-mediated actions.

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

When a private source is observed, Guardian records taint on the session. Session taint is coarse: it marks the session as having seen private data, without proving which exact output strings depend on which exact source objects.

Egress decisions reason over this ambient session taint directly. Guardian does *not* attempt per-payload object-level provenance: it never narrows the classes potentially leaving on the basis that a given payload "looks clean," because absence of detected private content is not evidence of safety. Narrowing — distinguishing a freshly typed email address from a calendar event copied out of a prior read — happens only in `llm` mode, where the verifier reads the real payload and judges its content against the authorized intent.

What *taints* on a document read is tiered by source provenance rather than left as an undifferentiated best-effort content scan. The content scan for document reads is deliberately lenient — skill docs are reference material full of placeholder contacts (`you@example.com`, a `555` sample number, an `Address:` label), and tainting on those gates unrelated egress for the rest of the turn. That leniency is safe only because the source is operator-installed reference material; extended to *any* read by tool-name shape it would be a silent fail-open, with a document read from an arbitrary MCP server serving genuinely personal content with no structural signal reading untainted. Guardian therefore tiers the source: a provably-reference read (the `skill_view` builtin, or a read whose target path resolves under the skills tree) keeps the lenient scan; a read from a server the operator has *declared* (`source = reference` or `source = private`) follows the declaration; an *undeclared* MCP document read of unknown provenance fails closed — it taints `documents` conservatively regardless of detectable signal, and Guardian records a one-time, per-server classification suggestion so the operator can declare it once. This gives source classification the same fail-closed discipline as destination classification: unknown destination is treated as external, and unknown source is treated as private until declared.

This coarseness is conservative in one direction and imprecise in another:

- It can block flows even when the outgoing content is harmless, because the full ambient session taint applies to any outward flow absent a verifier allow or a declassification rule.
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

Guardian therefore classifies conservatively in both directions. A tool that matches no known built-in family is treated as an unrecognized sink and gated under taint (the `tool_unknown` family), mirroring the treatment of unknown MCP tools, rather than being allowed by default. The operator can opt into permissive handling globally, but that choice is explicit and surfaced as a runtime risk.

A browser console eval is classified by what its expression does, not by the tool name alone. Reading page state — DOM nodes, form field values, page text, attributes — and returning it to the agent is a read, not a sink: the agent already has page read access through the ungated read tools, and any later attempt to send that data onward is itself independently gated. Guardian recognizes this through a fail-closed allowlist — the eval is treated as a read only when every operation is a known pure-read accessor — so anything it cannot prove read-only falls through to gating. An eval that writes into the page (assigning to DOM/element properties, inserting nodes, setting attributes), submits, navigates, reads a credential store, runs dynamic code, or hits a network sink is a sink. The page-write case matters even with no network call in the eval: writing tainted data into an attacker-controlled DOM is an exfiltration channel, because page-resident script can read the mutation back out. This is the same "reading is not egress" principle applied to in-page operations.

A turn-scoped deterministic rule — the cross-channel lockdown — complements the per-action decision: once an export of private classes to an external destination has been withheld in a turn, no export of those same policy classes to an external destination may be *auto*-approved for the rest of the turn — not by the read-only preset and not by the LLM verifier — whatever tool or channel the retry uses. A task-driven agent's natural response to a block is to re-route (a gated terminal export re-tried through a browser form), and the lockdown denies the re-route a softer channel, so the human review the first block requested cannot be shopped around. The lockdown state is volatile and clears on the next owner message; explicit approvals and standing rules still apply, since they are themselves the human review the lockdown preserves.

Because conservative classification produces false positives for genuinely benign custom tools, Guardian pairs it with an operator-managed tool override registry. An override is a trusted operator declaration about a specific tool or tool-name prefix: which private classes its results carry (a source declaration), and whether it is a safe non-sink, a forced-gate sink, or a specific action family (a sink declaration). Overrides are trusted for classification but are not declassification of access-sensitive content: they never bypass the non-approvable Security Module or the intrinsic same-call hard blocks.

### Declassification

Approvals and allow rules act as declassification decisions. A declassification
decision means that a particular class of private information is allowed to flow
to a particular route, and optionally a particular purpose or pseudonymous
recipient identity, through a particular kind of action under a particular
scope.

A typical decision includes:

- Owner or actor scope.
- Optional cron-job scope.
- Optional expiry.
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

Credential suppression is directional, consistent with the egress-first thesis. Hard-secret categories — private keys, cloud access keys, and password or private-key assignments — are suppressed on every surface, inbound tool results included. Account-security content is also suppressed inbound when it carries concrete access-sensitive material such as OTP/MFA codes, reset/recovery links, magic links, redaction markers, or security notifications from ordinary sources. Provably-reference material, such as `skill_view` and reads under the operator-installed skills tree, gets a narrower inbound relaxation for phrase-only account-security prose: reference docs can discuss password reset, verification, magic-link, or security-alert concepts without being access material. API/service authentication tokens are treated asymmetrically: they are blocked on egress (tool arguments, gateway dispatch, final response) but read into context on the inbound tool-result path. The rationale is that suppressing a service token at read-time breaks legitimate integrations — an MCP server surfacing its own auth token — without preventing exfiltration: a token that never leaves has not leaked, and one the model later tries to send is still caught at the sink. Reading is not egress, so the confidentiality boundary stays where Guardian enforces it.

Security-rule toggles are administrative model changes, not declassification decisions. Disabling a Security Module rule means Guardian no longer categorically blocks that matching content or action shape. The privacy taint-and-egress layer can still gate classified private egress, but it is no substitute for the disabled non-approvable hardening category. Runtime policy snapshots, `/guardian status`, and the dashboard surface risk banners for concrete risky Guardian configuration such as disabled intrinsic same-call hardening.

### Metadata and control surfaces

Guardian's operational surfaces are designed to preserve the same policy semantics across slash commands, CLI helpers, and the dashboard. Dashboard mutation routes call the same policy mutation functions used by the command surfaces, and dashboard mutations can be disabled or guarded by an admin token.

The persisted activity and dashboard model is metadata-only. Activity rows, policy snapshots, dashboard payloads, cron notifications, and standing rules should not contain raw private bodies, typed browser text, document contents, credentials, tokenized URL paths or queries, full command payloads carrying secrets, raw message recipients, or other raw content-bearing arguments. Pending approval records have one narrow exception: to support explicit `mine` and `trust` approval choices, `pending_approvals` may temporarily store bounded raw permit candidates (`permit_recipient`, `permit_host`, and `permit_command`). Those values are TTL-bound to the pending approval, are not exposed through the public dashboard policy/approval payloads, and are deleted when the approval is approved, dismissed, or pruned after expiry. The LLM-verifier input is the deliberate model-visibility exception and is *not* persisted state: in `llm` mode it carries the real action payload so the verifier can check content against intent, with the full relaxation rationale and its at-rest caveat set out in *Coarse declassification context* below. Intrinsic same-call blocks persist only bounded metadata such as action family, destination host or network class, purpose token, pseudonymous recipient identity, data classes, and a sanitized reason, with other action details reduced to bounded summaries and redaction notes.

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

Session-level taint is not complete object-level provenance. It records that private data has entered the session, but it does not prove semantic dependency between a specific output and a specific source object. Destination trust removes a large class of false positives at the *destination* end (intra-boundary flows never gate), and the `llm`-mode verifier narrows at the *content* end, but the deterministic taint itself stays coarse and conservative.

This creates predictable tradeoffs:

- Benign outbound actions to an external destination may require approval because the session has private taint, with narrowing available only via the `llm`-mode verifier (not deterministically).
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

Contextual-integrity (CI) work makes a sharper version of this point: privacy is the *appropriate flow* of information, and appropriateness is fixed by the norms of the receiving context — not by the data's type and not by the sender's wishes alone. Guardian deliberately does **not** adopt that anchor. It enforces *owner authorization*: did the data's owner authorize this flow, or is something moving it out against the owner's interest? The two criteria usually agree, but they come apart on the case CI is built around — an owner who directs a flow that the receiving context's norm would forbid (the textbook example: a clinician sending a record to a recipient the medical-context norm excludes). CI calls that a violation; Guardian, anchored on owner authorization, allows it, because the owner initiated it. That is the correct anchor for a *personal* confidentiality tool — the asset is the owner's own data and the adversary is a third party laundering it out, not the owner over-sharing someone else's data — but it is a different criterion from contextual integrity, and Guardian names it as such rather than claiming to implement CI. What Guardian borrows from CI is the descriptive vocabulary for *describing* a flow (sender, recipient, subject, information type, transmission principle); what it does not borrow is CI's normative claim that the receiver's context decides appropriateness.

In `llm` mode, Guardian partially recovers the "trusted user intent" dimension without widening the verifier surface to the full transcript. The verifier receives one additional field, `user_request_context`: a sanitized excerpt of the most recent inbound message from an authenticated session owner, captured at gateway dispatch before the model or any tool runs, and only after the Security Module clears that message. It is scoped to the CLI owner or a configured gateway owner, so group non-owners, cron, and unauthenticated senders never populate it; it carries the user turn only, not the system prompt, prior tool results, or model output; and it is sanitized, held in volatile owner-keyed state with a short TTL, and never persisted. Consistent with the egress-first thesis, the verifier treats this as authorization evidence rather than instruction: it can raise the assessed authorization level for actions the owner actually requested, but cannot override risk level or absolute deny rules, and a malicious party who is not an authenticated owner cannot inject it. This narrows the gap where an owner-requested declassification (for example, submitting a form the owner explicitly asked Guardian to submit) would otherwise be indistinguishable from attacker-driven exfiltration under metadata alone.

Crucially, the assessed authorization level is itself model-emitted, and so is the risk level — both are attacker-influenceable through the payload the verifier reads. Guardian therefore does not let the model's word alone clear a private export to an untrusted destination. A deterministic corroboration gate sits after the verdict: an `allow` of a private export whose destination trust is `external` or `unknown` is honored only when the model rates authorization `explicit`/`substantive` *and* Guardian independently holds owner/cron authorization context for this owner this window (the same `user_request_context`/`cron_context` presence the verifier input was built from). Absent that independent signal the allow is downgraded to manual approval across every risk band — so a model coaxed into labelling an exfiltration "medium risk, weakly authorized" cannot auto-clear it. Low-risk verifier-approved public remote reads are the narrow exception: if Guardian's structural safe-remote-read detector proves the call cannot carry local/private data, the call is not treated as a private export for this gate. This converts the softest model-trust point into an agreement between the model's judgment and a fact Guardian already knows, while leaving legitimate owner-driven declassification and provably safe public reads auto-allowed.

Both channels are operator-gated and default to the conservative posture. `llm_user_context` (default on) gates the owner channel above. `llm_cron_context` (default off) gates a parallel `cron_context` channel that, when enabled, supplies the verifier with a cron job's own sanitized stored instruction — the closest analog to "trusted user intent" for an unattended run, sourced from the owner-authored job record rather than live run context. Cron is treated more conservatively than a live owner for a structural reason: a live owner is present to catch a denied action and approve it manually, whereas a cron run is unattended and recurring. Guardian therefore caps the cron channel: a high-risk `allow` verdict on a cron session is always downgraded to manual approval, so a job can smooth routine low- and medium-risk egress but can never self-authorize a high-risk export. This keeps the human in the loop precisely where the blast radius is largest, while still reducing approval fatigue on the routine cron actions an operator has opted into.

Authorization evidence introduces a laundering risk: a request for one purpose ("subscribe to this newsletter") could be stretched to wave through an export of unrelated private data the agent happened to taint the session with ("submit my calendar event into the form"). Guardian closes this by scoping authorization to the data actually being sent, not merely to the action, and by having the verifier read the real payload. The verifier input carries the ambient scope (the classes the session has read) alongside the live call's actual arguments. The policy then requires content/intent consistency: authorization covers only the data classes intrinsic to the request, and a payload whose content points to a source the request did not call for — a calendar event submitted into a subscription form — is a mismatch that must fall back to manual approval. A freshly typed email address into a subscription form is consistent with the intent and need not block, even though the session may carry a broad ambient scope; the judgment is made on the payload content, not on ambient taint alone, so a broad session scope does not by itself block a narrow, authorized export. The judgment is semantic — it covers paraphrased as well as verbatim copies — and it is the only laundering catch in `llm` mode: there is no separate deterministic check for verbatim copying, so a laundering payload that fools the verifier is not otherwise caught. In `strict` mode (verifier off) every tainted egress already goes to a human, who is the laundering catch.

This judgment requires the verifier to read the real payload, in `llm` mode, rather than a redacted shape of it. The justification is a trust-boundary identity: the verifier is the same model/provider the agent already uses to process all of the user's private content, so withholding that content from the verifier protects nothing against the provider while preventing it from noticing, for instance, that an "email subscription" field actually contains a calendar event. Guardian therefore relaxes the verifier-input minimization deliberately, but only there, and keeps the boundary that does independent work: at-rest exposure. Security-sensitive material (credentials, OTPs, reset links) is still stripped from the payload — and such arguments are hard-blocked before the approvable verifier runs in any case — credential-shaped tokens are removed, and the verdict rationale is sanitized before it is shown or persisted. Persistent activity rows, rules, dashboard payloads, and notifications remain sanitized or pseudonymous, with two qualifications: the persisted rationale is a sanitized, length-capped free-text string — best-effort redaction of emails, phones, and credential-shaped tokens, not structured metadata — so a paraphrased private detail that is none of those could survive into at-rest storage for the retention window; and pending approvals may briefly hold the bounded permit candidates described under *Metadata and control surfaces*. The relaxation assumes the configured verifier LLM shares the agent's trust boundary; because operators connect those LLMs themselves, that assumption is theirs to own, and it is surfaced in the documentation and dashboard.

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

The literature on protecting private data in LLM agents organizes around one question: when an agent is about to move information, what determines whether that is appropriate, and what component enforces the answer? Different lines of work answer at different layers, and Guardian's position is clearest when seen against that structure rather than against individual products.

### Three families

Almost every system is an instance of one of three approaches.

| Family | Where appropriateness lives | What enforces it | Examples |
|---|---|---|---|
| In-the-model | In the model's judgment | The model itself, prompted or trained | PrivacyChecker (prompt-time CI reasoning); CI-RL, CPPLM, GoldCoin (training-time) |
| Deterministic enforcement | In a policy outside the model | Deterministic code the model cannot influence | Conseca, CaMeL, RTBAS, GAAP, the information-flow-control lineage — **and Guardian** |
| Measurement-only | N/A (does not enforce) | Benchmarks that score whether appropriateness was achieved | ConfAIde → PrivacyLens → CI-Bench → PrivaCI-Bench → CIMemories |

The first family makes the model better at judging appropriateness — either by prompting it to reason flow-by-flow (PrivacyChecker enumerates information flows in CI terms and asks the model to rule on each) or by training the judgment in (reinforcement learning from CI-aligned rewards, instruction tuning on positive/negative disclosure examples, grounding in legal statute). The second concedes the model's judgment is corruptible and moves the decision to a deterministic layer outside it. The third does not enforce at all; it builds the instruments that measure how badly models violate appropriateness, and is where most of the field's volume sits.

Guardian is squarely in the second family. The reason is not a stylistic preference for determinism but the argument set out under *Background*: if injection cannot be solved at the model layer, then a defense whose decision routes through model judgment inherits the same foolability it is trying to defend against. The known-answer-detection result makes this concrete — a detector built from the same kind of model it guards is provably unsound. So the first family, whatever its utility for a cooperative agent, cannot be the security boundary for an adversarial one; that boundary has to live in family two.

### The shared vocabulary, and the seam in it

Every family describes flows in Nissenbaum's five parameters — sender, receiver, subject, information type, transmission principle. That shared vocabulary is why these systems can be compared at all. But the formal CI model (Barth et al.) has nine parameters, adding *roles*, *contexts*, *traces*, *policies*, *policy combination*, and *compliance* to the descriptive core; and surveys of CI-in-LLM work find a sharp asymmetry: the field has operationalized the first five (the descriptive parameters — who, what, which context) and left the governance parameters — traces, policies, policy combination, compliance — largely unaddressed.

That asymmetry is the most useful single fact about the field, because it locates Guardian precisely. Guardian works the governance side that most CI-LLM work leaves empty:

- **Traces** — session taint is a trace: prior disclosures accumulate and constrain the appropriateness of later flows. This is Guardian's strongest under-recognized asset; almost no surveyed system implements it.
- **Policies** — destination trust and the allow/deny rules are an enforced policy layer, not a model that is merely prompted to behave.
- **Compliance** — the deterministic `decide` over the accumulated trace is a compliance check in the formal sense: does this flow, given everything the session has seen, satisfy the standing policy?

Two governance parameters Guardian does not implement, by design rather than as gaps to close:

- **Policy combination** — reconciling conflicting norms when a flow bridges two contexts (the patient who consents to share with a doctor but not an insurer present in the same exchange). This is unaddressed across the entire field; it is a hard, open research problem. In Guardian's single-owner setting it is also largely out of scope, because there is usually no second party whose context-norms Guardian is obligated to reconcile — the protected asset is one owner's data.
- **Receiver-context norms** — the heart of CI's normative claim. Guardian substitutes *owner authorization* for this (see *Coarse declassification context*): it asks whether the data's owner authorized the flow, not whether the receiving context's norm would permit it. The two usually agree but come apart on the case CI is built around — an owner directing a flow the receiving context would forbid — and Guardian, anchored on owner authorization, allows it. That is the correct anchor for a personal confidentiality tool, where the adversary is a third party laundering the owner's data out, not the owner over-sharing someone else's; but it is a different criterion from contextual integrity, and Guardian names it as such rather than presenting itself as an incomplete CI system. What Guardian borrows from CI is the descriptive vocabulary for a flow; what it does not borrow is CI's claim that the receiver's context decides appropriateness.

### The foundational disagreement Guardian takes a side in

The field is not a settled consensus; it has a live disagreement about whether the model layer can be made safe at all, and two independent critiques converge on "no." The injection-pessimists argue, conceptually and formally and empirically, that prompt injection cannot be solved at the model layer (see *Background* and the *Foundations* references). The CI-skeptics — most pointedly the position paper arguing CI is inadequately applied to LLMs — argue that the field borrows CI's name while doing data-minimization, sensitive-data protection, and the public/private dichotomy, the very framings CI was defined against, so that much "CI for LLMs" work is invoking the theory rather than applying it. The two critiques come from different directions but point the same way: away from trusting the model to judge appropriateness, and toward enforcing a boundary that does not depend on that judgment.

Guardian sits with both. Its egress-first thesis is the injection-pessimist conclusion made operational, and its owner-authorization anchor is the honest response to the CI-skeptic critique — rather than claim a normative apparatus it does not have, it names the narrower criterion it actually enforces. This is a coherent and currently under-populated position, not a hedge.

### Guardian's closest neighbor

Within the deterministic-enforcement family, Conseca (Contextual Agent Security) is the closest architectural relative. It generates a just-in-time security policy for each task from *trusted context only*, then enforces it deterministically — explicitly so that the untrusted content the agent later reads cannot alter an already-generated policy. The shared spine is exactly Guardian's: the model is assumed foolable, the decision is deterministic, and the policy reasoner is kept away from attacker-controlled input.

The instructive difference is which point each takes on the same tradeoff curve. Conseca isolates its policy generator to trusted context, and its stated limitation follows directly: it cannot easily reason about data-dependent flows ("act on the request in my manager's email"), because the data the flow depends on is the untrusted content it walled off. Guardian takes the other point — its `llm`-mode verifier reads the real payload precisely to handle the data-dependent case — and pays for it with a model-judgment surface, which it then disciplines with a deterministic corroboration gate so the payload cannot move the boundary on its own. Neither is strictly better; Guardian's choice favors confidentiality decisions that depend on content, at the cost of a larger judgment surface to constrain. CaMeL, RTBAS, and GAAP are the more formal members of the same family, stronger in their stated models and less directly deployable for a general-purpose local agent; GAAP in particular is more ambitious in placing the model provider outside the trust boundary, where Guardian keeps the provider inside it and governs egress after private context is in session.

### The live frontiers, and which Guardian touches

Three problems are where the field's energy is, and naming them shows what Guardian does and does not attempt:

- **Evaluation realism.** Every benchmark line confesses that synthetic, single-turn, single-context scenarios overstate how well anything works; live multi-agent evaluation reveals substantially higher leakage. Guardian shares this gap — it has a decision corpus and unit tests but no live adversarial benchmark — and the PrivacyLens-Live methodology is the obvious thing to borrow, extended with the laundered- and injected-exfil cases that are Guardian's differentiator.
- **Policy combination / cross-context conflict.** The hardest open problem, unsolved field-wide, and out of scope for a single-owner tool as discussed above.
- **Theory of mind.** Tracking who knows what across parties over time. Underexplored, genuinely difficult, and largely orthogonal to an egress monitor's job.

### Where this leaves Guardian

Stated in the field's own coordinates: Guardian is in the deterministic-enforcement family; it implements the governance parameters (traces, policies, compliance) that the descriptive-and-measurement majority leaves empty; it has taken the side of the injection-pessimists and the CI-skeptics in the field's central disagreement; and it anchors on owner authorization rather than receiver-context norms, which is correct for a personal confidentiality tool. The parameters it does not implement — policy combination, receiver-context norms, the full normative heuristic — are not places it lags the field; they are the parts that are hard for everyone or out of scope by the nature of an enforcement mechanism for a single owner. The contribution, if it has one, is less "a better CI system" than a worked example of what remains buildable and sound when you stop relying on model judgment entirely: owner-authorized, trace-aware boundary enforcement, scoped honestly to what it actually guarantees.

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

### Foundations: injection (in)solvability

- “AI Agents May Always Fall for Prompt Injections” (data/instruction separation is incoherent for agents; recasts injection via contextual integrity): <https://arxiv.org/abs/2605.17634>
- “How Not to Detect Prompt Injections with an LLM” (formal unsoundness of known-answer detection; the DataFlip attack): <https://arxiv.org/abs/2507.05630>
- “Prompt Injection Attacks on Agentic Coding Assistants” (SoK; >85% adaptive attack success across 78 studies; code/data conflation): <https://arxiv.org/abs/2601.17548>
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
