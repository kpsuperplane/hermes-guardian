# email-sensitive-filter

Hermes Agent user plugin that suppresses security-sensitive content before it
reaches the model.

The plugin is intentionally conservative. It blocks or suppresses content that
looks like password resets, one-time codes, magic links, account recovery,
verification flows, new-login alerts, or upstream redaction placeholders such
as `[sensitive email subject redacted]`.

The scanner recursively checks every value in tool results and inbound gateway
messages. It does not limit itself to known email fields.

## Hooks

- `transform_tool_result`: scans all tool results before they are added to
  model context.
- `pre_gateway_dispatch`: scans inbound gateway messages before agent
  dispatch.

## Install

Copy this directory into `~/.hermes/plugins/email-sensitive-filter`, then enable
it in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - email-sensitive-filter
```

Restart or reload the Hermes gateway for gateway sessions to pick it up.

## Behavior

- Sensitive structured list items are removed entirely when possible.
- Sensitive unstructured results are replaced with a suppression stub.
- Sensitive inbound gateway messages are skipped before model dispatch.
- Normal content passes through unchanged.
