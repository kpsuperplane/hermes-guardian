# Guardian dashboard plugin

This directory ships the Guardian tab for the Hermes dashboard. The Hermes
dashboard loads the plugin from the built artifacts referenced by
[`manifest.json`](manifest.json):

- `entry`: `dist/index.js` — a pre-built **IIFE** bundle
- `css`: `dist/style.css`

Per the [Hermes dashboard extension docs](https://hermes-agent.nousresearch.com/docs/user-guide/features/extending-the-dashboard),
the bundle must **not** contain React. React, hooks, the shadcn UI primitives,
`fetchJSON`, and the utility helpers are all read at runtime from
`window.__HERMES_PLUGIN_SDK__`. The single typed accessor for that global lives in
[`src/sdk.ts`](src/sdk.ts); nothing else touches `window` directly.

## Source layout

The dashboard is a TypeScript + React app under [`src/`](src). `dist/` is a
**committed build artifact** — regenerate it whenever you change `src/`.

```
src/
  index.tsx        entry — registers GuardianPage with the host
  sdk.ts           typed window.__HERMES_PLUGIN_SDK__ accessor + re-exports
  types.ts         payload + form types
  constants.ts     option lists and form defaults
  api/             fetchJSON wrapper scoped to /api/plugins/hermes-guardian
  lib/             pure formatting + rule<->form helpers
  hooks/           usePolicy, useToasts, useHistory
  components/      Button, Field, ToastRegion, RiskBanners, RuleModal, OverrideModal
  tabs/            SettingsTab, ToolsTab, RulesTab, BlocksTab, HistoryTab
  GuardianPage.tsx top-level shell, tab nav, modal orchestration
  styles/          co-located plain CSS, aggregated by styles/index.css
```

## Build

Requires [Bun](https://bun.sh) (`curl -fsSL https://bun.sh/install | bash`).

```bash
bun install        # one-time: dev-only types (TypeScript, @types/react)
bun run build      # writes dist/index.js (IIFE) and dist/style.css
bun run typecheck  # tsc --noEmit
bun run dev        # rebuild dist/index.js on change
```

JSX uses the **classic** runtime (`React.createElement`), so React only needs to
be an object in scope — there is no `react/jsx-runtime` import and no React in the
output bundle. Each `.tsx` imports `React` from `@/sdk`.

After rebuilding, reload the plugin in a running dashboard:

```bash
curl http://127.0.0.1:9119/api/dashboard/plugins/rescan
```

(or restart `hermes dashboard`).
