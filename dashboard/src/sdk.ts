// Single typed accessor for the Hermes dashboard plugin SDK.
//
// React, the hooks, the shadcn UI primitives, fetchJSON and the utility helpers
// are all provided at runtime by the host on `window.__HERMES_PLUGIN_SDK__`. We
// never import the `react` npm package as a value (that would bundle React); we
// only borrow its *types* from @types/react via `import type`. JSX compiles to
// `React.createElement` (classic runtime), so importing `React` from this module
// is all a `.tsx` file needs to render.

import type * as ReactTypes from "react";

type ReactModule = typeof ReactTypes;

interface PluginHooks {
  useState: ReactModule["useState"];
  useEffect: ReactModule["useEffect"];
  useCallback: ReactModule["useCallback"];
  useMemo: ReactModule["useMemo"];
  useRef: ReactModule["useRef"];
  useContext: ReactModule["useContext"];
  createContext: ReactModule["createContext"];
}

export interface PluginSDK {
  React: ReactModule;
  hooks: PluginHooks;
  components: Record<string, ReactTypes.ComponentType<any>>;
  api: unknown;
  fetchJSON: (input: string, init?: RequestInit) => Promise<any>;
  utils: {
    cn: (...args: unknown[]) => string;
    timeAgo: (ts: number) => string;
    isoTimeAgo: (iso: string) => string;
  };
  useI18n?: () => unknown;
}

export interface PluginRegistry {
  register: (name: string, component: ReactTypes.ComponentType<any>) => void;
  registerSlot: (
    name: string,
    slot: string,
    component: ReactTypes.ComponentType<any>,
  ) => void;
}

declare global {
  interface Window {
    __HERMES_PLUGIN_SDK__?: PluginSDK;
    __HERMES_PLUGINS__?: PluginRegistry;
  }
}

const sdk = window.__HERMES_PLUGIN_SDK__;
const registry = window.__HERMES_PLUGINS__;

if (!sdk || !registry) {
  // Matches the original bundle's guard: without the host SDK there is nothing
  // to render. Throwing here surfaces the reason in the console; the dashboard
  // logs the failed plugin script and continues loading.
  throw new Error("Hermes Guardian: plugin SDK is unavailable on window.");
}

export const SDK: PluginSDK = sdk;
export const PLUGINS: PluginRegistry = registry;

export const React = sdk.React;
export const { useState, useEffect, useCallback, useMemo, useRef } = sdk.hooks;
export const fetchJSON = sdk.fetchJSON;
