import { useCallback, useEffect, useRef, useState } from "@/sdk";
import { text } from "@/lib/format";
import type { Toast, ToastVariant } from "@/types";

export interface ToastController {
  toasts: Toast[];
  showToast: (message?: unknown, variant?: ToastVariant) => void;
  dismissToast: (id: string) => void;
}

// Transient notifications with auto-dismiss timers. At most four are kept; the
// cleanup effect clears any pending timers on unmount.
export function useToasts(): ToastController {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timers = useRef<Record<string, number>>({});

  const dismissToast = useCallback((id: string) => {
    const current = timers.current || {};
    if (current[id]) {
      window.clearTimeout(current[id]);
      delete current[id];
    }
    setToasts((items) => items.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback(
    (message?: unknown, variant?: ToastVariant) => {
      const id =
        "toast_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
      const toast: Toast = {
        id,
        message: text(message, variant === "error" ? "Something went wrong." : "Saved."),
        variant: variant || "success",
      };
      setToasts((items) => items.concat([toast]).slice(-4));
      timers.current[id] = window.setTimeout(
        () => dismissToast(id),
        toast.variant === "error" ? 5200 : 3600,
      );
    },
    [dismissToast],
  );

  useEffect(
    () => () => {
      const current = timers.current || {};
      Object.keys(current).forEach((id) => window.clearTimeout(current[id]));
      timers.current = {};
    },
    [],
  );

  return { toasts, showToast, dismissToast };
}
