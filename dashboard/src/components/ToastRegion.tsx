import { React } from "@/sdk";
import type { Toast } from "@/types";

export interface ToastRegionProps {
  toasts: Toast[];
  onDismiss: (id: string) => void;
}

export function ToastRegion({ toasts, onDismiss }: ToastRegionProps) {
  if (!toasts.length) return null;
  return (
    <div
      className="hermes-guardian-toast-region"
      aria-live="polite"
      aria-atomic="false"
    >
      {toasts.map((toast) => {
        const classes = ["hermes-guardian-toast"];
        if (toast.variant === "error") classes.push("hermes-guardian-toast-error");
        return (
          <div
            key={toast.id}
            className={classes.join(" ")}
            role={toast.variant === "error" ? "alert" : "status"}
          >
            <div className="hermes-guardian-toast-message">{toast.message}</div>
            <button
              type="button"
              className="hermes-guardian-toast-close"
              aria-label="Dismiss notification"
              onClick={() => onDismiss(toast.id)}
            >
              x
            </button>
          </div>
        );
      })}
    </div>
  );
}
