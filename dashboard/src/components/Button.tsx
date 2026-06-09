import { React } from "@/sdk";

export type ButtonVariant = "primary" | "secondary" | "danger";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
}

export function Button({ variant, type, children, ...rest }: ButtonProps) {
  const cls =
    variant === "danger"
      ? "hermes-guardian-danger"
      : variant === "secondary"
        ? "hermes-guardian-secondary"
        : "hermes-guardian-button";
  return (
    <button {...rest} className={cls} type={type || "button"}>
      {children}
    </button>
  );
}
