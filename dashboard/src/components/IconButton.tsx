import { React } from "@/sdk";
import { Button, type ButtonProps } from "@/components/Button";

export type DashboardIconName =
  | "chevron-left"
  | "chevron-right"
  | "edit"
  | "eye"
  | "refresh"
  | "trash"
  | "x";

export interface DashboardIconProps {
  name: DashboardIconName;
}

export interface IconButtonProps extends Omit<ButtonProps, "children"> {
  icon: DashboardIconName;
  label: string;
}

const common = {
  fill: "none",
  stroke: "currentColor",
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  strokeWidth: 2,
};

export function DashboardIcon({ name }: DashboardIconProps) {
  if (name === "chevron-left") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M15 18l-6-6 6-6" />
      </svg>
    );
  }
  if (name === "chevron-right") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M9 6l6 6-6 6" />
      </svg>
    );
  }
  if (name === "edit") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M4 20h4l11-11-4-4L4 16v4z" />
        <path {...common} d="M13 7l4 4" />
      </svg>
    );
  }
  if (name === "eye") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" />
        <circle {...common} cx="12" cy="12" r="2.5" />
      </svg>
    );
  }
  if (name === "refresh") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M20 11a8 8 0 0 0-14.5-4.5L4 8" />
        <path {...common} d="M4 4v4h4" />
        <path {...common} d="M4 13a8 8 0 0 0 14.5 4.5L20 16" />
        <path {...common} d="M20 20v-4h-4" />
      </svg>
    );
  }
  if (name === "trash") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
        <path {...common} d="M4 7h16" />
        <path {...common} d="M10 11v6" />
        <path {...common} d="M14 11v6" />
        <path {...common} d="M6 7l1 14h10l1-14" />
        <path {...common} d="M9 7V4h6v3" />
      </svg>
    );
  }
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-icon">
      <path {...common} d="M6 6l12 12" />
      <path {...common} d="M18 6L6 18" />
    </svg>
  );
}

export function IconButton({ icon, label, title, className, variant, ...rest }: IconButtonProps) {
  return (
    <Button
      {...rest}
      variant={variant || "secondary"}
      className={"hermes-guardian-icon-button" + (className ? " " + className : "")}
      aria-label={label}
      title={title || label}
    >
      <DashboardIcon name={icon} />
    </Button>
  );
}
