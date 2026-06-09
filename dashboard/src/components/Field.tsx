import { React } from "@/sdk";

export interface FieldProps {
  label: React.ReactNode;
  children?: React.ReactNode;
}

export function Field({ label, children }: FieldProps) {
  return (
    <label className="hermes-guardian-field">
      {label}
      {children}
    </label>
  );
}
