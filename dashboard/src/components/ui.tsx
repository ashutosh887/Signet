import { HTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

type DivProps = HTMLAttributes<HTMLDivElement>;

export function Card({
  className = "",
  children,
  ...rest
}: DivProps & { children: ReactNode }) {
  return (
    <div
      className={`rounded-lg border border-neutral-800/80 bg-neutral-900/40 ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  className = "",
  children,
  ...rest
}: DivProps & { children: ReactNode }) {
  return (
    <div
      className={`px-4 py-3 border-b border-neutral-800/80 ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
}

export function CardTitle({ children }: { children: ReactNode }) {
  return (
    <h3 className="text-sm font-medium text-neutral-200 tracking-tight">
      {children}
    </h3>
  );
}

export function CardContent({
  className = "",
  children,
  ...rest
}: DivProps & { children: ReactNode }) {
  return (
    <div className={`px-4 py-3 ${className}`} {...rest}>
      {children}
    </div>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "outline" | "destructive" | "ghost";
  size?: "sm" | "md";
};

export function Button({
  className = "",
  variant = "default",
  size = "md",
  children,
  ...rest
}: ButtonProps) {
  const sizes =
    size === "sm" ? "text-xs px-2.5 py-1" : "text-sm px-3 py-1.5";
  const variants = {
    default:
      "bg-neutral-100 text-neutral-900 hover:bg-neutral-200 disabled:opacity-40",
    outline:
      "border border-neutral-700 text-neutral-200 hover:bg-neutral-800/60 disabled:opacity-40",
    destructive:
      "border border-rose-700/60 text-rose-300 hover:bg-rose-700/15 disabled:opacity-30 disabled:cursor-not-allowed",
    ghost: "text-neutral-300 hover:bg-neutral-800/50",
  }[variant];
  return (
    <button
      className={`inline-flex items-center justify-center rounded-md font-medium transition-colors ${sizes} ${variants} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "ok" | "warn" | "bad" | "accent";
  children: ReactNode;
}) {
  const tones = {
    neutral: "bg-neutral-800/60 text-neutral-300 border-neutral-700",
    ok: "bg-emerald-950/40 text-emerald-300 border-emerald-900",
    warn: "bg-amber-950/40 text-amber-300 border-amber-900",
    bad: "bg-rose-950/40 text-rose-300 border-rose-900",
    accent: "bg-indigo-950/40 text-indigo-300 border-indigo-900",
  }[tone];
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] mono ${tones}`}
    >
      {children}
    </span>
  );
}
