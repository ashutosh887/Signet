import { HTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

type DivProps = HTMLAttributes<HTMLDivElement>;

export function Card({
  className = "",
  children,
  ...rest
}: DivProps & { children: ReactNode }) {
  return (
    <div
      className={`rounded-xl border border-neutral-800/80 bg-neutral-900/40 shadow-[0_1px_0_0_rgba(255,255,255,0.04)_inset] ${className}`}
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
      className={`px-5 py-4 border-b border-neutral-800/80 ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  children,
  subtitle,
}: {
  children: ReactNode;
  subtitle?: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <h3 className="text-sm font-semibold text-neutral-100 tracking-tight">
        {children}
      </h3>
      {subtitle && (
        <p className="text-[12px] text-neutral-500 leading-relaxed">
          {subtitle}
        </p>
      )}
    </div>
  );
}

export function CardContent({
  className = "",
  children,
  ...rest
}: DivProps & { children: ReactNode }) {
  return (
    <div className={`px-5 py-4 ${className}`} {...rest}>
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
  className = "",
}: {
  tone?: "neutral" | "ok" | "warn" | "bad" | "accent" | "muted";
  children: ReactNode;
  className?: string;
}) {
  const tones = {
    neutral: "bg-neutral-800/60 text-neutral-300 border-neutral-700",
    muted: "bg-transparent text-neutral-500 border-neutral-800",
    ok: "bg-emerald-950/40 text-emerald-300 border-emerald-900",
    warn: "bg-amber-950/40 text-amber-300 border-amber-900",
    bad: "bg-rose-950/40 text-rose-300 border-rose-900",
    accent: "bg-indigo-950/40 text-indigo-300 border-indigo-900",
  }[tone];
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] mono ${tones} ${className}`}
    >
      {children}
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "neutral" | "ok" | "warn" | "bad" | "accent";
}) {
  const accent = {
    neutral: "text-neutral-100",
    ok: "text-emerald-300",
    warn: "text-amber-300",
    bad: "text-rose-300",
    accent: "text-indigo-300",
  }[tone];
  return (
    <Card className="px-5 py-4 flex flex-col gap-1.5">
      <span className="text-[11px] uppercase tracking-[0.08em] text-neutral-500 font-medium">
        {label}
      </span>
      <span className={`text-2xl font-semibold tracking-tight tabular-nums ${accent}`}>
        {value}
      </span>
      {hint && (
        <span className="text-[12px] text-neutral-500 leading-snug">
          {hint}
        </span>
      )}
    </Card>
  );
}

export function CopyButton({ text }: { text: string }) {
  return (
    <button
      type="button"
      onClick={() => {
        if (typeof navigator !== "undefined" && navigator.clipboard) {
          navigator.clipboard.writeText(text).catch(() => {});
        }
      }}
      className="text-[10px] uppercase tracking-wider text-neutral-500 hover:text-neutral-200 px-1.5 py-0.5 rounded border border-neutral-800 hover:border-neutral-700"
    >
      copy
    </button>
  );
}
