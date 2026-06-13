"use client";

import Link from "next/link";
import { useFormStatus } from "react-dom";

interface TextNavLinkProps {
  href: string;
  label: string;
  className?: string;
}

export function TextNavLink({ href, label, className = "" }: TextNavLinkProps) {
  return (
    <Link
      href={href}
      className={`font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#13252E] hover:opacity-80 transition-opacity ${className}`}
    >
      {label}
    </Link>
  );
}

interface ActionNavButtonProps {
  label: string;
  href?: string;
  onClick?: () => void;
}

export function ActionNavButton({
  label,
  href,
  onClick,
}: ActionNavButtonProps) {
  const commonClasses =
    "flex items-center justify-center bg-[#263775] backdrop-blur-[7.5px] rounded-[15px] text-white font-['Merriweather'] font-bold text-[18px] px-4 py-1.5 h-[31px] transition-transform hover:scale-105 cursor-pointer";

  if (href) {
    return (
      <Link href={href} className={commonClasses}>
        {label}
      </Link>
    );
  }

  return (
    <button onClick={onClick} className={commonClasses}>
      {label}
    </button>
  );
}

export function LoginButton({ disabled }: { disabled: boolean }) {
  const { pending } = useFormStatus();
  const isPending = pending || false;

  return (
    <button
      type="submit"
      disabled={disabled || isPending}
      className="w-full h-[50px] bg-[#263775] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center"
    >
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        {isPending ? "Checking..." : "Login"}
      </span>
    </button>
  );
}
