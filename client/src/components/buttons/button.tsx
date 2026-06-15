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
      className="w-full h-[45px] bg-[#263775] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center"
    >
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        {isPending ? "Checking..." : "Login"}
      </span>
    </button>
  );
}

export function GoogleLoginButton() {
  return (
    <button
      type="button"
      onClick={() => console.log("Google Auth Invoked")}
      className="w-full h-[45px] bg-[#2E2E2E] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center gap-[10px]"
    >
      {/* Label Placed Exactly to Specification Matrix */}
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        Login with Google
      </span>

      {/* Recreated Responsive Combined Google SVG Component Icon Grid */}
      <div className="w-[24px] h-[24px] flex flex-wrap relative">
        <svg viewBox="0 0 24 24" className="w-full h-full" fill="#E7E7E7">
          {/* Top Red Arc */}
          <path
            fill="#E94335"
            d="M12.24 10.285V14.4h6.887c-.315 1.886-2.135 5.542-6.887 5.542-4.09 0-7.43-3.39-7.43-7.57s3.34-7.57 7.43-7.57c2.33 0 3.89.97 4.78 1.83l3.22-3.11C18.13 1.57 15.44 1 12.24 1 6.13 1 1.12 6.01 1.12 12.18s5.01 11.18 11.12 11.18c6.38 0 10.61-4.49 10.61-10.8 0-.73-.08-1.28-.18-1.78H12.24z"
          />
        </svg>
      </div>
    </button>
  );
}

/* Facebook OAuth Connector Button Component */
export function FacebookLoginButton() {
  return (
    <button
      type="button"
      onClick={() => console.log("Facebook Auth Invoked")}
      className="w-full h-[45px] bg-[#2E2E2E] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center gap-[10px]"
    >
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        Login with Facebook
      </span>

      {/* Facebook Icon Box */}
      <div className="w-[24px] h-[24px] flex items-center justify-center">
        <svg viewBox="0 0 24 24" className="w-full h-full" fill="#3B5998">
          <path d="M22 12c0-5.52-4.48-10-10-10S2 6.48 2 12c0 4.84 3.44 8.87 8 9.8V15H8v-3h2V9.5C10 7.57 11.57 6 13.5 6H16v3h-2c-.55 0-1 .45-1 1v2h3v3h-3v6.8c4.56-.93 8-4.96 8-9.8z" />
        </svg>
      </div>
    </button>
  );
}

/* GitHub OAuth Connector Button Component */
export function GitHubLoginButton() {
  return (
    <button
      type="button"
      onClick={() => console.log("GitHub Auth Invoked")}
      className="w-full h-[45px] bg-[#2E2E2E] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center gap-[10px]"
    >
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        Login with Github
      </span>

      {/* GitHub Icon Box Container Layer */}
      <div className="w-[24px] h-[24px] flex items-center justify-center">
        <svg viewBox="0 0 24 24" className="w-full h-full" fill="#E7E7E7">
          <path d="M12 2A10 10 0 0 0 2 12c0 4.42 2.87 8.17 6.84 9.5.5.08.66-.23.66-.5v-1.69c-2.77.6-3.36-1.34-3.36-1.34-.46-1.16-1.11-1.47-1.11-1.47-.9-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.07 2.91.83.1-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.1.39-1.99 1.03-2.69-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02.79-.22 1.65-.33 2.5-.33.85 0 1.71.11 2.5.33 1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.6 1.03 2.69 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85V21c0 .27.16.59.67.5C19.14 20.16 22 16.42 22 12A10 10 0 0 0 12 2z" />
        </svg>
      </div>
    </button>
  );
}
