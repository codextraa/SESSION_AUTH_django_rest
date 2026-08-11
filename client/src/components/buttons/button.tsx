"use client";

import Link from "next/link";
import Image from "next/image";
import { useFormStatus } from "react-dom";
import { useRouter } from "next/navigation";

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

interface FormButtonProps {
  disabled: boolean;
  mode: "login" | "signup"; // String literal types to avoid any accidental text input errors
}

export function FormButton({ disabled, mode }: FormButtonProps) {
  const { pending } = useFormStatus();
  const isPending = pending || false;

  return (
    <button
      type="submit"
      disabled={disabled || isPending}
      className="w-full h-[45px] bg-[#263775] rounded-[37px] transition-all hover:opacity-90 disabled:opacity-50 active:scale-[0.99] cursor-pointer flex items-center justify-center"
    >
      <span className="font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]">
        {isPending
          ? mode === "login"
            ? "Checking..."
            : "Signing up..."
          : mode === "login"
            ? "Login"
            : "Sign Up"}
      </span>
    </button>
  );
}

interface SocialButtonProps {
  onClick?: () => void;
  className?: string;
}

const googleLogo = "/assets/google-icon.svg";
const facebookLogo = "/assets/facebook-icon.svg";
const githubLogo = "/assets/github-icon.svg";
const microsoftLogo = "/assets/microsoft-icon.svg";
const linkedinLogo = "/assets/linkedin-icon.svg";
const amazonLogo = "/assets/amazon-icon.svg";

const buttonBaseStyle =
  "w-full max-w-[540px] h-[45px] bg-[#2E2E2E] rounded-[37px] transition-all hover:opacity-90 active:scale-[0.99] cursor-pointer flex items-center justify-center gap-[10px]";
const labelStyle =
  "font-['Merriweather'] font-bold text-[18px] leading-[23px] text-[#E7E7E7]";

// 1. Google Login Button
export function GoogleLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Google</span>
      <Image
        src={googleLogo}
        width={24}
        height={24}
        alt="Google logo"
        className="w-[24px] h-[24px] block"
      />
    </button>
  );
}

// 2. Facebook Login Button
export function FacebookLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Facebook</span>
      <Image
        src={facebookLogo}
        width={15}
        height={24}
        alt="Facebook logo"
        className="w-[15px] h-[24px] block"
      />
    </button>
  );
}

// 3. GitHub Login Button
export function GithubLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Github</span>
      <Image
        src={githubLogo}
        width={24}
        height={24}
        alt="GitHub logo"
        className="w-[24px] h-[24px] block"
      />
    </button>
  );
}

// 4. Microsoft Login Button
export function MicrosoftLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Microsoft</span>
      <Image
        src={microsoftLogo}
        width={21}
        height={21}
        alt="Microsoft logo"
        className="w-[21px] h-[21px] block"
      />
    </button>
  );
}

// 5. LinkedIn Login Button
export function LinkedinLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Linkedin</span>
      <Image
        src={linkedinLogo}
        width={22}
        height={22}
        alt="LinkedIn logo"
        className="w-[22px] h-[22px] block"
      />
    </button>
  );
}

// 6. Amazon Login Button
export function AmazonLoginButton({
  onClick,
  className = "",
}: SocialButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${buttonBaseStyle} ${className}`}
    >
      <span className={labelStyle}>Login with Amazon</span>
      <Image
        src={amazonLogo}
        width={24}
        height={24}
        alt="Amazon logo"
        className="w-[24px] h-[24px] block"
      />
    </button>
  );
}

interface EyeButtonProps {
  action: () => void;
  showPassword: boolean;
  isPending: boolean;
}

export function EyeButton({ action, showPassword, isPending }: EyeButtonProps) {
  return (
    <button
      type="button"
      onClick={action}
      className="absolute top-1/2 right-[10px] -translate-y-1/2 bg-transparent border-none p-[5px] z-10 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 group selection:bg-transparent"
      aria-label={showPassword ? "Hide password" : "Show password"}
      disabled={isPending}
    >
      <Image
        src={
          showPassword ? "/assets/eye-closed-icon.svg" : "/assets/eye-icon.svg"
        }
        width={20}
        height={14}
        alt={showPassword ? "Hidden" : "Visible"}
        className="w-[20px] h-[14px] block opacity-80 group-hover:opacity-100 transition-opacity duration-150"
      />
    </button>
  );
}

export function OTPFormSubmitButton() {
  const { pending } = useFormStatus();

  return (
    <button
      type="submit"
      disabled={pending}
      className="w-[183px] h-[52px] bg-[#263775] text-white rounded-[56px] font-['Merriweather'] font-bold text-base flex items-center justify-center transition-opacity hover:opacity-90 disabled:opacity-50"
    >
      {pending ? "Verifying..." : "Verify OTP"}
    </button>
  );
}

export function OTPBackToLoginButton() {
  const router = useRouter();

  return (
    <button
      type="button"
      onClick={() => router.push("/auth/login")}
      className="font-['Merriweather'] font-bold text-[18px] text-black mt-[25px] hover:underline"
    >
      Back to Login
    </button>
  );
}

interface OTPResendButtonProps {
  onResend: () => void;
}

export function OTPResendButton({ onResend }: OTPResendButtonProps) {
  return (
    <button
      type="button"
      onClick={onResend}
      className="w-[183px] h-[52px] bg-[#4285F4] text-[#E7E7E7] rounded-[56px] font-['Merriweather'] font-bold text-base flex items-center justify-center transition-opacity hover:opacity-90"
    >
      Resend OTP
    </button>
  );
}
