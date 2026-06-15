"use client";

import Form from "next/form";
import Script from "next/script";
import Link from "next/link";
import {
  useActionState,
  useState,
  useRef,
  useEffect,
  useCallback,
} from "react";
import { createUserAction } from "@/actions/userActions";
import { SignUpFormState } from "@/types/types";
import {
  FormButton,
  GoogleLoginButton,
  FacebookLoginButton,
  GitHubLoginButton,
} from "@/components/buttons/button";

const initialState: SignUpFormState = {
  success: undefined,
  error: undefined,
  email: "",
  first_name: "",
  last_name: "",
  username: "",
  password: "",
  c_password: "",
  phone_number: "",
  is_staff: false,
};

export default function SignUpForm() {
  const [state, formAction, isPending] = useActionState(
    createUserAction,
    initialState,
  );

  const [v3SiteKey, setV3SiteKey] = useState<string>("");
  const [recaptchaToken, setRecaptchaToken] = useState<string>("");
  const [currentVersion, setCurrentVersion] = useState<"v3" | "v2">("v3");
  const [isFallback, setIsFallback] = useState<boolean>(false);

  const [isV2Verified, setIsV2Verified] = useState<boolean>(false);
  const v2WidgetIdRef = useRef<number | null>(null);
  const lastFetchTimeRef = useRef<number>(0);
  const formRef = useRef<HTMLFormElement | null>(null);

  const executeV3Telemetry = useCallback(() => {
    if (!v3SiteKey || currentVersion !== "v3" || !window.grecaptcha?.enterprise)
      return;

    window.grecaptcha.enterprise.ready(async () => {
      try {
        const token = await window.grecaptcha.enterprise.execute(v3SiteKey, {
          action: "signup", // Updated context token action key
        });
        setRecaptchaToken(token);
        lastFetchTimeRef.current = Date.now();
      } catch (error) {
        console.error("V3 Smart Telemetry execution failed:", error);
      }
    });
  }, [v3SiteKey, currentVersion]);

  useEffect(() => {
    async function fetchV3Key() {
      try {
        const response = await fetch("/api/recaptcha-key-v3");
        const data = await response.json();
        if (data.sitekey) setV3SiteKey(data.sitekey);
      } catch (err) {
        console.error("Failed to load reCAPTCHA v3 sitekey", err);
      }
    }
    fetchV3Key();
  }, []);

  useEffect(() => {
    if (v3SiteKey) executeV3Telemetry();
  }, [v3SiteKey, executeV3Telemetry]);

  const handleUserActivity = () => {
    if (currentVersion !== "v3") return;
    const now = Date.now();
    if (now - lastFetchTimeRef.current > 90000) {
      executeV3Telemetry();
    }
  };

  useEffect(() => {
    if (state && "error" in state && state.error) {
      if (currentVersion === "v3") {
        if (typeof state.error === "string" && state.error.includes("Score")) {
          setIsFallback(true);
        } else {
          setIsFallback(false);
          executeV3Telemetry();
        }
      } else if (
        currentVersion === "v2" &&
        v2WidgetIdRef.current !== null &&
        window.grecaptcha
      ) {
        window.grecaptcha.enterprise.reset(v2WidgetIdRef.current);
        setIsV2Verified(false);
        setRecaptchaToken("");
      }
    }
  }, [state, currentVersion, executeV3Telemetry]);

  useEffect(() => {
    if (isFallback && currentVersion === "v3") {
      setCurrentVersion("v2");
      setRecaptchaToken("");

      window.onloadCallback = async () => {
        if (v2WidgetIdRef.current !== null) return;

        if (window.grecaptcha?.enterprise) {
          try {
            const response = await fetch("/api/recaptcha-key-v2");
            const data = await response.json();
            if (data.sitekey) {
              const widgetId = window.grecaptcha.enterprise.render(
                "recaptcha-container",
                {
                  sitekey: data.sitekey,
                  theme: "light",
                  action: "signup",
                  callback: (token: string) => {
                    setIsV2Verified(true);
                    setRecaptchaToken(token);
                  },
                  "expired-callback": () => {
                    setIsV2Verified(false);
                    setRecaptchaToken("");
                  },
                  "error-callback": () => {
                    setIsV2Verified(false);
                    setRecaptchaToken("");
                  },
                },
              );
              v2WidgetIdRef.current = widgetId;
            }
          } catch (err) {
            console.error("Failed mounting V2 fallback framework", err);
          }
        }
      };

      if (window.grecaptcha?.enterprise) {
        window.onloadCallback();
      }
    }
  }, [currentVersion, isFallback]);

  useEffect(() => {
    return () => {
      window.onloadCallback = () => {};
    };
  }, []);

  return (
    <>
      {currentVersion === "v3" && v3SiteKey && (
        <Script
          src={`https://www.google.com/recaptcha/enterprise.js?render=${v3SiteKey}`}
          strategy="afterInteractive"
        />
      )}

      {currentVersion === "v2" && (
        <Script
          src={`https://www.google.com/recaptcha/enterprise.js?onload=onloadCallback&render=explicit`}
          strategy="afterInteractive"
        />
      )}

      <div className="w-full max-w-[540px]  flex flex-col items-center">
        <Form
          ref={formRef}
          action={formAction}
          onMouseMove={handleUserActivity}
          onFocusCapture={handleUserActivity}
          onInput={handleUserActivity}
          className="w-full flex flex-col gap-[20px]"
        >
          {/* 1. Email Input */}
          <div className="w-full flex flex-col gap-1">
            <div className="w-full h-[42px]">
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                defaultValue={state && "email" in state ? state.email : ""}
                disabled={isPending}
                required
                placeholder="Email*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.email !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.email}
                </p>
              )}
          </div>

          {/* 2. First Name Input */}
          <div className="w-full flex flex-col gap-1">
            <div className="w-full h-[42px]">
              <input
                id="first_name"
                name="first_name" // Aligned to match backend parameter syntax expectations
                type="text"
                autoComplete="given-name"
                defaultValue={
                  state && "first_name" in state ? state.first_name : ""
                }
                disabled={isPending}
                placeholder="First Name"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.first_name !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.first_name}
                </p>
              )}
          </div>
          {/* 3. Last Name Input */}
          <div className="w-full flex flex-col gap-1">
            <div className="w-full h-[42px]">
              <input
                id="last_name"
                name="last_name" // Aligned to match backend parameter syntax expectations
                type="text"
                autoComplete="family-name"
                defaultValue={
                  state && "last_name" in state ? state.last_name : ""
                }
                disabled={isPending}
                placeholder="Last Name"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.last_name !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.last_name}
                </p>
              )}
          </div>

          {/* 4. Username Input Block + Subtext */}
          <div className="w-full flex flex-col gap-1.5">
            <div className="w-full h-[42px]">
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                defaultValue={
                  state && "username" in state ? state.username : ""
                }
                disabled={isPending}
                placeholder="Username"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.username !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.username}
                </p>
              )}
            <div className="pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[10px] leading-[13px] text-[#000000] opacity-80 space-y-0.5">
              <p>
                Username must be at least 6 characters long, and cannot contain
                spaces.
              </p>
              <p>
                Username can only contain letters, numbers, periods,
                underscores, hyphens, and @ signs.
              </p>
            </div>
          </div>

          {/* 5. Password Input Block + Subtext */}
          <div className="w-full flex flex-col gap-1.5">
            <div className="w-full h-[42px]">
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="new-password"
                defaultValue={
                  state && "password" in state ? state.password : ""
                }
                disabled={isPending}
                required
                placeholder="Password*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.password !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {String(state.error.password)}
                </p>
              )}
            <div className="pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[10px] leading-[13px] text-[#000000] opacity-80 space-y-0.5">
              <p>Password must be at least 8 characters.</p>
              <p>
                Must include at least one uppercase letter, one lowercase
                letter, one number, one special character.
              </p>
            </div>
          </div>

          {/* 6. Confirm Password Input */}
          <div className="w-full flex flex-col gap-1">
            <div className="w-full h-[42px]">
              <input
                id="c_password"
                name="c_password" // Aligned to match backend confirmation parameter key
                type="password"
                autoComplete="new-password"
                defaultValue={
                  state && "c_password" in state ? state.c_password : ""
                }
                disabled={isPending}
                required
                placeholder="Confirm Password*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[16px] text-[#000000] placeholder-[#000000] focus:outline-none focus:border-[#263775] transition-all"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              state.error.c_password !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.c_password}
                </p>
              )}
          </div>

          {/* V2 Manual Checkbox Captcha Fallback (matches image mockup area) */}
          {currentVersion === "v2" && (
            <div className="w-full flex justify-center max-w-full overflow-hidden my-1">
              <div
                id="recaptcha-container"
                className="scale-[0.9] sm:scale-100 origin-center"
              ></div>
            </div>
          )}

          <input type="hidden" name="recaptchaToken" value={recaptchaToken} />
          <input type="hidden" name="recaptchaVersion" value={currentVersion} />

          {/* 7. Success Banner Box placement as styled in mockup image */}
          {state && "success" in state && state.success && (
            <div className="w-full h-[42px] box-border bg-[rgba(63,221,0,0.15)] border-2 border-[#368C04] rounded-[93px] flex items-center justify-center px-4">
              <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#368C04]">
                {state.success}
              </span>
            </div>
          )}

          {/* Error Banner Box placement fallback */}
          {state &&
            "error" in state &&
            state.error &&
            typeof state.error === "object" &&
            state.error.global !== "" &&
            state.error.global && (
              <div className="w-full h-[42px] box-border bg-[rgba(255,5,5,0.15)] border-2 border-[#E30202] rounded-[93px] flex items-center justify-center px-4">
                <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#D80E0E]">
                  {state.error.global}
                </span>
              </div>
            )}

          {/* Action Control Trigger Cluster */}
          <div className="w-full flex flex-col gap-[10px] mt-[5px]">
            <div className="w-full h-[45px]">
              <FormButton
                disabled={
                  isPending ||
                  (currentVersion === "v3" && !recaptchaToken) ||
                  (currentVersion === "v2" && !isV2Verified)
                }
                mode="signup"
              />
            </div>
            <div className="w-full h-[45px] relative">
              <GoogleLoginButton />
            </div>
            <div className="w-full h-[45px] relative">
              <FacebookLoginButton />
            </div>
            <div className="w-full h-[45px] relative">
              <GitHubLoginButton />
            </div>
          </div>

          {/* Redirect Navigation Footer */}
          <div className="w-full text-center mt-2 font-['Merriweather'] text-[15px] text-[#000000]">
            Already have an account?{" "}
            <Link
              href="/auth/login"
              className="font-bold underline hover:opacity-80"
            >
              Login
            </Link>
          </div>
        </Form>
      </div>
    </>
  );
}
