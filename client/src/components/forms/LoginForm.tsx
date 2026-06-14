"use client";

import Form from "next/form";
import Script from "next/script";
import {
  useActionState,
  useState,
  useRef,
  useEffect,
  useCallback,
} from "react";
import { loginAction } from "@/actions/authActions";
import { LoginAPIResponse } from "@/types/types";
import { redirect } from "next/navigation";
import {
  LoginButton,
  GoogleLoginButton,
  FacebookLoginButton,
  GitHubLoginButton,
} from "@/components/buttons/button";
import { DEFAULT_LOGIN_REDIRECT } from "@/route";

const initialState: LoginAPIResponse = {
  success: undefined,
  otp: undefined,
  user_id: undefined,
  error: undefined,
  email: "",
  password: "",
};

export default function LoginForm() {
  const [state, formAction, isPending] = useActionState(
    loginAction,
    initialState,
  );

  const [v3SiteKey, setV3SiteKey] = useState<string>("");
  const [recaptchaToken, setRecaptchaToken] = useState<string>("");
  const [currentVersion, setCurrentVersion] = useState<"v3" | "v2">("v3");
  const [isFallback, setIsFallback] = useState<boolean>(false);

  const [isV2Verified, setIsV2Verified] = useState<boolean>(false);
  const v2WidgetIdRef = useRef<number | null>(null);

  const lastFetchTimeRef = useRef<number>(0);

  const executeV3Telemetry = useCallback(() => {
    if (!v3SiteKey || currentVersion !== "v3" || !window.grecaptcha?.enterprise)
      return;

    window.grecaptcha.enterprise.ready(async () => {
      try {
        const token = await window.grecaptcha.enterprise.execute(v3SiteKey, {
          action: "login",
        });
        console.log("V3 Smart Telemetry token acquired:", token);
        setRecaptchaToken(token);
        lastFetchTimeRef.current = Date.now();
      } catch (error) {
        console.error("V3 Smart Telemetry execution failed:", error);
      }
    });
  }, [v3SiteKey, currentVersion]); // Memory reference will only update if these two values change

  if (state && "success" in state && state.success) {
    console.log(state.success);
    // redirect(DEFAULT_LOGIN_REDIRECT);
  }

  useEffect(() => {
    async function fetchV3Key() {
      try {
        const response = await fetch("/api/recaptcha-key-v3"); // V3 key endpoint
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

  // SMART BACKGROUND TELEMETRY: Fires only on valid activity windows
  const handleUserActivity = () => {
    if (currentVersion !== "v3") return;
    const now = Date.now();
    if (now - lastFetchTimeRef.current > 90000) {
      // 1.5-minute cache validation
      executeV3Telemetry();
    }
  };

  useEffect(() => {
    if (state && "error" in state && state.error) {
      if (currentVersion === "v3") {
        if (state.error.includes("Score")) {
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
    // A. Handle Server-Instructed V2 Step-Up
    if (isFallback && currentVersion === "v3") {
      setCurrentVersion("v2");
      setRecaptchaToken(""); // Flush old low-score v3 token

      // Define the target callback explicitly for the script bundle lifecycle
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
                  action: "login",
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

      // If the library was loaded previously, invoke our setup pipeline immediately
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

      <Form
        action={formAction}
        onMouseMove={handleUserActivity}
        onFocusCapture={handleUserActivity}
        onInput={handleUserActivity}
        className="space-y-6 relative min-h-[460px]"
      >
        {state &&
          "error" in state &&
          state.error &&
          !state.error.includes("Score") && (
            <div className="w-full h-[40px] box-border bg-[rgba(255,5,5,0.15)] border-2 border-[#E30202] rounded-[93px] flex items-center justify-center px-4">
              <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#D80E0E]">
                {state.error}
              </span>
            </div>
          )}
        {state && "success" in state && state.success && (
          <div className="w-full h-[40px] box-border bg-[rgba(63,221,0,0.15)] border-2 border-[#368C04] rounded-[93px] flex items-center justify-center px-4">
            <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#368C04]">
              {state.success}
            </span>
          </div>
        )}
        <div className="flex flex-col gap-[50px]">
          <div className="flex flex-col gap-[25px]">
            <div className="w-full h-[42px]">
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                defaultValue={
                  state && "email" in state && state.email ? state.email : ""
                }
                disabled={isPending}
                required
                placeholder="Email*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] font-['Merriweather'] font-normal text-[16px] leading-[20px] text-[#000000] placeholder-[#000000] focus:outline-none"
              />
            </div>

            <div className="w-full h-[42px]">
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                disabled={isPending}
                defaultValue={
                  state && "password" in state && state.password
                    ? state.password
                    : ""
                }
                required
                placeholder="Password*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] font-['Merriweather'] font-normal text-[16px] leading-[20px] text-[#000000] placeholder-[#000000] focus:outline-none"
              />
              <p className="pl-[20px] pr-[20px] font-['Merriweather'] font-weight-[400] text-[10px] text-[#000000]">
                Password must be at least 8 characters.
              </p>
              <p className="pl-[20px] pr-[20px] font-['Merriweather'] font-weight-[400] text-[10px] text-[#000000]">
                Must include at least one uppercase letter, one lowercase
                letter, one number, one special character.
              </p>
            </div>
          </div>

          {currentVersion === "v2" && (
            <div className="flex justify-center my-4">
              <div id="recaptcha-container"></div>
            </div>
          )}

          <input type="hidden" name="recaptchaToken" value={recaptchaToken} />
          <input type="hidden" name="recaptchaVersion" value={currentVersion} />
          <div className="flex flex-col gap-[10px] mt-[10px]">
            <LoginButton
              disabled={
                isPending ||
                (currentVersion === "v3" && !recaptchaToken) ||
                (currentVersion === "v2" && !isV2Verified)
              }
            />
            <GoogleLoginButton />
            <FacebookLoginButton />
            <GitHubLoginButton />
          </div>
        </div>
      </Form>
    </>
  );
}
