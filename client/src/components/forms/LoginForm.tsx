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
import { loginAction } from "@/actions/authActions";
import { PrevStateLoginForm } from "@/types/types";
import { useRouter } from "next/navigation";
import {
  FormButton,
  EyeButton,
  GoogleLoginButton,
  FacebookLoginButton,
  GitHubLoginButton,
} from "@/components/buttons/button";
import { DEFAULT_LOGIN_REDIRECT } from "@/route";

const initialState: PrevStateLoginForm = {
  success: "",
  pre_auth_token: false,
  error: {},
  email_or_username: "",
  password: "",
};

export default function LoginForm() {
  const [state, formAction, isPending] = useActionState(
    loginAction,
    initialState,
  );

  const router = useRouter();
  const [v3SiteKey, setV3SiteKey] = useState<string>("");
  const [recaptchaToken, setRecaptchaToken] = useState<string>("");
  const [currentVersion, setCurrentVersion] = useState<"v3" | "v2">("v3");
  const [isFallback, setIsFallback] = useState<boolean>(false);

  const [isV2Verified, setIsV2Verified] = useState<boolean>(false);
  const v2WidgetIdRef = useRef<number | null>(null);

  const lastFetchTimeRef = useRef<number>(0);

  const [showPassword, setShowPassword] = useState<boolean>(false);

  const togglePasswordVisibility = () => {
    setShowPassword((prev) => !prev);
  };

  const executeV3Telemetry = useCallback(() => {
    if (!v3SiteKey || currentVersion !== "v3" || !window.grecaptcha?.enterprise)
      return;

    window.grecaptcha.enterprise.ready(async () => {
      try {
        const token = await window.grecaptcha.enterprise.execute(v3SiteKey, {
          action: "login",
        });
        setRecaptchaToken(token);
        lastFetchTimeRef.current = Date.now();
      } catch (error) {
        console.error("V3 Smart Telemetry execution failed:", error);
      }
    });
  }, [v3SiteKey, currentVersion]);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;

    if (
      state &&
      "success" in state &&
      state.success &&
      typeof state.success === "string" &&
      state.success.length > 0
    ) {
      if ("pre_auth_token" in state && state.pre_auth_token) {
        sessionStorage.setItem("otpExpiry", (Date.now() + 600000).toString());
        timer = setTimeout(() => {
          router.push("/auth/otp");
        }, 3000);
      } else {
        timer = setTimeout(() => {
          router.push(DEFAULT_LOGIN_REDIRECT);
        }, 3000);
      }
    }

    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [state, router]);

  useEffect(() => {
    async function fetchV3Key() {
      try {
        const response = await fetch("/api/recaptcha-key-v3"); // V3 key endpoint
        const data = await response.json();
        if (data.sitekey) setV3SiteKey(data.sitekey);
      } catch (error) {
        console.error("Failed to load reCAPTCHA v3 sitekey", error);
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
        if (
          state &&
          "error" in state &&
          typeof state.error === "object" &&
          "recaptcha_token" in state.error &&
          typeof state.error.recaptcha_token === "string" &&
          state.error.recaptcha_token.includes("reCAPTCHA validation failed")
        ) {
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
              const container = document.getElementById("recaptcha-container");
              // If the container node isn't mounted in the DOM yet due to state-batching delays,
              // defer the rendering process by one frame to let Next.js finish layout rendering.
              if (!container) {
                setTimeout(() => window.onloadCallback?.(), 50);
                return;
              }

              // Safely clear out inner DOM structures constructed by previous script execution chains
              container.innerHTML = "";

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
          typeof state.error === "object" &&
          "general" in state.error &&
          typeof state.error.general === "string" && (
            <div className="w-full h-[40px] box-border bg-[rgba(255,5,5,0.15)] border-2 border-[#E30202] rounded-[93px] flex items-center justify-center px-4">
              <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#D80E0E]">
                {state.error.general}
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
                id="email_or_username"
                name="email_or_username"
                type="email_or_username"
                autoComplete="email_or_username"
                defaultValue={
                  state &&
                  "email_or_username" in state &&
                  state.email_or_username
                    ? (state.email_or_username as string)
                    : ""
                }
                disabled={isPending}
                placeholder="Email or Username*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] font-['Merriweather'] font-normal text-[16px] leading-[20px] text-[#000000] placeholder-[#000000] focus:outline-none"
              />
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              "email_or_username" in state.error &&
              typeof state.error.email_or_username === "string" &&
              state.error.email_or_username !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.email_or_username}
                </p>
              )}

            <div className="w-full h-[42px] relative">
              <input
                id="password"
                name="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                disabled={isPending}
                defaultValue={
                  state && "password" in state && state.password
                    ? (state.password as string)
                    : ""
                }
                placeholder="Password*"
                className="w-full h-full box-border bg-transparent border-2 border-[#000000] rounded-[93px] pl-[20px] pr-[45px] font-['Merriweather'] font-normal text-[16px] leading-[20px] text-[#000000] placeholder-[#000000] focus:outline-none"
              />
              <EyeButton
                action={togglePasswordVisibility}
                showPassword={showPassword}
                isPending={isPending}
              />
            </div>

            <div className="flex flex-col gap-0.5">
              <p className="pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[10px] text-[#000000]">
                Password must be at least 8 characters.
              </p>
              <p className="pl-[20px] pr-[20px] font-['Merriweather'] font-normal text-[10px] text-[#000000]">
                Must include at least one uppercase letter, one lowercase
                letter, one number, one special character.
              </p>
            </div>
            {state &&
              "error" in state &&
              typeof state.error === "object" &&
              "password" in state.error &&
              typeof state.error.password === "string" &&
              state.error.password !== "" && (
                <p className="pl-[20px] font-['Merriweather'] text-[12px] text-[#D80E0E]">
                  {state.error.password}
                </p>
              )}
          </div>

          {currentVersion === "v2" && (
            <div className="flex justify-center my-4">
              <div id="recaptcha-container"></div>
            </div>
          )}

          <input type="hidden" name="recaptchaToken" value={recaptchaToken} />
          <input type="hidden" name="recaptchaVersion" value={currentVersion} />
          <div className="flex flex-col gap-[10px] mt-[10px]">
            <FormButton
              disabled={
                isPending ||
                (currentVersion === "v3" && !recaptchaToken) ||
                (currentVersion === "v2" && !isV2Verified)
              }
              mode="login"
            />
            <GoogleLoginButton />
            <FacebookLoginButton />
            <GitHubLoginButton />
          </div>
          <div className="w-full text-center font-['Merriweather'] text-[15px] text-[#000000]">
            Want to create an account?{" "}
            <Link
              href="/auth/signup"
              className="font-bold underline hover:opacity-80"
            >
              Sign Up
            </Link>
          </div>
        </div>
      </Form>
    </>
  );
}
