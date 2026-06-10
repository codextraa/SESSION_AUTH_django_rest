"use client";

import Form from "next/form";
import Script from "next/script";
import { useActionState, useState, useRef, useEffect } from "react";
import { loginAction } from "@/actions/authActions";
import { LoginAPIResponse } from "@/types/types";
import { redirect } from "next/navigation";
import { LoginButton } from "@/components/buttons/button";
import { DEFAULT_LOGIN_REDIRECT } from "@/route";

const initialState: LoginAPIResponse = {
  success: undefined,
  otp: undefined,
  user_id: undefined,
  error: undefined,
};

export default function LoginForm() {
  const [state, formAction, isPending] = useActionState(
    loginAction,
    initialState,
  );

  const [isRecaptchaVerified, setIsRecaptchaVerified] =
    useState<boolean>(false);
  const [recaptchaToken, setRecaptchaToken] = useState<string>("");
  const widgetIdRef = useRef<number | null>(null);

  if (state && "success" in state && state.success) {
    redirect(DEFAULT_LOGIN_REDIRECT);
  }

  useEffect(() => {
    if (state?.error && widgetIdRef.current !== null && window.grecaptcha) {
      window.grecaptcha.enterprise.reset(widgetIdRef.current);
      setIsRecaptchaVerified(false);
      setRecaptchaToken("");
    }
  }, [state]);

  useEffect(() => {
    window.onloadCallback = async () => {
      if (window.grecaptcha?.enterprise) {
        const response = await fetch("/api/recaptcha-key");
        const data = await response.json();
        if (data.sitekey) {
          const widgetId = window.grecaptcha.enterprise.render(
            "recaptcha-container",
            {
              sitekey: data.sitekey, // Ensure this is in your env
              theme: "light",
              action: "login",
              callback: (token: string) => {
                // This is your event binding via callback
                setIsRecaptchaVerified(true);
                setRecaptchaToken(token);
              },
              "expired-callback": () => {
                setIsRecaptchaVerified(false);
                setRecaptchaToken("");
              },
              "error-callback": () => {
                setIsRecaptchaVerified(false);
                setRecaptchaToken("");
              },
            },
          );
          widgetIdRef.current = widgetId;
        }
      }
    };

    // Cleanup global function on unmount
    return () => {
      window.onloadCallback = () => {};
    };
  }, []);

  return (
    <>
      <Script
        src={`https://www.google.com/recaptcha/enterprise.js?onload=onloadCallback&render=explicit`}
        strategy="afterInteractive"
      />
      <Form action={formAction} className="space-y-6 relative min-h-[460px]">
        {state && "error" in state && state.error && (
          <div className="w-full h-[40px] box-border bg-[rgba(255,5,5,0.15)] border-2 border-[#E30202] rounded-[93px] flex items-center justify-center px-4">
            <span className="font-['Merriweather'] font-normal text-[16px] leading-[20px] text-center text-[#D80E0E]">
              {state.error}
            </span>
          </div>
        )}
        <div>
          <label
            htmlFor="email"
            className="block text-sm font-medium text-gray-700"
          >
            Email
          </label>
          <div className="mt-1">
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="email"
              disabled={isPending}
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            />
          </div>
        </div>

        <div>
          <label
            htmlFor="password"
            className="block text-sm font-medium text-gray-700"
          >
            Password
          </label>
          <div className="mt-1">
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              disabled={isPending}
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            />
          </div>
        </div>

        <div className="flex justify-center my-4">
          <div id="recaptcha-container"></div>
        </div>

        <input type="hidden" name="recaptchaToken" value={recaptchaToken} />

        <LoginButton disabled={!isRecaptchaVerified} />
      </Form>
    </>
  );
}
