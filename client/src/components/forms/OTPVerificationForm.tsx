"use client";

import Form from "next/form";
import { useActionState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { twoFALoginAction } from "@/actions/authActions";
import { PrevStateTwoFALoginForm } from "@/types/types";
import {
  OTPFormSubmitButton,
  OTPBackToLoginButton,
  OTPResendButton,
} from "@/components/buttons/button";
import { DEFAULT_LOGIN_REDIRECT } from "@/route";

const initialState: PrevStateTwoFALoginForm = {
  success: "",
  error: {},
};

export default function OTPVerificationForm() {
  const [state, formAction, isPending] = useActionState(
    twoFALoginAction,
    initialState,
  );
  const router = useRouter();

  const handleResendOTP = () => {
    console.log("Resending OTP code...");
  };

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;

    if (
      state &&
      "success" in state &&
      state.success &&
      typeof state.success === "string" &&
      state.success.length > 0
    ) {
      sessionStorage.removeItem("otpExpiry");
      timer = setTimeout(() => {
        router.push(DEFAULT_LOGIN_REDIRECT);
      }, 3000);
    }

    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [state, router]);

  return (
    <Form
      action={formAction}
      className="flex flex-col items-center w-full max-w-[326px]"
    >
      <div className="flex flex-col items-center w-full mb-6">
        <label
          htmlFor="otp"
          className="font-['Merriweather'] font-bold text-xl text-black text-center mb-[10px]"
        >
          Enter the OTP sent in your email:
        </label>
        <input
          id="otp"
          name="otp"
          type="text"
          disabled={isPending}
          className="w-full h-[42px] border-2 border-black rounded-[37px] bg-transparent text-center font-['Merriweather'] font-bold text-lg px-4 focus:outline-none focus:ring-2 focus:ring-[#263775]"
        />
        {state &&
          "error" in state &&
          state.error &&
          typeof state.error === "object" &&
          "otp" in state.error &&
          typeof state.error.otp === "string" && (
            <p className="mt-1 font-['Merriweather'] font-bold text-xs text-[#B70000]">
              {state.error.otp}
            </p>
          )}
      </div>

      <div className="h-[23px] mb-[25px] flex items-center justify-center text-center">
        {state &&
          "success" in state &&
          state.success &&
          typeof state.success === "string" && (
            <p className="font-['Merriweather'] font-bold text-lg text-[#368C04]">
              {state.success}
            </p>
          )}
        {state &&
          "error" in state &&
          state.error &&
          typeof state.error === "object" &&
          "general" in state.error &&
          typeof state.error.general === "string" && (
            <p className="font-['Merriweather'] font-bold text-lg text-[#B70000]">
              {state.error.general}
            </p>
          )}
        {state &&
          "error" in state &&
          state.error &&
          typeof state.error === "object" &&
          "pre_auth_token" in state.error &&
          typeof state.error.pre_auth_token === "string" && (
            <p className="font-['Merriweather'] font-bold text-lg text-[#B70000]">
              {state.error.pre_auth_token}
            </p>
          )}
      </div>

      <div className="flex flex-col items-center gap-[25px]">
        <OTPFormSubmitButton />
        <OTPResendButton onResend={handleResendOTP} />
        <OTPBackToLoginButton />
      </div>
    </Form>
  );
}
