"use client";

import Form from "next/form";
import { useActionState } from "react";
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

  if (state && "success" in state && state.success) {
    console.log("state: ", state);
    redirect(DEFAULT_LOGIN_REDIRECT);
  }

  return (
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
      <LoginButton />
    </Form>
  );
}
