"use server";

import { login, reCaptchaVerify } from "@/libs/api";
import { LoginAPIResponse, reCaptchaVerifyResponse } from "@/types/types";

export async function verifyReCaptchaAction(
  token: string,
): Promise<reCaptchaVerifyResponse> {
  const data = {
    recaptcha_token: token,
  };
  try {
    return await reCaptchaVerify(data);
  } catch (error) {
    console.error(error);
    return {
      error: "An error occurred during reCAPTCHA verification.",
    };
  }
}
export async function loginAction(
  prevState: LoginAPIResponse | undefined,
  formData: FormData,
): Promise<LoginAPIResponse> {
  if (formData.has("login")) {
    return { error: "Login action is not supported." };
  }
  const email = formData.get("email");
  const password = formData.get("password");

  if (typeof email !== "string" || typeof password !== "string") {
    return { error: "Invalid form data submission." };
  }

  const credentials = {
    email: email,
    password: password,
  };

  try {
    return await login(credentials);
  } catch (error) {
    console.error(error);
    return { error: "An error occurred during login." };
  }
}
