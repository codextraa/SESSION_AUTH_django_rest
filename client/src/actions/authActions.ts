"use server";

import { login, reCaptchaVerify } from "@/libs/api";
import { LoginAPIResponse, reCaptchaVerifyResponse } from "@/types/types";

// export async function loginAction(
//   prevState: LoginAPIResponse | undefined,
//   formData: FormData,
// ): Promise<LoginAPIResponse> {
//   if (formData.has("login")) {
//     return { error: "Login action is not supported." };
//   }
//   const email = formData.get("email");
//   const password = formData.get("password");

//   if (typeof email !== "string" || typeof password !== "string") {
//     return { error: "Invalid form data submission." };
//   }

//   const credentials = {
//     email: email,
//     password: password,
//   };

//   try {
//     return await login(credentials);
//   } catch (error) {
//     console.error(error);
//     return { error: "An error occurred during login." };
//   }
// }

export async function loginAction(
  prevState: LoginAPIResponse | undefined,
  formData: FormData,
): Promise<LoginAPIResponse> {
  //! keep in mind to send back email and password incase of low v3 score to allow fallback to v2
  const recaptcha_token = formData.get("recaptchaToken");
  const recaptcha_version = formData.get("recaptchaVersion");

  if (
    typeof recaptcha_token !== "string" ||
    typeof recaptcha_version !== "string"
  ) {
    return { error: "Invalid form data submission." };
  }

  const credentials = {
    recaptcha_token: recaptcha_token,
    recaptcha_version: recaptcha_version,
    expected_action: "login",
  };

  try {
    return await login(credentials);
    // return {"error": "High risk transaction blocked. Score: 0.3"}
  } catch (error) {
    console.error(error);
    return { error: "An error occurred during login." };
  }
}
