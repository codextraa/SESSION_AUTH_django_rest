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
  const email = formData.get("email");
  const password = formData.get("password");
  const recaptcha_token = formData.get("recaptchaToken");
  const recaptcha_version = formData.get("recaptchaVersion");

  if (typeof email !== "string") {
    return { error: "Invalid form data submission." };
  } else if (!email) {
    return { error: "Email is required." };
  } else if (!email.includes("@")) {
    return { error: "Invalid email format." };
  }

  if (typeof password !== "string") {
    return { error: "Invalid form data submission." };
  } else if (!password) {
    return { error: "Password is required." };
  }

  if (
    typeof recaptcha_token !== "string" ||
    typeof recaptcha_version !== "string"
  ) {
    return { error: "Invalid form data submission." };
  }

  const credentials = {
    email: email,
    password: password,
    recaptcha_token: recaptcha_token,
    recaptcha_version: recaptcha_version,
    expected_action: "login",
  };

  try {
    const response = await login(credentials);
    // return {"error": "High risk transaction blocked. Score: 0.3", "email": email, "password": password};
    if (response && "error" in response && response.error) {
      if (response.error.includes("Score") && recaptcha_version === "v3") {
        return {
          error: response.error,
          email: email,
          password: password,
        };
      }
    }
    return response;
  } catch (error) {
    console.error(error);
    return { error: "An error occurred during login." };
  }
}
