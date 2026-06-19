"use server";

import { login } from "@/libs/api";
import { PrevStateLoginForm, LoginErrorFields } from "@/types/types";
import { setSessionCookie, setPreAuthCookie } from "@/libs/cookie";

const userError = async (response: object): Promise<LoginErrorFields> => {
  if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "object"
  ) {
    const backendErrors = response.error as Record<string, string[]>;

    const errorMessages: LoginErrorFields = {};

    if (backendErrors.email_or_username?.[0]) {
      const msg = backendErrors.email_or_username[0];
      errorMessages.email_or_username =
        msg.charAt(0).toUpperCase() + msg.slice(1).toLowerCase();
    }

    if (backendErrors.password?.[0]) {
      const msg = backendErrors.password[0];
      errorMessages.password =
        msg.charAt(0).toUpperCase() + msg.slice(1).toLowerCase();
    }

    if (backendErrors.recaptcha_token?.[0]) {
      const msg = backendErrors.recaptcha_token[0];
      errorMessages.recaptcha_token =
        msg.charAt(0).toUpperCase() + msg.slice(1).toLowerCase();
    }

    if (backendErrors.recaptcha_version?.[0]) {
      const msg = backendErrors.recaptcha_version[0];
      errorMessages.recaptcha_version =
        msg.charAt(0).toUpperCase() + msg.slice(1).toLowerCase();
    }

    return errorMessages;
  } else if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "string"
  ) {
    return {
      general: response.error,
    };
  }

  return {
    general: "An error occurred during login.",
  };
};

export async function loginAction(
  prevState: PrevStateLoginForm,
  formData: FormData,
): Promise<PrevStateLoginForm> {
  const email_or_username =
    formData.get("email_or_username")?.toString().trim() || "";
  const password = formData.get("password")?.toString().trim() || "";
  const recaptcha_token =
    formData.get("recaptchaToken")?.toString().trim() || "";
  const recaptcha_version =
    formData.get("recaptchaVersion")?.toString().trim() || "";

  const localErrors: LoginErrorFields = {};

  if (typeof email_or_username !== "string") {
    localErrors.email_or_username = "Invalid form data submission.";
  } else if (!email_or_username) {
    localErrors.email_or_username = "Email or username is required.";
  } else if (!email_or_username.includes("@")) {
    localErrors.email_or_username = "Invalid email format.";
  }

  if (typeof password !== "string") {
    localErrors.password = "Invalid form data submission.";
  } else if (!password) {
    localErrors.password = "Password is required.";
  }

  if (typeof recaptcha_token !== "string") {
    localErrors.recaptcha_token = "Invalid form data submission.";
  } else if (!recaptcha_token) {
    localErrors.recaptcha_token = "Recaptcha token is required.";
  }

  if (typeof recaptcha_version !== "string") {
    localErrors.recaptcha_version = "Invalid form data submission.";
  } else if (!recaptcha_version) {
    localErrors.recaptcha_version = "Recaptcha version is required.";
  }

  if (Object.keys(localErrors).length > 0) {
    return {
      success: "",
      pre_auth_token: false,
      error: localErrors,
      email_or_username: "",
      password: "",
    };
  }

  console.log("password: ", password);
  const credentials = {
    email_or_username: email_or_username,
    password: password,
    recaptcha_token: recaptcha_token,
    recaptcha_version: recaptcha_version,
  };

  try {
    const response = await login(credentials);
    // const response = {"error": "High risk transaction blocked. Score: 0.3"};
    if (response && "error" in response && response.error) {
      if (
        typeof response.error === "string" &&
        response.error.includes("Score") &&
        recaptcha_version === "v3"
      ) {
        return {
          success: "",
          pre_auth_token: false,
          error: {
            recaptcha_token: response.error,
          },
          email_or_username: email_or_username,
          password: password,
        };
      } else {
        const errorResponse = await userError(response);
        console.log("errorResponse: ", errorResponse);
        return {
          success: "",
          pre_auth_token: false,
          error: errorResponse,
          email_or_username: "",
          password: "",
        };
      }
    } else if (
      response &&
      "success" in response &&
      response.success &&
      "pre_auth_token" in response &&
      response.pre_auth_token
    ) {
      await setPreAuthCookie(response);
      return {
        success: "OTP Verification Sent.",
        pre_auth_token: true,
        error: {},
        email_or_username: "",
        password: "",
      };
    } else if (
      typeof response === "object" &&
      "sessionid" in response &&
      response.sessionid &&
      typeof response.session_expiry === "string" &&
      "session_expiry" in response &&
      response.session_expiry &&
      typeof response.session_expiry === "string" &&
      "user_id" in response &&
      response.user_id &&
      typeof response.user_id === "string" &&
      "user_role" in response &&
      response.user_role &&
      typeof response.user_role === "string" &&
      "csrf_token" in response &&
      response.csrf_token &&
      typeof response.csrf_token === "string" &&
      "csrf_token_expiry" in response &&
      response.csrf_token_expiry &&
      typeof response.csrf_token_expiry === "string"
    ) {
      await setSessionCookie(response);
      return {
        success: "Login Successful.",
        pre_auth_token: false,
        error: {},
        email_or_username: "",
        password: "",
      };
    } else {
      return {
        success: "",
        pre_auth_token: false,
        error: {
          general: "An error occurred during login.",
        },
        email_or_username: "",
        password: "",
      };
    }
  } catch (error) {
    console.error(error);
    return {
      success: "",
      pre_auth_token: false,
      error: {
        general: "An error occurred during login.",
      },
      email_or_username: "",
      password: "",
    };
  }
}
