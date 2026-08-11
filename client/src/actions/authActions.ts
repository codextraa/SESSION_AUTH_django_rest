"use server";

import {
  setSessionCookie,
  deleteSessionCookie,
  setPreAuthCookie,
  getPreAuthTokenFromSession,
  deletePreAuthCookie,
} from "@/libs/cookie";
import { login, twoFALogin, logout } from "@/libs/api";
import {
  PrevStateLoginForm,
  LoginErrorFields,
  TwoFAErrorFields,
  PrevStateTwoFALoginForm,
  LogoutAPIResponse,
} from "@/types/authTypes";
import {
  loginInputError,
  twoFAInputError,
  loginServerError,
  twoFAServerError,
} from "@/libs/errors";

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

  const credentials = {
    email_or_username: email_or_username,
    password: password,
    recaptcha_token: recaptcha_token,
    recaptcha_version: recaptcha_version,
  };

  const localErrors: LoginErrorFields = loginInputError(credentials);

  if (Object.keys(localErrors).length > 0) {
    return {
      success: "",
      pre_auth_token: false,
      error: localErrors,
      email_or_username: "",
      password: "",
    };
  }

  try {
    const response = await login(credentials);
    // const response = { "error": "reCAPTCHA validation failed" };
    if (response && "error" in response && response.error) {
      if (
        typeof response.error === "string" &&
        recaptcha_version === "v3" &&
        response.error.includes("reCAPTCHA validation failed")
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
        const LoginErrorResponse: LoginErrorFields = loginServerError(response);
        return {
          success: "",
          pre_auth_token: false,
          error: LoginErrorResponse,
          email_or_username: "",
          password: "",
        };
      }
    } else if (
      typeof response === "object" &&
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
      "session_expiry" in response &&
      response.session_expiry &&
      "user_id" in response &&
      response.user_id &&
      "user_role" in response &&
      response.user_role &&
      "csrf_token" in response &&
      response.csrf_token &&
      "csrf_token_expiry" in response &&
      response.csrf_token_expiry
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
export async function twoFALoginAction(
  prevState: PrevStateTwoFALoginForm,
  formData: FormData,
): Promise<PrevStateTwoFALoginForm> {
  const pre_auth_token = (await getPreAuthTokenFromSession()) || "";
  const otp = formData.get("otp")?.toString().trim() || "";

  const data = {
    pre_auth_token: pre_auth_token,
    otp: otp,
  };

  const localErrors: TwoFAErrorFields = twoFAInputError(data);

  if (Object.keys(localErrors).length > 0) {
    return {
      success: "",
      error: localErrors,
    };
  }

  try {
    const response = await twoFALogin(data);
    if (response && "error" in response && response.error) {
      const TwoFAErrorResponse: TwoFAErrorFields =
        await twoFAServerError(response);
      return {
        success: "",
        error: TwoFAErrorResponse,
      };
    } else if (
      typeof response === "object" &&
      "sessionid" in response &&
      response.sessionid &&
      "session_expiry" in response &&
      response.session_expiry &&
      "user_id" in response &&
      response.user_id &&
      "user_role" in response &&
      response.user_role &&
      "csrf_token" in response &&
      response.csrf_token &&
      "csrf_token_expiry" in response &&
      response.csrf_token_expiry
    ) {
      await setSessionCookie(response);
      await deletePreAuthCookie();
      return {
        success: "Login Successful.",
        error: {},
      };
    } else {
      return {
        success: "",
        error: {
          general: "An error occurred during login.",
        },
      };
    }
  } catch (error) {
    console.error(error);
    return {
      success: "",
      error: {
        general: "An error occurred during login.",
      },
    };
  }
}

export async function logoutAction(): Promise<LogoutAPIResponse> {
  try {
    const response = await logout();
    if (response && "error" in response && response.error) {
      return response;
    } else if (response && "success" in response && response.success) {
      await deleteSessionCookie();
      return response;
    } else {
      return {
        error: "Logout failed",
      };
    }
  } catch (error) {
    console.error(error);
    return {
      error: "An error occurred during logout.",
    };
  }
}
