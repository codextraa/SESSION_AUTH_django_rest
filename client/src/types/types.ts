export interface SessionData {
  user_id: string;
  user_role: string;
  sessionid: string;
  session_expiry: string;
}

export interface CSRFTokenData {
  csrf_token: string;
  csrf_token_expiry: string;
}

export interface ErrorResponse {
  error: string | undefined;
}

export interface LoginAPIResponseSuccess {
  success: string | undefined;
  otp: boolean | undefined;
  user_id: number | undefined;
}

export type LoginAPIResponse = LoginAPIResponseSuccess | ErrorResponse;

export interface reCaptchaVerifyResponseSuccess {
  success: string | undefined;
}

export interface reCaptchaTokenData {
  recaptcha_token: string | undefined;
  recaptcha_version: string | undefined;
  expected_action?: string | undefined;
}

export type reCaptchaVerifyResponse =
  | reCaptchaVerifyResponseSuccess
  | ErrorResponse;

export interface CSRFTokenResponseSuccess {
  csrf_token: string | undefined;
  csrf_token_expiry: string | undefined;
}

export type CSRFTokenResponse = CSRFTokenResponseSuccess | ErrorResponse;

export interface SessionResponseSuccess {
  sessionid: string | undefined;
  session_expiry: string | undefined;
  user_id: number | undefined;
  user_role: string | undefined;
  csrf_token: string | undefined;
  csrf_token_expiry: string | undefined;
}

export type SessionResponse = SessionResponseSuccess | ErrorResponse;

/* eslint-disable no-unused-vars */
declare global {
  interface Window {
    onloadCallback?: () => void;
    grecaptcha: {
      enterprise: {
        // v3: Prepares the library to execute programmatic actions
        ready: (callback: () => void | Promise<void>) => void;

        // v3: Programmatically generates an invisible token
        execute: (
          siteKey: string,
          options: { action: string },
        ) => Promise<string>;

        // v2: Explicitly renders a visual challenge widget into a DOM container
        render: (
          containerIdOrElement: string | HTMLElement,
          parameters: {
            sitekey: string;
            theme?: "light" | "dark";
            size?: "normal" | "compact" | "invisible";
            action?: string;
            callback?: (token: string) => void;
            "expired-callback"?: () => void;
            "error-callback"?: () => void;
          },
        ) => number; // Returns a unique numeric Widget ID

        // v2: Resets a specific widget via its unique numeric ID
        reset: (widgetId?: number) => void;
      };
    };
  }
}
/* eslint-enable no-unused-vars */
