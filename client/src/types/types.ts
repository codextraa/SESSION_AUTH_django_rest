export interface SuccessResponse {
  success: string | undefined;
}

export interface ErrorResponse {
  error: string | object | undefined;
}

export interface CSRFTokenData {
  csrf_token: string;
  csrf_token_expiry: string;
}

export interface SessionData {
  user_id: string;
  user_role: string;
  sessionid: string;
  session_expiry: string;
}

export interface PreAuthData {
  pre_auth_token: string;
}

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

export interface PreAuthResponseSuccess {
  success: string | undefined;
  pre_auth_token: string | undefined;
}

export type SessionResponse =
  | SessionResponseSuccess
  | PreAuthResponseSuccess
  | ErrorResponse;

export interface LoginInput {
  email_or_username: string | undefined;
  password: string | undefined;
  recaptcha_token: string | undefined;
  recaptcha_version: string | undefined;
}

export interface LoginErrorFields {
  email_or_username?: string;
  password?: string;
  recaptcha_version?: string;
  recaptcha_token?: string;
  general?: string;
}

export interface PrevStateLoginForm {
  success: string;
  pre_auth_token: boolean;
  error: object;
  email_or_username: string;
  password: string;
}

export interface TwoFAErrorFields {
  pre_auth_token?: string;
  otp?: string;
  general?: string;
}

export interface PrevStateTwoFALoginForm {
  success: string;
  error: object;
}

export interface TwoFALoginInput {
  pre_auth_token: string | unknown | undefined;
  otp: number | string | undefined;
}

export type TwoFASessionResponse = SessionResponseSuccess | ErrorResponse;

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

export interface SignUpPasswordErrorResponse {
  short?: string;
  lower?: string;
  upper?: string;
  number?: string;
  special?: string;
}

export interface SignUpErrorResponse {
  email?: string[] | string;
  username?: string[] | string;
  first_name?: string[] | string;
  last_name?: string[] | string;
  phone_number?: string[] | string;
  password?: SignUpPasswordErrorResponse | string;
  c_password?: string[] | string;
  global?: string[] | string;
  errors?: string[] | string;
}

export interface CreateUserErrorResponse {
  error: string | SignUpErrorResponse | undefined;
}

export type CreateUserAPIResponse = SuccessResponse | CreateUserErrorResponse;

export interface CreateUserData {
  email: string | undefined;
  username: string | undefined;
  password: string | undefined;
  c_password: string | undefined;
  first_name?: string | undefined;
  last_name?: string | undefined;
  phone_number?: string | undefined;
  is_staff?: boolean | undefined;
}

export type SignUpFormState =
  | SuccessResponse
  | CreateUserErrorResponse
  | CreateUserData;
