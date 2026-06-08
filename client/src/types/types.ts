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
  error: string | undefined;
}

export type LoginAPIResponse = LoginAPIResponseSuccess | ErrorResponse;

export interface reCaptchaVerifyResponseSuccess {
  success: string | undefined;
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
