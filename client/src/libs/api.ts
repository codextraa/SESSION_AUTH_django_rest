import { ApiClient } from "./apiClient";
import {
  LoginInput,
  CSRFTokenResponse,
  SessionResponse,
  CreateUserData,
  CreateUserAPIResponse,
} from "@/types/types";

const HTTPS = process.env.HTTPS === "true";
const API_URL_OLD = HTTPS
  ? process.env.API_BASE_HTTPS_OLD_URL
  : process.env.API_BASE_URL;
const apiClientOld = new ApiClient(API_URL_OLD || "");

const API_URL = HTTPS
  ? process.env.API_BASE_HTTPS_URL
  : process.env.API_BASE_URL;
const apiClient = new ApiClient(API_URL || "");

export const getCSRFToken = async (): Promise<CSRFTokenResponse> => {
  return apiClient.get("/get-csrf-token/");
};

export const refreshSession = async (): Promise<SessionResponse> => {
  return apiClientOld.post("/session/refresh/", {});
};

// export const reCaptchaVerify = async (
//   data: reCaptchaTokenData,
// ): Promise<reCaptchaVerifyResponse> => {
//   return apiClientOld.post("/recaptcha-verify/", data);
// }; // not need now

// export const login = async (credentials: {
//   email: string;
//   password: string;
// }): Promise<LoginAPIResponse> => {
//   return apiClientOld.post("/login/", credentials);
// };

export const login = async (
  credentials: LoginInput,
): Promise<SessionResponse> => {
  return apiClient.post("/login/", credentials);
};

export const createUser = async (
  userData: CreateUserData,
): Promise<CreateUserAPIResponse> => {
  return apiClient.post("/users/", userData);
};
