import { ApiClient } from "./apiClient";
import {
  LoginAPIResponse,
  reCaptchaVerifyResponse,
  CSRFTokenResponse,
  SessionResponse,
} from "@/types/types";

const HTTPS = process.env.HTTPS === "true";
const API_URL = HTTPS
  ? process.env.API_BASE_HTTPS_OLD_URL
  : process.env.API_BASE_URL;
const apiClient = new ApiClient(API_URL || "");

export const getCSRFToken = async (): Promise<CSRFTokenResponse> => {
  return apiClient.get("/get-csrf-token/");
};

export const refreshSession = async (): Promise<SessionResponse> => {
  return apiClient.post("/session/refresh/", {});
};

export const reCaptchaVerify = async (data: {
  recaptcha_token: string;
}): Promise<reCaptchaVerifyResponse> => {
  return apiClient.post("/recaptcha-verify/", data);
};

export const login = async (credentials: {
  email: string;
  password: string;
}): Promise<LoginAPIResponse> => {
  return apiClient.post("/login/", credentials);
};
