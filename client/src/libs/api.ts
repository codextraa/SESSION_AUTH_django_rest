import { API_URL } from "@/routes";
import { ApiClient } from "./apiClient";
import {
  LoginInput,
  CSRFTokenResponse,
  SessionResponse,
  CreateUserData,
  CreateUserAPIResponse,
  TwoFALoginInput,
  SocialLoginInput,
  TwoFASessionAPIResponse,
  SocialLoginAPIResponse,
  LogoutAPIResponse,
} from "@/types/authTypes";

const apiClient = new ApiClient(API_URL || "");

export const getCSRFToken = async (): Promise<CSRFTokenResponse> => {
  return apiClient.get("/csrf-token/");
};

export const refreshSession = async (): Promise<SessionResponse> => {
  return apiClient.post("/refresh/", {});
};

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

export const twoFALogin = async (
  credentials: TwoFALoginInput,
): Promise<TwoFASessionAPIResponse> => {
  return apiClient.post("/two-fa-login/", credentials);
};

export const socialLogin = async (
  data: SocialLoginInput,
): Promise<SocialLoginAPIResponse> => {
  return apiClient.post("/social-login/", data);
};

export const logout = async (): Promise<LogoutAPIResponse> => {
  return await apiClient.post("/logout/", {});
};
