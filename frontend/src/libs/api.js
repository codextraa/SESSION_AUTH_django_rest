import { ApiClient } from "./apiClient";
import { 
  getRefreshTokenFromSession,
} from "./cookie";


const HTTPS = process.env.HTTPS === 'true';
const API_URL = HTTPS? process.env.API_BASE_HTTPS_URL : process.env.API_BASE_URL;
const apiClient = new ApiClient(API_URL);

// API functions
export const getCSRFToken = async () => {
  return apiClient.get('/get-csrf-token/');
};

export const recaptchaVerify = async (data) => {
  return apiClient.post('/recaptcha-verify/', data);
};

export const login = async (data) => {
  return apiClient.post('/login/', data);
};

export const getToken = async (data) => {
  return apiClient.post('/token/', data);
};

export const resendOtp = async (data) => {
  return apiClient.post('/resend-otp/', data);
};

export const refreshToken = async (refreshToken) => {
  return await apiClient.post('/token/refresh/', { refresh: refreshToken });
};

export const verifyEmail = async (token, expiry) => {
  const queryParams = new URLSearchParams({ token, expiry }).toString();
  return apiClient.get(`/verify-email/?${queryParams}`);
};

export const requestEmailVerification = async (data) => {
  return apiClient.post('/verify-email/', data); 
};

export const requestPhoneVerification = async (data) => {
  return apiClient.post('/verify-phone/', data);
};

export const verifyPhone = async (data) => {
  return apiClient.patch('/verify-phone/', data);
};

export const verifyPassResetLink = async (token, expiry) => {
  const queryParams = new URLSearchParams({ token, expiry }).toString();
  return apiClient.get(`/reset-password/?${queryParams}`);
};

export const requestPasswordReset = async (data) => {
  return apiClient.post('/reset-password/', data);
};

export const resetPassword = async (token, expiry, data) => {
  const queryParams = new URLSearchParams({ token, expiry }).toString();
  return apiClient.patch(`/reset-password/?${queryParams}`, data);
};

export const logout = async () => {
  const refreshToken = await getRefreshTokenFromSession();

  if (refreshToken) {
    await apiClient.post('/logout/', { refresh: refreshToken });
  };
};

export const socialOauth = async (data) => {
  return apiClient.post('/social-auth/', data);
};

export const getUsers = async (queryParams = {}) => {
  const params = new URLSearchParams(queryParams)
  return apiClient.get(`/users/?${params.toString()}`)
};

export const getUser = async (id) => {
  return apiClient.get(`/users/${id}/`);
};

export const createUser = async (data) => {
  return apiClient.post('/users/', data);
};

export const updateUser = async (id, data) => {
  return apiClient.patch(`/users/${id}/`, data);
};

export const deleteUser = async (id) => {
  return apiClient.delete(`/users/${id}/`);
};

export const activateUser = async (id) => {
  return apiClient.patch(`/users/${id}/activate-user/`);
};

export const deactivateUser = async (id) => {
  return apiClient.patch(`/users/${id}/deactivate-user/`);
};

export const uploadProfileImage = async (id, data) => {
  return apiClient.patch(`/users/${id}/upload-image/`, data, {}, true);
};