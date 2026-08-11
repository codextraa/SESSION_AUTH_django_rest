export const DEFAULT_LOGIN_REDIRECT = "/";

export const authRoute = "/auth";

export const apiRoute = "/api";

export const publicRoutes = ["/"];

const HTTPS = process.env.HTTPS === "true";

export const API_URL = HTTPS
  ? process.env.API_BASE_HTTPS_URL
  : process.env.API_BASE_URL;
