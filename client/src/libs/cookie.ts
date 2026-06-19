import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { RequestCookie, ResponseCookie } from "@edge-runtime/cookies";
import {
  encrypt,
  decrypt,
  validateSessionData,
  validateCSRFTokenData,
  validatePreAuthData,
} from "./session";
import { getCSRFToken, refreshSession } from "./api";
import {
  SessionData,
  CSRFTokenData,
  CSRFTokenResponse,
  CSRFTokenResponseSuccess,
  SessionResponse,
  SessionResponseSuccess,
  PreAuthResponseSuccess,
  PreAuthData,
} from "@/types/types";

export const setSessionCookie = async (
  data: SessionResponseSuccess,
): Promise<ResponseCookie> => {
  try {
    // Validate the incoming session data
    const validSessionData: SessionData | null = validateSessionData(data); // Sanitize and validate data
    const validCSRFToken: CSRFTokenData | null = validateCSRFTokenData(data);

    if (!validSessionData) {
      throw new Error("Invalid session data.");
    }

    if (!validCSRFToken) {
      throw new Error("Invalid CSRFToken");
    }

    // Encrypt the session data
    const encryptedCSRFToken = await encrypt(validCSRFToken);
    const encryptedSessionData = await encrypt(validSessionData);

    // Create a secure cookie
    // Set the secure cookie using Next.js cookies API
    const cookieConfig: Omit<ResponseCookie, "name" | "value"> = {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: "/", // Dynamic path
      sameSite: "lax", // Helps prevent CSRF attacks
    };

    const cookieStore = await cookies();
    cookieStore.set("__Secure-csrfToken", encryptedCSRFToken, cookieConfig);
    cookieStore.set("__Secure-session", encryptedSessionData, cookieConfig);

    return {
      name: "__Secure-session",
      value: encryptedSessionData,
      ...cookieConfig,
    };
  } catch (error) {
    console.error("Error setting cookie:", error);
    throw new Error("Failed to set session cookie.");
  }
};

export const setPreAuthCookie = async (
  data: PreAuthResponseSuccess,
): Promise<void> => {
  try {
    const validPreAuthData: PreAuthData | null = validatePreAuthData(data);

    if (!validPreAuthData) {
      throw new Error("Invalid pre-auth data.");
    }

    const encryptedPreAuthToken = await encrypt(validPreAuthData);

    // Create a secure cookie
    // Set the secure cookie using Next.js cookies API
    const cookieConfig: Omit<ResponseCookie, "name" | "value"> = {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 60 * 10, // 10 minutes
      path: "/", // Dynamic path
      sameSite: "lax", // Helps prevent CSRF attacks
    };

    const cookieStore = await cookies();
    cookieStore.set(
      "__Secure-preAuthToken",
      encryptedPreAuthToken,
      cookieConfig,
    );
  } catch (error) {
    console.error("Error setting cookie:", error);
    throw new Error("Failed to set session cookie.");
  }
};

export const setCSRFCookie = async (): Promise<void> => {
  try {
    const csrfTokenResponse: CSRFTokenResponse = await getCSRFToken();

    if (
      csrfTokenResponse &&
      "error" in csrfTokenResponse &&
      csrfTokenResponse.error
    ) {
      throw new Error("Failed to fetch CSRFToken");
    }

    const csrfTokenSuccess = csrfTokenResponse as CSRFTokenResponseSuccess;

    if (!csrfTokenSuccess.csrf_token || !csrfTokenSuccess.csrf_token_expiry) {
      throw new Error("CSRF token data is missing from the response");
    }

    const validCSRFToken: CSRFTokenData | null =
      validateCSRFTokenData(csrfTokenSuccess);

    if (!validCSRFToken) {
      throw new Error("Invalid CSRFToken");
    }

    const encryptedSessionData = await encrypt(validCSRFToken);

    const cookieStore = await cookies();
    cookieStore.set("__Secure-csrfToken", encryptedSessionData, {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: "/", // Dynamic path
      sameSite: "lax", // Helps prevent CSRF attacks
    });
  } catch (error) {
    console.error("Error setting csrfToken:", error);
    throw new Error("Failed to set CSRFToken");
  }
};

export const updateSessionCookie = async (
  req: NextRequest,
): Promise<ResponseCookie | false | undefined> => {
  const session = req.cookies.get("__Secure-session");

  if (!session) {
    return false;
  }

  const refreshSessionResponse: SessionResponse = await refreshSession();

  if (
    refreshSessionResponse &&
    "error" in refreshSessionResponse &&
    refreshSessionResponse.error
  ) {
    throw new Error("Failed to refresh Session Id");
  }

  const refreshSessionSuccess =
    refreshSessionResponse as SessionResponseSuccess;

  if (
    refreshSessionSuccess.user_id &&
    refreshSessionSuccess.user_role &&
    refreshSessionSuccess.sessionid &&
    refreshSessionSuccess.session_expiry &&
    refreshSessionSuccess.csrf_token &&
    refreshSessionSuccess.csrf_token_expiry
  ) {
    return await setSessionCookie(refreshSessionSuccess);
  } else {
    await deleteSessionCookie();
    await deleteCSRFCookie();
    return false;
  }
};

export const deleteSessionCookie = async (): Promise<void> => {
  const cookieStore = await cookies();

  if (cookieStore.has("__Secure-session")) {
    cookieStore.set("__Secure-session", "", {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 0, // Expire the cookie immediately
      path: "/", // Ensure the cookie is deleted for all paths
      sameSite: "lax",
    });
  }
};

export const deleteCSRFCookie = async (): Promise<void> => {
  const cookieStore = await cookies();

  if (cookieStore.has("__Secure-csrfToken")) {
    cookieStore.set("__Secure-csrfToken", "", {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 0, // Expire the cookie immediately
      path: "/", // Ensure the cookie is deleted for all paths
      sameSite: "lax",
    });
  }
};

export const deletePreAuthCookie = async (): Promise<void> => {
  const cookieStore = await cookies();

  if (cookieStore.has("__Secure-preAuthToken")) {
    cookieStore.set("__Secure-preAuthToken", "", {
      httpOnly: true,
      secure: process.env.HTTPS === "true", // Secure in production
      maxAge: 0, // Expire the cookie immediately
      path: "/", // Ensure the cookie is deleted for all paths
      sameSite: "lax",
    });
  }
};

export const getCSRFTokenCookie = async (): Promise<
  RequestCookie | undefined
> => {
  const cookieStore = await cookies();
  return cookieStore.get("__Secure-csrfToken");
};

export const getCSRFTokenFromSession = async (): Promise<string | null> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-csrfToken"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "csrf_token" in decryptedData &&
      decryptedData.csrf_token
    ) {
      // Check if user_id is present
      return decryptedData.csrf_token; // Return user_id if present
    }

    return null;
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getCSRFTokenExpiryFromSession = async (): Promise<
  boolean | null
> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-csrfToken"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "csrf_token_expiry" in decryptedData &&
      decryptedData.csrf_token_expiry
    ) {
      // Check if session_expiry is present
      const expiryDate = new Date(decryptedData.csrf_token_expiry);
      const currentDate = new Date();

      // Compare the expiry date with the current date
      if (currentDate > expiryDate) {
        console.warn("CSRF has expired");
        return false;
      } else {
        console.warn("CSRF is still valid");
        return true;
      }
    }

    return false; // Return false if csrf_token_expiry is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getPreAuthCookie = async (): Promise<
  RequestCookie | undefined
> => {
  const cookieStore = await cookies();
  return cookieStore.get("__Secure-preAuthToken");
};

export const getPreAuthTokenFromSession = async (): Promise<string | null> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-preAuthToken"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "pre_auth_token" in decryptedData &&
      decryptedData.pre_auth_token
    ) {
      // Check if pre_auth_token is present
      return decryptedData.pre_auth_token; // Return pre_auth_token if present
    }

    return null; // Return null if pre_auth_token is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getSessionCookie = async (): Promise<
  RequestCookie | undefined
> => {
  const cookieStore = await cookies();
  return cookieStore.get("__Secure-session");
};

export const getUserIdFromSession = async (): Promise<string | null> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-session"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (decryptedData && "user_id" in decryptedData && decryptedData.user_id) {
      // Check if user_id is present
      return decryptedData.user_id; // Return user_id if present
    }

    return null; // Return null if user_id is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getUserRoleFromSession = async (): Promise<string | null> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-session"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "user_role" in decryptedData &&
      decryptedData.user_role
    ) {
      // Check if user_id is present
      return decryptedData.user_role; // Return user_id if present
    }

    return null; // Return null if user_id is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getSessionIdFromSession = async (): Promise<string | null> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-session"); // Retrieve the session cookie
  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "sessionid" in decryptedData &&
      decryptedData.sessionid
    ) {
      // Check if sessionid is present
      return decryptedData.sessionid; // Return sessionid if present
    }

    return null; // Return null if sessionid is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};

export const getSessionExpiryFromSession = async (): Promise<
  boolean | null
> => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("__Secure-session"); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  }

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  }

  try {
    const decryptedData: SessionData | CSRFTokenData | PreAuthData =
      await decrypt(sessionCookie.value); // Decrypt the session data

    if (
      decryptedData &&
      "session_expiry" in decryptedData &&
      decryptedData.session_expiry
    ) {
      // Check if session_expiry is present
      const expiryDate = new Date(decryptedData.session_expiry);
      const currentDate = new Date();

      // Compare the expiry date with the current date
      if (currentDate > expiryDate) {
        console.warn("Session has expired");
        return false;
      } else {
        console.warn("Session is still valid");
        return true;
      }
    }

    return false; // Return false if session_expiry is not present
  } catch (error) {
    console.error("Error decrypting session data:", error);
    return null; // Return null if decryption fails
  }
};
