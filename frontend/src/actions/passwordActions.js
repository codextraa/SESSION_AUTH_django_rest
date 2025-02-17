"use server";

import { 
  requestPasswordReset, 
  verifyPassResetLink, 
  resetPassword
} from "@/libs/api";


// Can be improved
export const passwordError = async (response) => {
  if (typeof response.error === "object") {
    // Initialize an array to store error messages
    const errorMessages = [];

    // Check for each possible attribute and append its messages
    if (response.error.short) {
      errorMessages.push(...[response.error.short]);
    }
    if (response.error.upper) {
      errorMessages.push(...[response.error.upper]);
    }
    if (response.error.lower) {
      errorMessages.push(...[response.error.lower]);
    }
    if (response.error.number) {
      errorMessages.push(...[response.error.number]);
    }
    if (response.error.special) {
      errorMessages.push(...[response.error.special]);
    }

    if (errorMessages.length === 0) {
      return response.error;
    }

    // Combine messages into a single string with \n between each
    return errorMessages.join(" ");
  }

  // If it's not a dictionary, return the error as is (string or other type)
  return response.error;
};

export async function requestPasswordResetAction(formData) {
  const data = {
    email: formData.get("email"),
  };

  try {
    const response = await requestPasswordReset(data);

    if (response.error) {
      return { error: response.error };
    };

    return { success: "Password reset link sent to your email." };
  } catch (error) {
    console.error(error);
    return { error: error.message || "Failed to send password reset link." }
  };
};

export async function verifyResetLinkAction(token, expiry) {
  try {
    const response = await verifyPassResetLink(token, expiry);

    if (response.error) {
      return { error: response.error };
    };
    
    return { success: true };
  } catch (error) {
    console.error(error);
    return { error: error.message || "Invalid or expired reset link." };
  };
};

export async function resetPasswordAction(formData) {
  const token = formData.get("token");
  const expiry = formData.get("expiry");
  const data = {
    password: formData.get("password"),
    c_password: formData.get("c_password"),
  };

  try {
    const response = await resetPassword(token, expiry, data);

    if (response.error) {
      const error = await passwordError(response);
      return { error: error };
    };

    return { success: "Password reset successfully." };
  } catch (error) {
    console.error(error);
    return { error: error.message || "Failed to reset password." };
  };
};