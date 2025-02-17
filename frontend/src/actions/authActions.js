'use server';

import {
  recaptchaVerify,
  login, 
  getToken, 
  resendOtp, 
  socialOauth, 
  logout
} from '@/libs/api';
import { 
  getUserIdFromSession,
  getUserRoleFromSession,
  deleteCSRFCookie,
  deleteSessionCookie,
  setSessionCookie,
} from '@/libs/cookie';
import { BASE_ROUTE } from '@/route';
import { redirect } from 'next/navigation';


export const getUserIdAction = async() => {
  try {
    return await getUserIdFromSession();
  } catch (error) {
    console.error(error);
    return null;
  };
};

export const getUserRoleAction = async() => {
  try {
    return await getUserRoleFromSession();
  } catch (error) {
    console.error(error);
    return null;
  };
};

export async function recaptchaVerifyAction(token) {
  const data = {
    recaptcha_token: token
  };

  try {
    return await recaptchaVerify(data);
  } catch (error) {
    // Handle any network or unexpected error
    console.error(error);
    return { error: error.message || 'An error occurred during reCAPTCHA verification.' };
  };
};

export async function loginAction(formData) {
  const email = formData.get('email');
  const password = formData.get('password');

  const credentials = {
    email: email,
    password: password
  };

  try {
    // Make the login request to the backend API
    return await login(credentials);
  } catch (error) {
    // Handle any network or unexpected error
    console.error(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};

export async function verifyOtpAction(formData) {
  const otp_data = formData.get('otp');
  const user_id = formData.get('user_id');

  const otp = {
    user_id: user_id,
    otp: otp_data
  };

  try {
    // Call the backend API to verify OTP
    const response = await getToken(otp);

    if (response.access_token && response.refresh_token 
        && response.user_role && response.user_id 
        && response.access_token_expiry) {
        await setSessionCookie(response);
        // Return success response if OTP verification is successful
        return { success: 'OTP verified successfully' };
    } else {
      // Return error if OTP verification fails
      return response;
    }
  } catch (error) {
    // Handle any network or unexpected error
    console.error(error);
    return { error: error.message || 'An error occurred during OTP verification.' };
  };
};

export async function resendOtpAction(user_id) {
  const user = {
    user_id: user_id
  };

  try {
    // Make the login request to the backend API
    return await resendOtp(user);
  } catch (error) {
    // Handle any network or unexpected error
    console.error(error);
    return { error: error.message || 'An error occurred during login.' };
  };
};

export async function socialLoginAction(provider, accessToken) {
  try {
    const auth_data = {
      provider: provider,
      token: accessToken
    };
    const response = await socialOauth(auth_data)
    if (response.access_token && response.refresh_token 
      && response.user_role && response.user_id 
      && response.access_token_expiry) {
      await setSessionCookie(response);
      // Return success response if OTP verification is successful
      return { success: 'Login successful' };
    } else {
      return { error: response.error || "Backend authentication failed" }
    };
  } catch (error) {
    console.error(error)
    return { error: error.message || "An error occurred during login." }
  };
};

export const logoutAction = async() => {
  try {
    // Logout from the backend
    await logout();
    // Delete the CSRF cookie
    await deleteCSRFCookie();
    // Delete the session cookie
    await deleteSessionCookie();
    redirect(`${BASE_ROUTE}/login`);
  } catch (error) {
    // Throw the NEXT REDIRECT error (otherwise it won't work)
    throw error;
  };
};
