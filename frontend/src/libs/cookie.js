import { cookies } from 'next/headers';
import { encrypt, decrypt, validateSessionData } from './session';
import { refreshToken, getCSRFToken } from './api';
import { BASE_ROUTE } from '@/route';

export const setSessionCookie = async (data) => {
  try {
    // Validate the incoming session data
    const sessionData = validateSessionData(data); // Sanitize and validate data

    if (!sessionData) {
      throw new Error('Invalid session data.');
    };

    // Encrypt the session data
    const encryptedSessionData = await encrypt(sessionData);

    // Create a secure cookie
    // Set the secure cookie using Next.js cookies API
    const cookieStore = await cookies();
    cookieStore.set('__Secure-session', encryptedSessionData, {
      httpOnly: true,
      secure: process.env.HTTPS === 'true', // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: BASE_ROUTE, // Dynamic path
      sameSite: 'lax', // Helps prevent CSRF attacks
    });

    return cookieStore.get('__Secure-session');
  } catch (error) {
    console.error('Error setting cookie:', error);
    throw new Error('Failed to set session cookie.');
  };
};

export const setCSRFCookie = async () => {
  const csrf_token_data = await getCSRFToken();

  const encryptedSessionData = await encrypt(csrf_token_data);

  const cookieStore = await cookies();
  cookieStore.set('__Secure-csrftoken', encryptedSessionData, {
    httpOnly: true,
    secure: process.env.HTTPS === 'true', // Secure in production
    maxAge: 60 * 60 * 24, // One day in seconds
    path: BASE_ROUTE, // Dynamic path
    sameSite: 'lax', // Helps prevent CSRF attacks
  });
};


export const updateSessionCookie = async (req) => {
  const session = req.cookies.get('__Secure-session');

  if (!session) {
    return false;
  }

  const refresh_token = await getRefreshTokenFromSession();

  if (!refresh_token) {
    return false;
  };

  const res = await refreshToken(refresh_token);

  if (res.access_token && res.refresh_token && res.user_id && res.user_role && res.access_token_expiry) {
    return await setSessionCookie(res);
  } else {
    await deleteSessionCookie();
    // await deleteCSRFCookie();
    return false;
  };
};

export const deleteSessionCookie = async () => {
  const cookieStore = await cookies();

  if (cookieStore.has('__Secure-session')) {
    cookieStore.set('__Secure-session', '', {
      httpOnly: true,
      secure: process.env.HTTPS === 'true', // Secure in production
      maxAge: 0, // Expire the cookie immediately
      path: BASE_ROUTE, // Ensure the cookie is deleted for all paths
      sameSite: 'lax',
    });
  };
};

export const deleteCSRFCookie = async () => {
  const cookieStore = await cookies();

  if (cookieStore.has('__Secure-csrftoken')) {
    cookieStore.set('__Secure-csrftoken', '', {
      httpOnly: true,
      secure: process.env.HTTPS === 'true', // Secure in production
      maxAge: 0, // Expire the cookie immediately
      path: BASE_ROUTE, // Ensure the cookie is deleted for all paths
      sameSite: 'lax',
    })
  };
};

export const getCSRFTokenFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-csrftoken'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.csrf_token || null; // Return user_id if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getCSRFTokenExpiryFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-csrftoken'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.csrf_token_expiry || null; // Return user_id if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getUserIdFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.user_id || null; // Return user_id if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getUserRoleFromSession = async () => {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.user_role || null; // Return user_role if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getAccessTokenFromSession = async () =>  {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-session'); // Retrieve the session cookie
  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.access_token || null; // Return access_token if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getRefreshTokenFromSession = async () =>  {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data
    return decryptedData?.refresh_token || null; // Return refresh_token if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};

export const getAccessTokenExpiryFromSession = async () =>  {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get('__Secure-session'); // Retrieve the session cookie

  if (!sessionCookie) {
    return null; // No session cookie found
  };

  if (!sessionCookie.value) {
    return null; // No session cookie value found
  };

  try {
    const decryptedData = await decrypt(sessionCookie.value); // Decrypt the session data

    if (decryptedData && decryptedData.access_token_expiry) { // Check if access_token_expiry is present
      const expiryDate = new Date(decryptedData.access_token_expiry);
      const currentDate = new Date();

      // Compare the expiry date with the current date
      if (currentDate > expiryDate) {
        console.warn("Token has expired");
        return false;
      } else {
        console.warn("Token is still valid");
        return true;
      };
    };

    return false; // Return access_token_expiry if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};