import { cookies } from 'next/headers';
import { encrypt, decrypt, validateSessionData, validateCSRFTokenData } from './session';
import { getCSRFToken } from './api';
import { BASE_ROUTE } from '@/route';

export const setSessionCookie = async (data) => {
  try {
    // Validate the incoming session data
    const validsessionData = validateSessionData(data); // Sanitize and validate data
    const validcsrftoken = validateCSRFTokenData(data);

    if (!validsessionData) {
      throw new Error('Invalid session data.');
    };

    if (!validcsrftoken) {
      throw new Error('Invalid CSRFToken');
    };

    // Encrypt the session data
    const encryptedCSRFToken = await encrypt(validcsrftoken)
    const encryptedSessionData = await encrypt(validsessionData);

    // Create a secure cookie
    // Set the secure cookie using Next.js cookies API
    const cookieStore = await cookies();
    cookieStore.set('__Secure-csrftoken', encryptedCSRFToken, {
      httpOnly: true,
      secure: process.env.HTTPS === 'true', // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: BASE_ROUTE, // Dynamic path
      sameSite: 'lax', // Helps prevent CSRF attacks
    });

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
  try {
    const csrf_token_data = await getCSRFToken();
  
    const validcsrftoken = validateCSRFTokenData(data);
  
    if (!validcsrftoken) {
      throw new Error('Invalid CSRFToken');
    };
  
    const encryptedSessionData = await encrypt(csrf_token_data);
  
    const cookieStore = await cookies();
    cookieStore.set('__Secure-csrftoken', encryptedSessionData, {
      httpOnly: true,
      secure: process.env.HTTPS === 'true', // Secure in production
      maxAge: 60 * 60 * 24, // One day in seconds
      path: BASE_ROUTE, // Dynamic path
      sameSite: 'lax', // Helps prevent CSRF attacks
    });
  } catch(error) {
    console.error('Error setting csrftoken:', error);
    throw new Error('Failed to set CSRFToken')
  }
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

export const getSessionIdFromSession = async () =>  {
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
    return decryptedData?.sessionid || null; // Return sessionid if present
  } catch (error) {
    console.error('Error decrypting session data:', error);
    return null; // Return null if decryption fails
  };
};
