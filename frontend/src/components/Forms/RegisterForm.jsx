'use client';
import { useState, useEffect } from 'react';
import { createUserAction } from '@/actions/userActions';
import { getUserRoleAction } from '@/actions/authActions';
import { recaptchaVerifyAction } from '@/actions/authActions';
import { RegisterButton } from '../Buttons/Button';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import styles from './RegisterForm.module.css';

export default function RegisterForm() {
  const router = useRouter();
  const [userRole, setUserRole] = useState(null);
  const [error, setError] = useState(null);
  const [errors, setErrors] = useState(null);
  const [sitekey, setSitekey] = useState('');
  const [isRecaptchaVerified, setIsRecaptchaVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Dynamically load reCAPTCHA script
    const fetchUserRole = async () => {
      const role = await getUserRoleAction();
      if (role === 'Superuser') {
        setUserRole(role);
      }
    };
    fetchUserRole();
  }, []);

  useEffect(() => {
    // Fetch sitekey first
    const fetchSiteKey = async () => {
      setIsLoading(true);
      try {
        const response = await fetch('/api/recaptcha-key');
        const data = await response.json();
        if (data.sitekey) {
          setSitekey(data.sitekey);
          loadRecaptchaScript();
        } else {
          setError('Failed to load reCAPTCHA. Please refresh the page.');
        }
      } catch (error) {
        console.error('Failed to fetch reCAPTCHA sitekey:', error);
        setError('Failed to load reCAPTCHA. Please refresh the page.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchSiteKey();
  }, [router.pathname]);

  const loadRecaptchaScript = () => {
    // Dynamically load reCAPTCHA script
    const script = document.createElement('script');
    script.src = 'https://www.google.com/recaptcha/api.js';
    script.async = true;
    script.defer = true;
    script.onerror = () => {
      console.error('Failed to load reCAPTCHA script');
      setError('Failed to load reCAPTCHA. Please refresh the page.');
    };

    document.body.appendChild(script);

    window.handleRecaptchaCallback = (token) => {
      if (token) {
        setIsRecaptchaVerified(true);
      } else {
        setIsRecaptchaVerified(false);
      }
    };

    return () => {
      document.body.removeChild(script);
    };
  };

  const handleSubmit = async (formData) => {
    /* eslint-disable no-undef */
    if (typeof grecaptcha === 'undefined') {
      setError('reCAPTCHA not loaded. Please refresh the page.');
      return;
    }

    const recaptchaResponse = grecaptcha.getResponse();

    if (!recaptchaResponse) {
      setErrors({ error: 'Please verify you are not a robot.' });
      return;
    }

    const recaptchaValidRes = await recaptchaVerifyAction(recaptchaResponse);

    if (recaptchaValidRes.error) {
      setErrors({ error: recaptchaValidRes.error });
      return;
    }

    let result;
    if (userRole === 'Superuser') {
      result = await createUserAction(formData, 'admin');
    } else {
      result = await createUserAction(formData);
    }

    if (typeof grecaptcha !== 'undefined') {
      grecaptcha.reset();
    }
    setIsRecaptchaVerified(false);

    if (result.error) {
      setErrors(result.error);
    } else if (result.success) {
      if (userRole === 'Superuser') {
        router.push(`/admin-dashboard/new-admin/success`);
      } else {
        router.push(`/auth/register/success`);
      }
    }
  };

  return (
    <form action={handleSubmit} className={styles.form}>
      {error && <p className={styles.error}>{error}</p>}
      {errors && errors.error && <p className={styles.error}>{errors.error}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="email" className={styles.label}>
          Email*
        </label>
        <input type="email" id="email" name="email" className={styles.input} />
      </div>
      {errors && errors.email && <p className={styles.error}>{errors.email}</p>}
      <div className={styles.formGroup}>
        <label htmlFor="username" className={styles.label}>
          Username
        </label>
        <input
          type="text"
          id="username"
          name="username"
          className={styles.input}
        />
      </div>
      {errors && errors.username && (
        <p className={styles.error}>{errors.username}</p>
      )}
      <div className={styles.formGroup}>
        <label htmlFor="first_name" className={styles.label}>
          First Name
        </label>
        <input
          type="text"
          id="first_name"
          name="first_name"
          className={styles.input}
        />
      </div>
      {errors && errors.first_name && (
        <p className={styles.error}>{errors.first_name}</p>
      )}
      <div className={styles.formGroup}>
        <label htmlFor="last_name" className={styles.label}>
          Last Name
        </label>
        <input
          type="text"
          id="last_name"
          name="last_name"
          className={styles.input}
        />
      </div>
      {errors && errors.last_name && (
        <p className={styles.error}>{errors.last_name}</p>
      )}
      <div className={styles.formGroup}>
        <label htmlFor="phone_number" className={styles.label}>
          Phone Number
        </label>
        <input
          type="tel"
          id="phone_number"
          name="phone_number"
          pattern="[+0-9\s()-]*"
          className={styles.input}
        />
        <small className={styles.small}>
          Phone number must contain country code.
        </small>
      </div>
      {errors && errors.phone_number && (
        <p className={styles.error}>{errors.phone_number}</p>
      )}
      <div className={styles.formGroup}>
        <label htmlFor="password" className={styles.label}>
          Password*
        </label>
        <input
          type="password"
          id="password"
          name="password"
          className={styles.input}
        />
        <small className={styles.small}>
          Password must be at least 8 characters.
          <span className={styles.line}>
            Must include at least one uppercase letter, one lowercase letter,
            one number, one special character.
          </span>
        </small>
      </div>
      {errors && errors.password && (
        <p className={styles.error}>{errors.password}</p>
      )}
      <div className={styles.formGroup}>
        <label htmlFor="c_password" className={styles.label}>
          Confirm Password*
        </label>
        <input
          type="password"
          id="c_password"
          name="c_password"
          className={styles.input}
        />
      </div>
      {errors && errors.c_password && (
        <p className={styles.error}>{errors.c_password}</p>
      )}
      {isLoading ? (
        <div>Loading reCAPTCHA...</div>
      ) : sitekey ? (
        <div
          className="g-recaptcha"
          data-sitekey={sitekey}
          data-callback="handleRecaptchaCallback"
        ></div>
      ) : (
        <div className={styles.error}>
          Failed to load reCAPTCHA. Please refresh the page.
        </div>
      )}
      <RegisterButton disabled={!isRecaptchaVerified} />
      {userRole === 'Superuser' ? (
        <Link href={`/admin-dashboard`} className={styles.link}>
          Back to Admin Page
        </Link>
      ) : (
        <Link href={`/auth/login`} className={styles.link}>
          Already have an account? Login
        </Link>
      )}
    </form>
  );
}
