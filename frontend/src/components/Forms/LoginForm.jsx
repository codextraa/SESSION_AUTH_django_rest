"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { loginAction, recaptchaVerifyAction } from "@/actions/authActions";
import { encrypt } from "@/libs/session";
import styles from "./LoginForm.module.css";
import {
  LoginButton,
  GoogleLoginButton,
  FacebookLoginButton,
  GitHubLoginButton,
  // InstagramLoginButton,
  // TwitterLoginButton,
  // LinkedInLoginButton,
} from "../Buttons/Button";

export default function LoginForm() {
  const router = useRouter();
  const [otp, setOtp] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [sitekey, setSitekey] = useState("");
  const [isRecaptchaVerified, setIsRecaptchaVerified] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check for error parameter in URL
    const searchParams = new URLSearchParams(window.location.search);
    const urlError = searchParams.get("error");
    if (urlError) {
      setError(urlError);
    }

    const otpRequired = sessionStorage.getItem("otpRequired");
    const otpExpiry = sessionStorage.getItem("otpExpiry");

    if (!otpRequired || Date.now() > parseInt(otpExpiry, 10)) {
      sessionStorage.removeItem("otpRequired");
      sessionStorage.removeItem("otpExpiry");
      setOtp(false);
    } else {
      setOtp(true);
    }
  }, []);

  useEffect(() => {
    // Fetch sitekey first
    const fetchSiteKey = async () => {
      setIsLoading(true);
      try {
        const response = await fetch("/api/recaptcha-key");
        const data = await response.json();
        if (data.sitekey) {
          setSitekey(data.sitekey);
          loadRecaptchaScript();
        } else {
          setError("Failed to load reCAPTCHA. Please refresh the page.");
        }
      } catch (error) {
        console.error("Failed to fetch reCAPTCHA sitekey:", error);
        setError("Failed to load reCAPTCHA. Please refresh the page.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchSiteKey();
  }, [router.pathname]); // Re-fetch on route change

  const loadRecaptchaScript = () => {
    // Dynamically load reCAPTCHA script
    const script = document.createElement("script");
    script.src = "https://www.google.com/recaptcha/api.js";
    script.async = true;
    script.defer = true;
    script.onerror = () => {
      console.error("Failed to load reCAPTCHA script");
      setError("Failed to load reCAPTCHA. Please refresh the page.");
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
    if (typeof grecaptcha === "undefined") {
      setError("reCAPTCHA not loaded. Please refresh the page.");
      return;
    }

    const recaptchaResponse = grecaptcha.getResponse();

    if (!recaptchaResponse) {
      setError("Please verify you are not a robot.");
      return;
    }

    const recaptchaValidRes = await recaptchaVerifyAction(recaptchaResponse);

    if (recaptchaValidRes.error) {
      setError(recaptchaValidRes.error);
      return;
    }

    if (formData.has("login")) {
      const result = await loginAction(formData);

      if (result.error) {
        setError(result.error);
        setSuccess("");
      } else if (result.success && result.otp) {
        setOtp(true);
        try {
          const userId = await encrypt(result.user_id);
          sessionStorage.setItem("user_id", userId);
        } catch (error) {
          console.error("Error encrypting user_id:", error);
          setError("Something went wrong. Try again");
          return;
        }
        setSuccess(result.success);
        setError("");
        sessionStorage.setItem("otpRequired", "true");
        sessionStorage.setItem("otpExpiry", Date.now() + 600000); // 10 minutes
        router.push(`/auth/otp`);
      } else {
        setError("Something went wrong, could not send OTP. Try again");
      }
    } else {
      const provider = formData.has("google")
        ? "google"
        : formData.has("facebook")
          ? "facebook"
          : formData.has("github")
            ? "github"
            : "";

      if (!provider) {
        setError("Please select a provider");
        return;
      }

      try {
        await signIn(provider, { redirectTo: "/" });
      } catch (error) {
        console.error("Error signing in:", error);
        setError("Something went wrong. Try again");
      }
    }

    if (typeof grecaptcha !== "undefined") {
      grecaptcha.reset();
    }
    setIsRecaptchaVerified(false);
  };

  return (
    <form className={styles.form} action={handleSubmit}>
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
      <div className={styles.inputGroup}>
        <label htmlFor="email">Email:</label>
        <input type="email" id="email" name="email" />
      </div>
      <div className={styles.inputGroup}>
        <label htmlFor="password">Password:</label>
        <input type="password" id="password" name="password" />
      </div>
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
      <LoginButton disabled={!isRecaptchaVerified} />
      <div className={styles.actionLinks}>
        <Link href={`/auth/register`} className={styles.forgotPassword}>
          Register an account
        </Link>
        <Link href={`/auth/verify-email/request`} className={styles.verifyOtp}>
          Verify Email
        </Link>
      </div>
      <div className={styles.actionLinks}>
        <Link
          href={`/auth/reset-password/request`}
          className={styles.forgotPassword}
        >
          Forgot Password?
        </Link>
        {otp && (
          <Link href={`/auth/otp`} className={styles.verifyOtp}>
            Verify OTP
          </Link>
        )}
      </div>
      <div className={styles.socialLogin}>
        <GoogleLoginButton disabled={!isRecaptchaVerified} />
        <FacebookLoginButton disabled={!isRecaptchaVerified} />
        <GitHubLoginButton disabled={!isRecaptchaVerified} />
        {/* <InstagramLoginButton /> */}
        {/* <TwitterLoginButton /> */}
        {/* <LinkedInLoginButton /> */}
      </div>
    </form>
  );
}
