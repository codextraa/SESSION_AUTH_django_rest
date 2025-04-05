"use client";
import Link from "next/link";
import { DEFAULT_LOGIN_REDIRECT } from "@/route";
import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { verifyOtpAction, resendOtpAction } from "@/actions/authActions";
import {
  requestPhoneVerificationAction,
  verifyPhoneAction,
} from "@/actions/userActions";
import { OtpVerifyButton, ResendOtpButton } from "../Buttons/Button";
import { decrypt } from "@/libs/session";
import styles from "./OtpForm.module.css";

export default function OtpForm({ action }) {
  const router = useRouter();
  const [formAction, setFormAction] = useState("");
  const [timer, setTimer] = useState(60);
  const [canResend, setCanResend] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const intervalRef = useRef(null);

  useEffect(() => {
    fetchFormAction();
    const otpRequired = sessionStorage.getItem("otpRequired");
    const otpExpiry = sessionStorage.getItem("otpExpiry");

    if (!otpRequired || Date.now() > parseInt(otpExpiry, 10)) {
      router.push(`/auth/login`);
    }

    // Start the timer when the component is mounted
    intervalRef.current = setInterval(() => {
      setTimer((prevTimer) => {
        if (prevTimer === 0) {
          setCanResend(true);
          clearInterval(intervalRef.current); // Clear the interval when the timer reaches 0
          return 0;
        }
        return prevTimer - 1;
      });
    }, 1000);

    // Cleanup the interval when the component is unmounted
    return () => clearInterval(intervalRef.current);
  }, [router]);

  const fetchFormAction = async () => {
    const formAction = await action;
    setFormAction(formAction);
  };

  const handleSubmit = async (formData) => {
    if (formAction === "register") {
      try {
        const session_user_id = sessionStorage.getItem("user_id");

        if (!session_user_id) {
          setError("Session expired. Please login again");
          sessionStorage.clear();
          router.push(`/auth/login`);
          return;
        }

        const userId = await decrypt(session_user_id);
        formData.append("user_id", userId);
      } catch (error) {
        console.error("Error decrypting user_id:", error);
        setError("Something went wrong, could not send OTP. Try again");
        return;
      }
      const result = await verifyOtpAction(formData);
      if (result.error) {
        setError(result.error);
        setSuccessMessage("");
      } else if (result.success) {
        setSuccessMessage(result.success);
        setError("");
        sessionStorage.clear();
        router.push(`${DEFAULT_LOGIN_REDIRECT}`);
      }
    } else if (formAction === "phone-verify") {
      try {
        const result = await verifyPhoneAction(formData);
        if (result.error) {
          setError(result.error);
          setSuccessMessage("");
        } else if (result.success) {
          setSuccessMessage(result.success);
          setError("");
          sessionStorage.clear();
          router.push(`${DEFAULT_LOGIN_REDIRECT}`);
        }
      } catch (error) {
        console.error("Error decrypting user_id:", error);
      }
    } else {
      console.error("Invalid form action:", formAction);
      setError("Something went wrong, Contact Admin");
      return;
    }
  };

  const handleResendOtp = async () => {
    if (formAction === "register") {
      try {
        const session_user_id = sessionStorage.getItem("user_id");

        if (!session_user_id) {
          setError("Session expired. Please login again");
          sessionStorage.clear();
          router.push(`/auth/login`);
          return;
        }

        const userId = await decrypt(session_user_id);
        const result = await resendOtpAction(userId);

        if (result.error) {
          setError(result.error);
          setSuccessMessage("");
        }

        if (result.success) {
          setSuccessMessage(result.success);
          setError("");
          sessionStorage.setItem("otpExpiry", Date.now() + 600000);
        }
      } catch (error) {
        console.error("Error decrypting user_id:", error);
        setError("Something went wrong, could not send OTP. Try again");
        return;
      }
    } else if (formAction === "phone-verify") {
      const result = await requestPhoneVerificationAction();
      if (result.error) {
        setError(result.error);
        setSuccessMessage("");
      } else if (result.success) {
        setSuccessMessage(result.success);
        setError("");
        sessionStorage.setItem("otpExpiry", Date.now() + 600000);
      }
    } else {
      console.error("Invalid form action:", formAction);
      setError("Something went wrong, Contact Admin");
      return;
    }

    setTimer(60);
    setCanResend(false);

    clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      setTimer((prevTimer) => {
        if (prevTimer === 0) {
          setCanResend(true);
          clearInterval(intervalRef.current); // Clear interval when timer reaches 0
          return 0;
        }
        return prevTimer - 1;
      });
    }, 1000);
  };

  return (
    <form className={styles.form} action={handleSubmit}>
      {error && <p className={styles.error}>{error}</p>}
      {successMessage && <p className={styles.success}>{successMessage}</p>}
      <div className={styles.inputGroup}>
        <label htmlFor="otp">Enter the OTP sent in your mail:</label>
        <input type="text" id="otp" name="otp" required />
      </div>
      <div className={styles.actionLinks}>
        {formAction === "register" && (
          <Link href={`/auth/login`} className={styles.backToLogin}>
            Back to Login
          </Link>
        )}
        {formAction === "phone-verify" && (
          <Link
            href={`${DEFAULT_LOGIN_REDIRECT}`}
            className={styles.backToLogin}
          >
            Back to HomePage
          </Link>
        )}
      </div>
      <OtpVerifyButton />
      <ResendOtpButton
        onClick={handleResendOtp}
        disabled={!canResend}
        timer={timer}
      />
    </form>
  );
}
