"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { BASE_ROUTE } from "@/route";
import { resetPasswordAction } from "@/actions/passwordActions";
import styles from "./PasswordResetForm.module.css";
import { PasswordResetButton } from "../Buttons/Button";


export default function PasswordResetForm({ token, expiry }) {
  const router = useRouter();
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (formData) => {
    formData.append("token", token);
    formData.append("expiry", expiry);
    const result = await resetPasswordAction(formData);
    if (result.error) {
      setError(result.error);
      setSuccess("");
    } else if (result.success) {
      setSuccess(result.success);
      setError("");
      router.push(`${BASE_ROUTE}/auth/login`);
    };
  };

  return (
    <form action={handleSubmit} className={styles.form}>
      <div className={styles.formGroup}>
        <label htmlFor="password" className={styles.label}>
          New Password
        </label>
        <input type="password" id="password" name="password" required className={styles.input} />
        <small className={styles.small}>
          Password must be at least 8 characters.
          <span className={styles.line}>Must include at least
            one uppercase letter, 
            one lowercase letter, 
            one number, 
            one special character. 
          </span>
        </small>
      </div>
      <div className={styles.formGroup}>
        <label htmlFor="c_password" className={styles.label}>
          Confirm New Password
        </label>
        <input type="password" id="c_password" name="c_password" required className={styles.input} />
      </div>
      <PasswordResetButton />
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
    </form>
  );
};