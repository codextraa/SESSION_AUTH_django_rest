"use client";
import { useState } from "react";
import Link from "next/link";
import { requestEmailVerificationAction } from "@/actions/userActions";
import styles from "./EmailVerificationRequestForm.module.css";
import { EmailVerificationRequestButton } from "../Buttons/Button";

export default function EmailVerificationRequestForm() {
  const [formOpen, setFormOpen] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (formData) => {
    const result = await requestEmailVerificationAction(formData);
    if (result.error) {
      setError(result.error);
      setSuccess("");
    } else if (result.success) {
      setFormOpen(false);
      setSuccess(
        "Verification link sent successfully. Please check your email.",
      );
      setError("");
    }
  };

  return (
    <form action={handleSubmit} className={styles.form}>
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
      {formOpen && (
        <>
          <div className={styles.formGroup}>
            <label htmlFor="email" className={styles.label}>
              Email
            </label>
            <input
              type="email"
              id="email"
              name="email"
              required
              className={styles.input}
            />
          </div>
          <EmailVerificationRequestButton />
        </>
      )}
      <Link href={`/auth/login`} className={styles.backLink}>
        Back to Login
      </Link>
    </form>
  );
}
