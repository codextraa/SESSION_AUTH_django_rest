"use client";

import { useState } from "react";
import { requestPasswordResetAction } from "@/actions/passwordActions";
import { PasswordResetRequestButton } from "../Buttons/Button";
import styles from "./PasswordResetRequestForm.module.css";

export default function PasswordResetRequestForm() {
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleSubmit = async (formData) => {
    const result = await requestPasswordResetAction(formData);
    if (result.error) {
      setError(result.error);
      setSuccess("");
    } else if (result.success) {
      setSuccess(result.success);
      setError("");
    }
  };

  return (
    <form action={handleSubmit} className={styles.form}>
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
      <PasswordResetRequestButton />
      {error && <p className={styles.error}>{error}</p>}
      {success && <p className={styles.success}>{success}</p>}
    </form>
  );
}
