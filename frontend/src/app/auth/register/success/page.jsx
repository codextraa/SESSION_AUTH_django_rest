import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import styles from "./page.module.css";

export default function RegisterSuccessPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Registration Successful</h1>
      <p className={styles.message}>Thank you for registering. Your account has been created successfully.</p>
      <p className={styles.message}>Please check your email to verify your account.</p>
      <Link href={`${BASE_ROUTE}/auth/login`} className={styles.link}>
        Back to Login
      </Link>
    </div>
  );
};
