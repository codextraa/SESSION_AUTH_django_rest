import Link from "next/link";
import PasswordResetRequestForm from "@/components/Forms/PasswordResetRequestForm";
import styles from "./page.module.css";

export default function PasswordResetRequestPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Reset Password</h1>
      <PasswordResetRequestForm />
      <Link href={`/auth/login`} className={styles.backToLogin}>
        Back to Login
      </Link>
    </div>
  );
}
