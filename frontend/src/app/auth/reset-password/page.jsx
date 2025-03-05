import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import { verifyResetLinkAction } from "@/actions/passwordActions";
import PasswordResetForm from "@/components/Forms/PasswordResetForm";
import styles from "./page.module.css";


export default async function PasswordResetPage({ searchParams }) {
  const params = await searchParams;
  const { token, expiry } = params;
  const verificationResult = await verifyResetLinkAction(token, expiry);

  if (verificationResult.error) {
    return (
      <div className={styles.container}>
        <h1 className={styles.title}>Reset Password</h1>
        <p className={styles.error}>{verificationResult.error}</p>
        <Link href={`${BASE_ROUTE}/auth/login`} className={styles.backToLogin}>
          Back to Login
        </Link>
      </div>
    );
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Reset Password</h1>
      <PasswordResetForm token={token} expiry={expiry} />
      <Link href={`${BASE_ROUTE}/auth/login`} className={styles.backToLogin}>
        Back to Login
      </Link>
    </div>
  );
};