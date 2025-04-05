import Link from "next/link";
import styles from "./EmailVerificationResult.module.css";

export default function EmailVerificationResult({ result }) {
  return (
    <div className={styles.container}>
      {result.success ? (
        <p className={styles.success}>
          Your email has been successfully verified!
        </p>
      ) : (
        <p className={styles.error}>{result.error}</p>
      )}
      <Link href={`/auth/login`} className={styles.backLink}>
        Back to Login
      </Link>
    </div>
  );
}
