import EmailVerificationRequestForm from "@/components/Forms/EmailVerificationRequestForm";
import styles from "./page.module.css";

export default function EmailVerificationRequestPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Request Email Verification</h1>
      <EmailVerificationRequestForm />
    </div>
  );
}
