import OtpForm from "@/components/Forms/OtpForm";
import styles from "./page.module.css";

export default function OtpPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>OTP Verification</h1>
      <OtpForm action="register" />
    </div>
  );
}
