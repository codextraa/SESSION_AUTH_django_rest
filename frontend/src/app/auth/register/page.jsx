import RegisterForm from "@/components/Forms/RegisterForm";
import styles from "./page.module.css";

export default function RegisterPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Register</h1>
      <RegisterForm />
    </div>
  );
};
