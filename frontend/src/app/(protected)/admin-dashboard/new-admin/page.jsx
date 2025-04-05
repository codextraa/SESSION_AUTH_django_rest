import RegisterForm from "@/components/Forms/RegisterForm";
import styles from "@/app/auth/register/page.module.css";

export default function RegisterPage() {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>Create New Admin</h1>
      <RegisterForm />
    </div>
  );
}
