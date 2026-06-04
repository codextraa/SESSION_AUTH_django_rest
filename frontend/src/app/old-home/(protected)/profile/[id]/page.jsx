import UpdatePage from "@/components/Forms/UpdateForm";
import styles from "./page.module.css";

export default function ProfilePage({ params }) {
  return (
    <div className={styles.container}>
      <h1 className={styles.title}>User Profile</h1>
      <UpdatePage params={params} />
    </div>
  );
}
