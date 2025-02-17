"use client";
import Link from "next/link";
import { BASE_ROUTE } from "@/route";
import styles from "./UserCard.module.css";

export default function UserCard({ user, userRole, onAction }) {
  return (
    <div className={styles.card}>
      <h3>{user.email}</h3>
      <p>Username: {user.username}</p>
      <p>Status: {user.is_active ? "Active" : "Inactive"}</p>
      <p>Admin: {user.is_staff ? "Yes" : "No"}</p>
      <div className={styles.actions}>
        {user.is_active ? (
          <button onClick={() => onAction("deactivate", user.id)} className={styles.deactivateButton}>
            Deactivate
          </button>
        ) : (
          <button onClick={() => onAction("activate", user.id)} className={styles.activateButton}>
            Activate
          </button>
        )}
        {userRole === "Superuser" && (
          <>
            <Link href={`${BASE_ROUTE}/profile/${user.id}`} className={styles.editButton}>
              Edit
            </Link>
            <button onClick={() => onAction("delete", user.id)} className={styles.deleteButton}>
              Delete
            </button>
          </>
        )}
      </div>
    </div>
  );
};