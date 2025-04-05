"use client";
import Link from "next/link";
import { useState, useEffect } from "react";
import { getUserIdAction, getUserRoleAction } from "@/actions/authActions";
import { LogOutButton } from "../Buttons/Button";
import styles from "./Navbar.module.css";

export default function Navbar() {
  const [userId, setUserId] = useState(null);
  const [userRole, setUserRole] = useState(null);

  useEffect(() => {
    const fetchUserId = async () => {
      const userIdRes = await getUserIdAction();
      if (userIdRes) {
        setUserId(userIdRes);
      }
    };

    const fetchUserRole = async () => {
      const userRoleRes = await getUserRoleAction();
      if (userRoleRes) {
        setUserRole(userRoleRes);
      }
    };

    fetchUserId();
    fetchUserRole();
  });

  return (
    <nav className={styles.navbar}>
      <div>
        <Link href={`/`} className={styles.logo}>
          JWT-AUTH
        </Link>
      </div>
      <div className={styles.navLinks}>
        {userId && (
          <Link href={`/profile/${userId}`} className={styles.link}>
            Profile
          </Link>
        )}
        {(userRole === "Admin" || userRole === "Superuser") && (
          <Link href={`/admin-dashboard`} className={styles.link}>
            Dashboard
          </Link>
        )}
      </div>
      <div className={styles.navLinks}>
        {!userRole && (
          <>
            <Link href={`/auth/login`} className={styles.link}>
              Login
            </Link>
            <Link href={`/auth/register`} className={styles.link}>
              Register
            </Link>
          </>
        )}
        {userRole && <LogOutButton />}
      </div>
    </nav>
  );
}
