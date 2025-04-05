"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  requestPhoneVerificationAction,
  getUserAction,
  updateUserAction,
  uploadProfileImageAction,
  deactivateUserAction,
} from "@/actions/userActions";
import { getUserIdAction, logoutAction } from "@/actions/authActions";
import { signOut } from "next-auth/react";
import ProfileImage from "../Modals/ProfileImageModal";
import DeactivateModal from "../Modals/DeactivateModal";
import {
  PhoneVerificationRequestButton,
  UpdateButton,
  UploadImageButton,
} from "../Buttons/Button";
import styles from "./UpdateForm.module.css";

export default function UpdatePage({ params }) {
  const [isDeactivateOpen, setIsDeactivateOpen] = useState(false);
  const [otp, setOtp] = useState(false);
  const [user, setUser] = useState(null);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [updateErrors, setUpdateErrors] = useState("");
  const router = useRouter();

  useEffect(() => {
    // In developement react's strict mode calls this twice
    fetchUser();
    const otpRequired = sessionStorage.getItem("otpRequired");
    const otpExpiry = sessionStorage.getItem("otpExpiry");

    if (!otpRequired || Date.now() > parseInt(otpExpiry, 10)) {
      sessionStorage.removeItem("otpRequired");
      sessionStorage.removeItem("otpExpiry");
      setOtp(false);
    } else {
      setOtp(true);
    }
  }, []);

  const fetchUser = async () => {
    const params_obj = await params;
    const user_id = await getUserIdAction();
    setIsDeactivateOpen(user_id === params_obj.id);
    const result = await getUserAction(params_obj.id);
    if (result.data) {
      setUser(result.data);
      setError("");
      setUpdateErrors("");
    } else {
      setSuccess("");
      setError(result.error);
      setUpdateErrors("");
    }
  };

  const handleUpdate = async (formData) => {
    if (
      (formData.get("username") === user.username ||
        !formData.get("username")) &&
      (formData.get("first_name") === user.first_name ||
        (!formData.get("first_name") && !user.first_name)) &&
      (formData.get("last_name") === user.last_name ||
        (!formData.get("last_name") && !user.last_name)) &&
      (formData.get("phone_number") === user.phone_number ||
        (!formData.get("phone_number") && !user.phone_number))
    ) {
      setSuccess("");
      setError("No changes found.");
      setUpdateErrors("");
      return;
    }

    const params_obj = await params;
    const result = await updateUserAction(params_obj.id, formData);
    if (result.success) {
      fetchUser();
      setSuccess(result.success);
      setError("");
      setUpdateErrors("");
    } else {
      setSuccess("");
      setError("");
      setUpdateErrors(result.error);
    }
  };

  const handleUpload = async (file) => {
    if (file.size > 2 * 1024 * 1024) {
      // 2 MB limit
      setSuccess("");
      setError("File size exceeds 2MB. Please upload a smaller image.");
      setUpdateErrors("");
      return;
    }

    const params_obj = await params;
    const formData = new FormData();
    formData.append("profile_img", file);
    const result = await uploadProfileImageAction(params_obj.id, formData);
    if (result.success) {
      fetchUser();
      setSuccess(result.success);
      setError("");
      setUpdateErrors("");
    } else {
      setSuccess("");
      setError(result.error);
      setUpdateErrors("");
    }
  };

  const handlePhoneVerify = async () => {
    const result = await requestPhoneVerificationAction();

    if (result.error) {
      setError(result.error);
      setUpdateErrors("");
      setSuccess("");
    } else if (result.success) {
      setOtp(true);
      setSuccess(result.success);
      setError("");
      setUpdateErrors("");
      sessionStorage.setItem("otpRequired", "true");
      sessionStorage.setItem("otpExpiry", Date.now() + 600000); // 10 minutes
      router.push(`/profile/phone-verify`);
    } else {
      setError("Something went wrong, could not send OTP. Try again");
      setSuccess("");
      setUpdateErrors("");
    }
  };

  const handleDeactivate = async () => {
    const params_obj = await params;
    const result = await deactivateUserAction(params_obj.id);
    if (result.success) {
      setSuccess(result.success);
      setError("");
      setUpdateErrors("");
      await logoutAction(); // DRF rejects request because is_active is false
      await signOut();
      router.push(`/auth/login`);
    } else {
      setSuccess("");
      setError(result.error);
      setUpdateErrors("");
    }
  };

  if (!user) {
    return <div className={styles.loading}>Loading...</div>;
  }

  return (
    <>
      <div className={styles.profile}>
        <ProfileImage src={user.profile_img} alt={user.username} />
        <UploadImageButton onUpload={handleUpload} />
      </div>
      {success && <p className={styles.success}>{success}</p>}
      {error && <p className={styles.error}>{error}</p>}
      {updateErrors.error && (
        <p className={styles.error}>{updateErrors.error}</p>
      )}
      <form action={handleUpdate} className={styles.form}>
        <h2 className={styles.title}>Update Profile</h2>
        <div className={styles.formGroup}>
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            value={user.email}
            disabled
          />
        </div>
        <div className={styles.formGroup}>
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            name="username"
            defaultValue={user.username}
          />
        </div>
        {updateErrors && updateErrors.username && (
          <p className={styles.error}>{updateErrors.username}</p>
        )}
        <div className={styles.formGroup}>
          <label htmlFor="first_name">First Name</label>
          <input
            type="text"
            id="first_name"
            name="first_name"
            defaultValue={user.first_name}
          />
        </div>
        {updateErrors && updateErrors.first_name && (
          <p className={styles.error}>{updateErrors.first_name}</p>
        )}
        <div className={styles.formGroup}>
          <label htmlFor="last_name">Last Name</label>
          <input
            type="text"
            id="last_name"
            name="last_name"
            defaultValue={user.last_name}
          />
        </div>
        {updateErrors && updateErrors.last_name && (
          <p className={styles.error}>{updateErrors.last_name}</p>
        )}
        <div className={styles.formGroup}>
          <label htmlFor="phone_number">
            Phone Number
            {user.is_phone_verified ? " (Verified)" : " (Not Verified)"}
          </label>
          <input
            type="tel"
            id="phone_number"
            name="phone_number"
            defaultValue={user.phone_number}
          />
        </div>
        {updateErrors && updateErrors.phone_number && (
          <p className={styles.error}>{updateErrors.phone_number}</p>
        )}
        <div className={styles.buttons}>
          <UpdateButton />
          {!user.is_phone_verified && user.phone_number && (
            <PhoneVerificationRequestButton onClick={handlePhoneVerify} />
          )}
          {otp && (
            <Link href={`/profile/phone-verify`} className={styles.otpButton}>
              Verify OTP
            </Link>
          )}
        </div>
      </form>
      <div className={styles.buttons}>
        {isDeactivateOpen && (
          <DeactivateModal onDeactivate={handleDeactivate} />
        )}
      </div>
    </>
  );
}
