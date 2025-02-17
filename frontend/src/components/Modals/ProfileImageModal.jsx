"use client";
import { useState } from "react";
import Image from "next/image";
import styles from "./ProfileImageModal.module.css";

export default function ProfileImage({ src, alt }) {
  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <div className={styles.container}>
      <div className={styles.imageWrapper} onClick={() => setIsModalOpen(true)}>
        <Image
          src={src || "/placeholder.svg?height=200&width=200"}
          alt={alt}
          width={200}
          height={200}
          className={styles.profileImage}
          priority
        />
      </div>
      {isModalOpen && (
        <div className={styles.modal} onClick={() => setIsModalOpen(false)}>
          <Image
            src={src || "/placeholder.svg?height=600&width=600"}
            alt={alt}
            width={600}
            height={600}
            className={styles.modalImage}
          />
        </div>
      )}
    </div>
  );
};