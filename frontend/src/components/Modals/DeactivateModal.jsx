"use client"

import { useState } from "react"
import styles from "./DeactivateModal.module.css"

export default function DeactivateModal({ onDeactivate }) {
  const [showModal, setShowModal] = useState(false)

  const handleDeactivate = () => {
    setShowModal(true)
  }

  const confirmDeactivate = () => {
    onDeactivate()
    setShowModal(false)
  }

  return (
    <div>
      <button onClick={handleDeactivate} className={styles.button}>
        Deactivate Account
      </button>
      {showModal && (
        <div className={styles.modal}>
          <div className={styles.modalContent}>
            <p>Are you sure you want to deactivate your account?</p>
            <button onClick={confirmDeactivate} className={styles.yesButton}>
              Yes
            </button>
            <button onClick={() => setShowModal(false)} className={styles.noButton}>
              No
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
