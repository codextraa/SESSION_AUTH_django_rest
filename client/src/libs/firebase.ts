"use client";

import { initializeApp, getApps, getApp } from "firebase/app";
import { fcmTokenAction } from "@/actions/authActions";
import {
  getMessaging,
  isSupported,
  Messaging,
  register,
  onRegistered,
} from "firebase/messaging";

const firebaseConfig = {
  apiKey: "AIzaSyBwxM3Dw1RKD5j1xprKxzNdgkJBoqr1BU4",
  authDomain: "codextra-auth.firebaseapp.com",
  projectId: "codextra-auth",
  storageBucket: "codextra-auth.firebasestorage.app",
  messagingSenderId: "952041976682",
  appId: "1:952041976682:web:56e285eccb34179e1d6b13",
  measurementId: "G-MFEW1VNWWJ",
};

// Prevent re-initialization during HMR or SSR
const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();

// FCM Messaging Instance only if supported
const getMessagingInstance = async (): Promise<Messaging | null> => {
  const supported = await isSupported();
  if (typeof window !== "undefined" && supported) {
    return getMessaging(app);
  }
  return null;
};

// FCM Registration
const registerFCM = async (): Promise<void> => {
  try {
    if (!("serviceWorker" in navigator) || !("Notification" in window)) {
      return;
    }

    const permission = await Notification.requestPermission();
    if (permission !== "granted") return;

    const swRegistration = await navigator.serviceWorker.register(
      "/firebase-messaging-sw.js",
    );

    const messaging = await getMessagingInstance();
    if (!messaging) return;

    onRegistered(messaging, async (fid: string) => {
      if (fid) {
        const data = { fcm_token: fid };
        const response = await fcmTokenAction(data);

        if (response && "error" in response && response.error) {
          console.error(response.error);
        }
      }
    });

    await register(messaging, {
      serviceWorkerRegistration: swRegistration,
      vapidKey: process.env.NEXT_PUBLIC_FIREBASE_VAPID_KEY,
    });
  } catch (error) {
    console.error("FID registration error:", error);
  }
};

export { app, registerFCM };
