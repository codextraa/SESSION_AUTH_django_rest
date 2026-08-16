"use client";

import { useState, useEffect } from "react";
import { registerFCM } from "@/libs/firebase";

export default function NotificationPrompt({
  isAuthenticated,
}: Readonly<{
  isAuthenticated: boolean;
}>) {
  const [showPrompt, setShowPrompt] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (
      !isAuthenticated ||
      typeof window === "undefined" ||
      !("Notification" in window)
    ) {
      return;
    }

    if (Notification.permission === "default") {
      setShowPrompt(true);
    } else if (Notification.permission === "granted") {
      registerFCM();
    }
  }, [isAuthenticated]);

  const handleEnable = async () => {
    setLoading(true);
    await registerFCM();
    setLoading(false);
    setShowPrompt(false);
  };

  if (!showPrompt) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-sm rounded-lg border border-gray-200 bg-white p-4 shadow-xl dark:border-gray-800 dark:bg-gray-900">
      <h4 className="font-semibold text-gray-900 dark:text-white">
        Enable Notifications
      </h4>
      <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
        Stay updated with real-time push notifications.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          onClick={() => setShowPrompt(false)}
          disabled={loading}
          className="rounded px-3 py-1.5 text-xs text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-slate-800"
        >
          Dismiss
        </button>
        <button
          onClick={handleEnable}
          disabled={loading}
          className="rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? "Registering..." : "Enable"}
        </button>
      </div>
    </div>
  );
}
