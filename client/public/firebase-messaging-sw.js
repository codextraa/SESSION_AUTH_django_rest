importScripts(
  "https://www.gstatic.com/firebasejs/12.17.1/firebase-app-compat.js",
);
importScripts(
  "https://www.gstatic.com/firebasejs/12.17.1/firebase-messaging-compat.js",
);

firebase.initializeApp({
  apiKey: "AIzaSyBwxM3Dw1RKD5j1xprKxzNdgkJBoqr1BU4",
  authDomain: "codextra-auth.firebaseapp.com",
  projectId: "codextra-auth",
  storageBucket: "codextra-auth.firebasestorage.app",
  messagingSenderId: "952041976682",
  appId: "1:952041976682:web:56e285eccb34179e1d6b13",
  measurementId: "G-MFEW1VNWWJ",
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const notificationTitle = payload.notification?.title || "Notification";
  const notificationOptions = {
    body: payload.notification?.body,
    icon: "/vercel.svg",
    data: {
      url: payload.fcmOptions?.link || payload.data?.url || "/",
    },
  };

  self.registration.showNotification(notificationTitle, notificationOptions);
});
