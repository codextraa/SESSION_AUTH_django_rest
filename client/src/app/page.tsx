import Link from "next/link";

export default function Page() {
  return (
    <div className="max-w-4xl mx-auto p-8">
      <h1 className="text-3xl font-bold mb-6">Welcome to SESSION-AUTH</h1>
      
      <p className="mb-4 text-gray-700 leading-relaxed font-['Merriweather'] font-bold text-[20px] leading-[25px] text-left text-black">
        A fullstack web application built with <strong>NextJS</strong> for the
        frontend and <strong>Django</strong> for the backend, utilizing{" "}
        <strong>REST</strong> APIs and a <strong>Postgres</strong> database.
        This project demonstrates a secure authentication system using{" "}
        <strong>Session-based authentication</strong>, featuring OTP-based
        login, email verification based registration, email and phone
        verification, password reset, and social media login integration. The
        application starts with a login page where users enter their email and
        password. Upon successful authentication, an OTP is sent to the user's
        email for verification. After verifying the OTP, a session is
        established, and users receive a session ID and CSRF token for accessing
        protected routes. The user can edit thier profile in the{" "}
        <strong>Profile</strong> page. The profile image is retrieved from
        social providers if the account is created using social account.
        Otherwise a default image is set for password users.
      </p>

      <p className="mb-4 text-gray-700 leading-relaxed font-['Merriweather'] font-bold text-[20px] leading-[25px] text-left text-black">
        <strong>Superusers</strong> and <strong>Admins</strong> have elevated
        priviliges where they can access the <strong>Admin Dashboard</strong>{" "}
        and can activate, deactivate, edit or delete an user according to their
        priviliges.
      </p>

      <p className="mb-8 text-gray-700 font-['Merriweather'] font-bold text-[20px] leading-[25px] text-center text-black">
        For more details, visit the{" "}
        <a
          href="https://github.com/codextraa/SESSION_AUTH_django_rest"
          target="_blank"
          rel="noopener noreferrer"
          className="text-blue-600 hover:underline"
        >
          GitHub repository
        </a>
        .
      </p>
    </div>
  );
}