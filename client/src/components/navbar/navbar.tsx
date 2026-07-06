"use client";

import { useEffect, useState } from "react";
import { authRoute, DEFAULT_LOGIN_REDIRECT } from "@/route";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import UpdateAlert from "@/components/alerts/UpdateAlert";
import { TextNavLink, ActionNavButton } from "@/components/buttons/button";
import { logoutAction } from "@/actions/authActions";

interface NavbarProps {
  initialSession: string | null;
  initialRole: string | null;
}

export default function Navbar({ initialSession, initialRole }: NavbarProps) {
  const pathname = usePathname();
  const router = useRouter();

  const [session, setSession] = useState<string | null>(initialSession);
  const [role, setRole] = useState<string | null>(initialRole);
  const [alert, setAlert] = useState<boolean>(false);
  const [responseMessage, setResponseMessage] = useState<string>("");

  useEffect(() => {
    setSession(initialSession);
    setRole(initialRole);
  }, [initialSession, initialRole]);

  if (pathname.startsWith(authRoute)) {
    return null;
  }
  // 1. First, define a ref at the top of your component to store the timer ID safely
  // const logoutTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleLogout = async () => {
    const response = await logoutAction();
    if (
      response &&
      "error" in response &&
      response.error &&
      typeof response.error === "string"
    ) {
      setAlert(true);
      setResponseMessage(response.error);
    } else if (
      response &&
      "success" in response &&
      response.success &&
      typeof response.success === "string"
    ) {
      setAlert(true);
      setResponseMessage(response.success);
    } else {
      setAlert(true);
      setResponseMessage("Logout failed");
    }

    // logoutTimeoutRef.current = setTimeout(() => {
    //   setAlert(false);
    //   setResponseMessage(""); // Optional: clear message text too
    // }, 5000);

    router.push(DEFAULT_LOGIN_REDIRECT);
  };

  // useEffect(() => {
  //   return () => {
  //     if (logoutTimeoutRef.current) clearTimeout(logoutTimeoutRef.current);
  //   };
  // }, []);

  return (
    <nav className="w-full min-h-[31px] py-4 px-6 pt-[15px] md:px-[80px] flex flex-row items-center justify-between px-6 z-[100]">
      <UpdateAlert alert={alert} message={responseMessage} />
      <Link
        href="/"
        className="w-[48px] h-[25px] font-['Merriweather'] font-bold text-[20px] leading-[25px] text-center text-black"
      >
        Auth
      </Link>

      <div className="flex flex-row items-center gap-[20px] h-[31px]">
        {!session ? (
          <>
            <TextNavLink href="/auth/signup" label="Register" />
            <ActionNavButton href="/auth/login" label="Log In" />
          </>
        ) : (
          <>
            <TextNavLink
              href="/profile"
              label="Profile"
              className="w-[60px] underline"
            />

            {(role === "admin" || role === "superuser") && (
              <TextNavLink href="/admin/dashboard" label="Dashboard" />
            )}
            <ActionNavButton onClick={handleLogout} label="Log Out" />
          </>
        )}
      </div>
    </nav>
  );
}
