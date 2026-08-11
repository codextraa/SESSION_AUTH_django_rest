"use client";

import { useEffect, useState, useRef } from "react";
import { authRoute, DEFAULT_LOGIN_REDIRECT } from "@/routes";
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
  const [erroFlag, setErrorFlag] = useState<boolean>(false);
  const [responseMessage, setResponseMessage] = useState<string>("");

  const logoutTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setSession(initialSession);
    setRole(initialRole);
  }, [initialSession, initialRole]);

  // Clean up timer on unmount
  useEffect(() => {
    return () => {
      if (logoutTimeoutRef.current) clearTimeout(logoutTimeoutRef.current);
    };
  }, []);

  if (pathname.startsWith(authRoute)) {
    return null;
  }

  const handleLogout = async () => {
    const response = await logoutAction();

    if (
      response &&
      "error" in response &&
      response.error &&
      typeof response.error === "string"
    ) {
      setResponseMessage(response.error);
      setErrorFlag(true);
    } else if (
      response &&
      "success" in response &&
      response.success &&
      typeof response.success === "string"
    ) {
      setResponseMessage(response.success);
    } else {
      setResponseMessage("Logout failed");
    }

    // Trigger alert visibility
    setAlert(true);

    // Auto-dismiss alert and redirect after a short delay
    logoutTimeoutRef.current = setTimeout(() => {
      setAlert(false);
      if (erroFlag) setErrorFlag(false);
      // Delay navigation slightly so the exit animation can complete, or redirect immediately
      setTimeout(() => {
        router.push(DEFAULT_LOGIN_REDIRECT);
      }, 300);
    }, 2500);
  };

  return (
    <nav className="w-full min-h-[31px] py-4 px-6 pt-[15px] md:px-[80px] flex flex-row items-center justify-between px-6 z-[100]">
      <UpdateAlert alert={alert} message={responseMessage} isError={erroFlag} />
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
