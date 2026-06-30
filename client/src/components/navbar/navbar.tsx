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
  const [responseMessage, setResponseMessage] = useState<object | string>({});

  useEffect(() => {
    setSession(initialSession);
    setRole(initialRole);
  }, [initialSession, initialRole]);

  if (pathname.startsWith(authRoute)) {
    return null;
  }

  const handleLogout = async () => {
    const response = await logoutAction();
    if (response && "error" in response && response.error) {
      setAlert(true);
      setResponseMessage(response);
    } else if (response && "success" in response && response.success) {
      setAlert(true);
      setResponseMessage(response);
    } else {
      setAlert(true);
      setResponseMessage("Logout failed");
    }

    router.push(DEFAULT_LOGIN_REDIRECT);
  };

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
