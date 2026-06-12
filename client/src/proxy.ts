import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { ResponseCookie } from "@edge-runtime/cookies";
import {
  getSessionExpiryFromSession,
  updateSessionCookie,
  getCSRFTokenExpiryFromSession,
  setCSRFCookie,
} from "@/libs/cookie";
import {
  DEFAULT_LOGIN_REDIRECT,
  publicRoutes,
  apiRoute,
  authRoute,
} from "./route";

export async function proxy(req: NextRequest) {
  console.warn("Middleware triggered");
  // const nonce = req.headers.get("x-csp-nonce") || "";
  const { pathname } = req.nextUrl;

  const isPublicRoute = publicRoutes.includes(pathname);
  const isApiRoute = pathname.startsWith(apiRoute);
  const isAuthRoute = pathname.startsWith(authRoute);

  const res = NextResponse.next();
  // if (nonce) {
  // res.headers.set('Content-Security-Policy', `script-src 'nonce-${nonce}'`);
  // }

  if (isPublicRoute) {
    console.warn("Handling public route");
    return res; // Allow access to public routes
  }

  if (isApiRoute) {
    console.warn("Handling API route");
    return undefined; // Allow access to API routes
  }

  let isLoggedIn: boolean | null = await getSessionExpiryFromSession();
  let updatedCookie: ResponseCookie | false | undefined = false;

  if (!isLoggedIn) {
    updatedCookie = await updateSessionCookie(req);
    if (updatedCookie) {
      isLoggedIn = true;
    }
  }

  const csrfToken = await getCSRFTokenExpiryFromSession();
  if (!csrfToken) {
    await setCSRFCookie();
  }

  if (isAuthRoute) {
    console.warn("Handling auth route");
    if (isLoggedIn) {
      console.warn("User is logged in, redirecting to home page");
      // Avoid redirect loop if already at the login page
      if (pathname === DEFAULT_LOGIN_REDIRECT) {
        console.warn("Skipping middleware for DEFAULT_LOGIN_REDIRECT");
        return res;
      }
      return NextResponse.redirect(new URL(DEFAULT_LOGIN_REDIRECT, req.url)); // Redirect to homepage or dashboard
    }
    return res; // Allow access to login/register if not logged in
  }

  // Redirect unauthenticated users from protected routes to the login page
  if (!isLoggedIn) {
    console.warn(`User is not logged in, redirecting to /auth/login`);
    // Prevent redirect loop if already at the login page
    if (pathname === "/auth/login") {
      console.warn("Skipping middleware for /auth/login");
      return res;
    }
    return NextResponse.redirect(new URL("/auth/login", req.url)); // Redirect to login page
  }

  if (updatedCookie) {
    // Set the updated session cookie in the response
    // cookieStore takes time to set the cookie and update the client side
    // therefore it is not available right at the moment the next request is called
    // this is for the next response so that it gets the updated cookie value
    res.cookies.set(updatedCookie.name, updatedCookie.value, {
      httpOnly: updatedCookie.httpOnly,
      secure: updatedCookie.secure,
      maxAge: updatedCookie.maxAge,
      path: updatedCookie.path,
      sameSite: updatedCookie.sameSite,
    });
  }

  // If everything is fine, allow the request to continue
  return res;
}

export const config = {
  matcher: [
    // Skip Next.js internals and all static files, unless found in search params
    "/((?!_next|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)",
    // Always run for API routes
    "/(api|trpc)(.*)",
    "/",
  ],
};
