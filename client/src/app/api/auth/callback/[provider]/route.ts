import { NextRequest } from "next/server";
import {
  PROVIDER_MAP,
  OAuthCallbackHandler,
} from "@/libs/oauthCallbackHandler";
import { setSessionCookie } from "@/libs/cookie";
import { socialLogin } from "@/libs/api";
import { SocialLoginErrorFields } from "@/types/authTypes";
import { socialLoginServerError } from "@/libs/errors";

export async function GET(
  request: NextRequest,
  {
    params,
  }: {
    params: Promise<{ provider: string }>;
  },
) {
  const { provider: providerPath } = await params;
  const socialProvider = PROVIDER_MAP[providerPath];

  const oauthHandler = new OAuthCallbackHandler(
    request.nextUrl.searchParams,
    socialProvider,
    providerPath,
    request.cookies,
  );

  const response = await oauthHandler.handleCallback();

  if ("error" in response) {
    return oauthHandler.redirectToLogin(response.error as string);
  }

  const data = {
    provider: socialProvider,
    social_auth_code: response.success as string,
    redirect_uri: oauthHandler.getRedirectUri(),
  };

  try {
    const response = await socialLogin(data);

    if (response && "error" in response && response.error) {
      console.log("response.error", response.error);
      const responseError: SocialLoginErrorFields =
        await socialLoginServerError(response);
      const errorMessage =
        responseError.general ||
        responseError.social_auth_code ||
        responseError.provider ||
        responseError.redirect_uri ||
        "An error occurred during Google sign-in.";

      return oauthHandler.redirectToLogin(errorMessage);
    } else if (
      typeof response === "object" &&
      "sessionid" in response &&
      response.sessionid &&
      "session_expiry" in response &&
      response.session_expiry &&
      "user_id" in response &&
      response.user_id &&
      "user_role" in response &&
      response.user_role &&
      "csrf_token" in response &&
      response.csrf_token &&
      "csrf_token_expiry" in response &&
      response.csrf_token_expiry
    ) {
      await setSessionCookie(response);
      return oauthHandler.redirectToHome();
    }

    return oauthHandler.redirectToLogin("An error occurred during login.");
  } catch (error) {
    console.error(error);
    return oauthHandler.redirectToLogin("An error occurred during login.");
  }
}
