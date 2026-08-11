import { NextRequest, NextResponse } from "next/server";
import {
  SuccessResponse,
  ErrorResponse,
  SocialProvider,
} from "@/types/authTypes";

//* Social utils

export const PROVIDER_MAP: Record<string, SocialProvider> = {
  google: "google-oauth2",
  facebook: "facebook",
  github: "github",
  microsoft: "microsoft-graph",
  linkedin: "linkedin-openidconnect",
  amazon: "amazon",
};

export class OAuthCallbackHandler {
  private searchParams: URLSearchParams;
  private baseUrl: string;
  private provider: SocialProvider;
  private providerPath: string;
  private requestCookies: NextRequest["cookies"];

  constructor(
    searchParams: URLSearchParams,
    provider: SocialProvider,
    providerPath: string,
    requestCookies: NextRequest["cookies"],
    baseUrl: string = process.env.NEXT_PUBLIC_BASE_HTTPS_URL ||
      "http://localhost:3000",
  ) {
    this.searchParams = searchParams;
    this.baseUrl = baseUrl;
    this.provider = provider;
    this.providerPath = providerPath;
    this.requestCookies = requestCookies;
  }

  public getRedirectUri(): string {
    return `${this.baseUrl}/api/auth/callback/${this.providerPath}`;
  }

  public redirectToLogin(errorMessage: string): NextResponse {
    const encodedError = encodeURIComponent(errorMessage);
    return NextResponse.redirect(
      `${this.baseUrl}/auth/login?error=${encodedError}`,
    );
  }

  public redirectToHome(): NextResponse {
    const response = NextResponse.redirect(`${this.baseUrl}/`);
    // Clear the cookie based on the provider
    response.cookies.delete(`${this.providerPath}_oauth2_token`);
    return response;
  }

  //* Handle the OAuth callback Response
  public async handleCallback(): Promise<SuccessResponse | ErrorResponse> {
    if (!this.provider) {
      return { error: "Unsupported OAuth provider" };
    }

    switch (this.provider) {
      case "google-oauth2":
        return await this.handleGoogleCallback();
      // case "facebook":
      //   return await this.handleFacebook();
      // case "github":
      //   return await this.handleGithub();
      default:
        return { error: "Unsupported OAuth provider" };
    }
  }

  //* Google Response
  private async handleGoogleCallback(): Promise<
    SuccessResponse | ErrorResponse
  > {
    const code = this.searchParams.get("code");
    const state = this.searchParams.get("state");
    const error = this.searchParams.get("error");
    const errorDescription = this.searchParams.get("error_description");

    if (error) {
      console.error(errorDescription || error);
      return { error: "Google authentication failed." };
    }

    const stateFromCookie = this.requestCookies.get(
      "google_oauth2_token",
    )?.value;

    if (!state || !stateFromCookie || state !== stateFromCookie) {
      console.error("Invalid OAuth state. Possibly a CSRF attack.");
      return { error: "Authentication failed. Please try signing in again." };
    }

    if (!code) {
      console.error("Google code missing.");
      return { error: "Google authentication failed." };
    }

    return { success: code };
  }
}
