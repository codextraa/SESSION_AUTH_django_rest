"use client";

import type { SocialProvider } from "@/types/authTypes";

const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "";
// const FACEBOOK_CLIENT_ID = process.env.NEXT_PUBLIC_FACEBOOK_CLIENT_ID || "";
// const GITHUB_CLIENT_ID = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID || "";
// const MICROSOFT_CLIENT_ID = process.env.NEXT_PUBLIC_MICROSOFT_CLIENT_ID || "";
// const LINKEDIN_CLIENT_ID = process.env.NEXT_PUBLIC_LINKEDIN_CLIENT_ID || "";
// const AMAZON_CLIENT_ID = process.env.NEXT_PUBLIC_AMAZON_CLIENT_ID || "";

function loadScript(url: string, id: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window === "undefined") {
      reject(new Error("Cannot load script in a non-browser environment."));
      return;
    }

    if (document.getElementById(id)) return resolve();

    const script = document.createElement("script");
    script.id = id;
    script.src = url;
    script.async = true;
    script.defer = true;

    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`Failed to load script: ${url}`));

    document.head.appendChild(script);
  });
}

// ----------------------------------------------------------------------------
//* Base class — every provider implements this contract
// ----------------------------------------------------------------------------

export abstract class SocialAuthProvider {
  // Provider name (cannot be overwritten after intialization)
  abstract readonly provider: SocialProvider;

  // Loads any vendor SDK / prepares state. Safe to call multiple times.
  abstract init(): Promise<void>;

  // Triggers the sign-in UX and redirects to the callback page
  abstract authorize(): Promise<void>;

  // Generate unique state token and set it as a cookie
  protected createAndSetStateCookie(cookieName: string): string {
    const stateToken = window.crypto?.randomUUID
      ? window.crypto.randomUUID()
      : Math.random().toString(36).substring(2);

    document.cookie = `${cookieName}=${stateToken}; path=/; max-age=60; SameSite=Lax; Secure`;
    return stateToken;
  }
}

// ----------------------------------------------------------------------------
//* Google — Google Identity Services (native SDK, returns an id_token)
// ----------------------------------------------------------------------------

class GoogleAuthProvider extends SocialAuthProvider {
  readonly provider: SocialProvider = "google-oauth2";
  private initialized = false;

  async init(): Promise<void> {
    if (this.initialized) return;

    if (!GOOGLE_CLIENT_ID) {
      throw new Error("Missing GOOGLE_CLIENT_ID.");
    }

    await loadScript(
      "https://accounts.google.com/gsi/client",
      "google-gsi-script",
    );
    this.initialized = true;
  }

  async authorize(): Promise<void> {
    await this.init();

    if (!window.google?.accounts?.oauth2) {
      throw new Error("Google SDK failed to load.");
    }

    const stateToken = this.createAndSetStateCookie("google_oauth2_token");
    const redirectURL = `${process.env.NEXT_PUBLIC_BASE_HTTPS_URL}/api/auth/callback/google`;

    const client = window.google.accounts.oauth2.initCodeClient({
      client_id: GOOGLE_CLIENT_ID,
      scope: "openid email profile",
      ux_mode: "redirect",
      state: stateToken,
      select_account: true,
      redirect_uri: redirectURL,
    });

    // Trigger the browser to navigate to google consent screen
    client.requestCode();
  }
}

// ----------------------------------------------------------------------------
//* Client SDK — the main class used by UI components
// ----------------------------------------------------------------------------

class SocialAuthClient {
  private providers = new Map<SocialProvider, SocialAuthProvider>();

  private register(provider: SocialAuthProvider) {
    this.providers.set(provider.provider, provider);
  }

  constructor() {
    this.register(new GoogleAuthProvider());
    //TODO: implement the other providers
  }

  //* Returns the SDK for a given provider
  getSDK(provider: SocialProvider): SocialAuthProvider {
    const authProvider = this.providers.get(provider);

    if (!authProvider) {
      throw new Error(`Social auth provider '${provider}' is not supported.`);
    }

    return authProvider;
  }

  //TODO: implement this in social buttons
  //* Preload a provider's SDK ahead of time
  async preload(provider: SocialProvider): Promise<void> {
    return await this.getSDK(provider).init();
  }

  //* Triggers the sign-in UX and resolves with a token/code for the backend
  async getToken(provider: SocialProvider): Promise<void> {
    return await this.getSDK(provider).authorize();
  }
}

export const socialAuthClient = new SocialAuthClient();
