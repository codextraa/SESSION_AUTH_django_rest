import { getSessionIdFromSession, getCSRFTokenFromSession } from "./cookie";

const HTTPS = process.env.HTTPS === "true";

export class ApiClient {
  private baseURL: string;
  private lastRequestTimes: Map<string, number>; // Track last request times per endpoint
  private THROTTLE_TIME: number; // 2 seconds

  constructor(baseURL: string) {
    this.baseURL = baseURL;
    this.lastRequestTimes = new Map<string, number>(); // Track last request times per endpoint
    this.THROTTLE_TIME = 2000; // 2 seconds
  }

  async throttle(endpoint: string): Promise<void> {
    const now = Date.now();
    const lastRequestTime = this.lastRequestTimes.get(endpoint) || 0;
    const timeSinceLastRequest = now - lastRequestTime;

    if (timeSinceLastRequest < this.THROTTLE_TIME) {
      const waitTime = this.THROTTLE_TIME - timeSinceLastRequest;
      console.warn(
        `Throttling: Waiting ${waitTime / 1000} seconds before sending request to ${endpoint}`,
      );

      await new Promise<void>((resolve) => setTimeout(resolve, waitTime));
    }

    this.lastRequestTimes.set(endpoint, Date.now());
  }

  async handleErrors(response: Response): Promise<unknown> {
    const contentType = response.headers.get("Content-Type") || "";
    // const clonedResponse = response.clone();

    if (response.ok) {
      if (contentType.includes("application/json")) {
        return await response.json(); // Parse JSON response
      }
    }

    if (response.status >= 400) {
      if (response.status === 401) {
        return {
          error:
            "Unauthorized. Please refresh the page. If this persists, login again.",
        };
      }

      if (response.status === 429) {
        if (contentType.includes("application/json")) {
          const errorResponse = await response.json();
          const errorMessage = errorResponse.errors;

          try {
            const match = errorMessage.match(/(\d+) second(s)?/);
            return {
              error: `Validation already sent. Please try again in ${match[1]} seconds.`,
            };
          } catch (error) {
            console.error("Error parsing error message:", error);
            return { error: `Validation already sent. Please try again.` };
          }
        }
      }

      if (contentType.includes("application/json")) {
        try {
          const errorData = await response.json();
          if (errorData.errors) {
            return { error: errorData.errors }; // Return specific error
          }
        } catch (e) {
          console.error("Error parsing error response:", e);
          return { error: "Unexpected error occurred." };
        }
      } else {
        return { error: "Unexpected error occurred." };
      }

      // try { // only for debugging
      //   // Non-JSON error response
      //   const errorText = await clonedResponse.text();

      //   // Handle the error message here
      //   return { error: errorText || 'Unexpected error occurred. Something went wrong' };
      // } catch (err) {
      //   console.error('Error while reading the error response body:', err);
      //   return { error: 'Unexpected error occurred. Something went wrong' };
      // };
    }

    if (response.status >= 500) {
      return { error: "Server error" }; // Server-side error
    }

    throw new Error("Unexpected error occurred.");
  }

  async request<T>(
    endpoint: string,
    method: string,
    data: object | null = null,
    additionalOptions: RequestInit = {},
    isMultipart: boolean = false,
  ): Promise<T> {
    await this.throttle(endpoint);

    const sessionid = await getSessionIdFromSession();
    const csrfToken = await getCSRFTokenFromSession();
    const url = `${this.baseURL}${endpoint}`;

    let cookieHeader = "";

    if (csrfToken) {
      cookieHeader += `csrftoken=${csrfToken}; `;
    }

    if (sessionid) {
      cookieHeader += `sessionid=${sessionid};`;
    }

    const customHeaders: Record<string, string> = {
      Accept: "application/json",
      ...(cookieHeader && { Cookie: cookieHeader.trim() }),
      ...(csrfToken && { "X-CSRFToken": csrfToken }),
      "NEXT-X-API-KEY": process.env.NEXT_PUBLIC_API_SECRET_KEY || "",
      ...(HTTPS && { Referer: process.env.NEXT_PUBLIC_BASE_HTTPS_URL || "" }),
    };

    const options: RequestInit = {
      method,
      headers: customHeaders,
      credentials: "include",
      ...additionalOptions,
    };

    if (isMultipart && data instanceof FormData) {
      // For multipart/form-data
      delete customHeaders["Content-Type"];
      options.body = data;
    } else if (data) {
      // For application/json
      customHeaders["Content-Type"] = "application/json";
      options.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, options);
      return (await this.handleErrors(response)) as T;
    } catch (error) {
      console.error("Fetch error:", error);
      throw error;
    }
  }

  async get<T>(
    endpoint: string,
    additionalOptions: RequestInit = {},
  ): Promise<T> {
    return await this.request<T>(endpoint, "GET", null, additionalOptions);
  }

  async post<T>(
    endpoint: string,
    data: object | null = null,
    additionalOptions: RequestInit = {},
    isMultipart: boolean = false,
  ): Promise<T> {
    return await this.request<T>(
      endpoint,
      "POST",
      data,
      additionalOptions,
      isMultipart,
    );
  }

  async patch<T>(
    endpoint: string,
    data: object | null = null,
    additionalOptions: RequestInit = {},
    isMultipart: boolean = false,
  ): Promise<T> {
    return await this.request<T>(
      endpoint,
      "PATCH",
      data,
      additionalOptions,
      isMultipart,
    );
  }

  async put<T>(
    endpoint: string,
    data: object | null = null,
    additionalOptions: RequestInit = {},
    isMultipart: boolean = false,
  ): Promise<T> {
    return await this.request<T>(
      endpoint,
      "PUT",
      data,
      additionalOptions,
      isMultipart,
    );
  }

  async delete<T>(
    endpoint: string,
    data: object | null = null,
    additionalOptions: RequestInit = {},
  ): Promise<T> {
    return await this.request<T>(endpoint, "DELETE", data, additionalOptions);
  }
}
