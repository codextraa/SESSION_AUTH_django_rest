import { 
  getAccessTokenFromSession,
  getCSRFTokenFromSession
} from "./cookie";


const HTTPS = process.env.HTTPS === 'true';

export class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.lastRequestTimes = new Map(); // Track last request times per endpoint
    this.THROTTLE_TIME = 2000; // 2 seconds
  };

  async throttle(endpoint) {
    const now = Date.now();
    const lastRequestTime = this.lastRequestTimes.get(endpoint) || 0;
    const timeSinceLastRequest = now - lastRequestTime;

    if (timeSinceLastRequest < this.THROTTLE_TIME) {
      const waitTime = this.THROTTLE_TIME - timeSinceLastRequest;
      console.warn(`Throttling: Waiting ${waitTime / 1000} seconds before sending request to ${endpoint}`);

      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    this.lastRequestTimes.set(endpoint, Date.now());
  }

  async handleErrors(response) {
    const contentType = response.headers.get("Content-Type") || "";
    // const clonedResponse = response.clone();

    if (response.ok) {
      if (contentType.includes("application/json")) {
        return await response.json(); // Parse JSON response
      };
    };

    if (response.status >= 400) {
      if (response.status === 401) {
        return { error: "Unauthorized. Please refresh the page. If this persists, login again." };
      };

      if (response.status === 429) {
        if (contentType.includes("application/json")) {
          const errorResponse = await response.json();
          const errorMessage = errorResponse.errors;

          try {
            const match = errorMessage.match(/(\d+) second(s)?/);
            return { error: `Validation already sent. Please try again in ${match[1]} seconds.` };
          } catch (error) {
            return { error: `Validation already sent. Please try again.` };
          };
        };
      };

      if (contentType.includes("application/json")) {
        try {
          const errorData = await response.json();
          if (errorData.errors) {
            return { error: errorData.errors }; // Return specific error
          };
        } catch (e) {
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
    };

    if (response.status >= 500) {
      return { error: "Server error" }; // Server-side error
    };

    throw new Error("Unexpected error occurred.");
  };

  async request(endpoint, method, data = null, additionalOptions = {}, isMultipart = false) {
    await this.throttle(endpoint);

    const accessToken = await getAccessTokenFromSession();
    const csrfToken = await getCSRFTokenFromSession();
    const url = `${this.baseURL}${endpoint}`;

    let options = {
      method,
      headers: {
        "Accept": "application/json",
        "Cookie": `csrftoken=${csrfToken}`,
        ...(accessToken && { Authorization: `Bearer ${accessToken}` }),
        ...(csrfToken && { "X-CSRFToken" : csrfToken }),
        ...(HTTPS && { "Referer": process.env.NEXT_PUBLIC_BASE_HTTPS_URL }),
      },
      credentials: "include",
      ...additionalOptions,
    };

    if (isMultipart && data instanceof FormData) {
      // For multipart/form-data
      delete options.headers["Content-Type"];
      options.body = data;
    } else if (data) {
      // For application/json
      options.headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(data);
    };

    try {
      const response = await fetch(url, options);
      return await this.handleErrors(response);
    } catch (error) {
      console.error("Fetch error:", error);
      throw error;
    };
  };

  async get(endpoint, additionalOptions = {}) {
    return await this.request(endpoint, "GET", null, additionalOptions);
  };

  async post(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "POST", data, additionalOptions, isMultipart);
  };

  async patch(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "PATCH", data, additionalOptions, isMultipart);
  };

  async put(endpoint, data, additionalOptions = {}, isMultipart = false) {
    return await this.request(endpoint, "PUT", data, additionalOptions, isMultipart);
  };

  async delete(endpoint, data = null, additionalOptions = {}) {
    return await this.request(endpoint, "DELETE", data, additionalOptions);
  };
};
