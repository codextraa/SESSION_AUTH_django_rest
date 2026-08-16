import {
  LoginErrorFields,
  TwoFAErrorFields,
  SocialLoginErrorFields,
  FCMTokenErrorFields,
} from "@/types/authTypes";

const formatErrorMsg = (msg: string): string =>
  msg.charAt(0).toUpperCase() + msg.slice(1);

//* Input Errors

export const loginInputError = (
  formInput: LoginErrorFields,
): LoginErrorFields => {
  const localErrors: LoginErrorFields = {};

  if (!formInput.email_or_username?.trim()) {
    localErrors.email_or_username = "Email or username is required.";
  }

  if (!formInput.password) {
    localErrors.password = "Password is required.";
  }

  if (!formInput.recaptcha_token) {
    localErrors.recaptcha_token = "Recaptcha token is required.";
  }

  if (!formInput.recaptcha_version) {
    localErrors.recaptcha_version = "Recaptcha version is required.";
  }

  return localErrors;
};

export const twoFAInputError = (
  formInput: TwoFAErrorFields,
): TwoFAErrorFields => {
  const localErrors: TwoFAErrorFields = {};

  if (!formInput.pre_auth_token) {
    localErrors.pre_auth_token = "Token is not generated.";
  }

  if (typeof formInput.otp !== "string" || !/^\d+$/.test(formInput.otp)) {
    localErrors.otp = "Invalid form data submission.";
  } else if (!formInput.otp) {
    localErrors.otp = "OTP is required.";
  }

  return localErrors;
};

//* Server Errors

export const loginServerError = (response: object): LoginErrorFields => {
  if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "object"
  ) {
    const backendErrors = response.error as Record<string, string[]>;

    const errorMessages: LoginErrorFields = {};

    if (backendErrors.email_or_username?.[0]) {
      errorMessages.email_or_username = formatErrorMsg(
        backendErrors.email_or_username[0],
      );
    }

    if (backendErrors.password?.[0]) {
      errorMessages.password = formatErrorMsg(backendErrors.password[0]);
    }

    if (backendErrors.recaptcha_token?.[0]) {
      errorMessages.recaptcha_token = formatErrorMsg(
        backendErrors.recaptcha_token[0],
      );
    }

    if (backendErrors.recaptcha_version?.[0]) {
      errorMessages.recaptcha_version = formatErrorMsg(
        backendErrors.recaptcha_version[0],
      );
    }

    return errorMessages;
  } else if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "string"
  ) {
    return {
      general: response.error,
    };
  }

  return {
    general: "An error occurred during login.",
  };
};

export const twoFAServerError = (response: object): TwoFAErrorFields => {
  if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "object"
  ) {
    const backendErrors = response.error as Record<string, string[]>;

    const errorMessages: TwoFAErrorFields = {};

    if (backendErrors.pre_auth_token?.[0]) {
      errorMessages.pre_auth_token = formatErrorMsg(
        backendErrors.pre_auth_token[0],
      );
    }

    if (backendErrors.otp?.[0]) {
      errorMessages.otp = formatErrorMsg(backendErrors.otp[0]);
    }
    return errorMessages;
  } else if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "string"
  ) {
    return {
      general: response.error,
    };
  }

  return {
    general: "An error occurred during login.",
  };
};

export const socialLoginServerError = (
  response: object,
): SocialLoginErrorFields => {
  if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "object"
  ) {
    const backendErrors = response.error as Record<string, string[]>;

    const errorMessages: SocialLoginErrorFields = {};

    if (backendErrors.provider?.[0]) {
      errorMessages.provider = formatErrorMsg(backendErrors.provider[0]);
    }

    if (backendErrors.social_auth_code?.[0]) {
      errorMessages.social_auth_code = formatErrorMsg(
        backendErrors.social_auth_token[0],
      );
    }

    if (backendErrors.redirect_uri?.[0]) {
      errorMessages.redirect_uri = formatErrorMsg(
        backendErrors.social_auth_token[0],
      );
    }

    return errorMessages;
  } else if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "string"
  ) {
    return {
      general: response.error,
    };
  }

  return {
    general: "An error occurred during login.",
  };
};

export const fcmTokenServerError = (response: object): FCMTokenErrorFields => {
  if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "object"
  ) {
    const backendErrors = response.error as Record<string, string[]>;

    const errorMessages: FCMTokenErrorFields = {};

    if (backendErrors.fcm_token?.[0]) {
      errorMessages.fcm_token = formatErrorMsg(backendErrors.fcm_token[0]);
    }

    return errorMessages;
  } else if (
    typeof response === "object" &&
    "error" in response &&
    response.error &&
    typeof response.error === "string"
  ) {
    return {
      general: response.error,
    };
  }

  return {
    general: "An error occurred during login.",
  };
};
