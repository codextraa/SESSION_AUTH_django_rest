"use server";

import { createUser } from "@/libs/api";
import {
  CreateUserErrorResponse,
  SignUpFormState,
  CreateUserData,
  SignUpErrorResponse,
  SignUpPasswordErrorResponse,
} from "@/types/types";

const userError = async (
  response: CreateUserErrorResponse,
): Promise<CreateUserErrorResponse> => {
  if (response.error && typeof response.error === "object") {
    const errorMessages: SignUpErrorResponse = {};

    if (response.error.email) {
      errorMessages.email =
        response.error.email[0][0].toUpperCase() +
        response.error.email[0].slice(1).toLowerCase();
    }

    if (response.error.username) {
      errorMessages.username =
        response.error.username[0][0].toUpperCase() +
        response.error.username[0].slice(1).toLowerCase();
    }
    if (response.error.first_name) {
      errorMessages.first_name =
        response.error.first_name[0][0].toUpperCase() +
        response.error.first_name[0].slice(1).toLowerCase();
    }
    if (response.error.last_name) {
      errorMessages.last_name =
        response.error.last_name[0][0].toUpperCase() +
        response.error.last_name[0].slice(1).toLowerCase();
    }
    if (response.error.phone_number) {
      errorMessages.phone_number =
        response.error.phone_number[0][0].toUpperCase() +
        response.error.phone_number[0].slice(1).toLowerCase();
    }
    if (
      response.error.password &&
      typeof response.error.password === "object"
    ) {
      const passErrorMessages: string[] = [];
      const error = response.error.password as SignUpPasswordErrorResponse;

      if (error.short) passErrorMessages.push(...[error.short]);
      if (error.upper) passErrorMessages.push(...[error.upper]);
      if (error.lower) passErrorMessages.push(...[error.lower]);
      if (error.number) passErrorMessages.push(...[error.number]);
      if (error.special) passErrorMessages.push(...[error.special]);

      if (passErrorMessages.length > 0) {
        errorMessages.password = passErrorMessages.join(" ");
      } else {
        errorMessages.password = response.error.password;
      }
    }
    return { error: errorMessages };
  }
  return {
    error: { global: response.error },
  };
};

export const createUserAction = async (
  prevState: SignUpFormState | undefined,
  formData: FormData,
): Promise<SignUpFormState> => {
  const email = formData.get("email")?.toString().trim() || "";
  const password = formData.get("password")?.toString().trim() || "";
  const c_password = formData.get("c_password")?.toString().trim() || "";
  const username = formData.get("username")?.toString().trim() || "";
  const first_name = formData.get("first_name")?.toString().trim() || "";
  const last_name = formData.get("last_name")?.toString().trim() || "";
  const phone_number = formData.get("phone_number")?.toString().trim() || "";
  const is_staff = formData.get("is_staff")?.toString() === "true";

  const localErrors: SignUpErrorResponse = {
    email: "",
    username: "",
    password: "",
    c_password: "",
  };

  if (!email) {
    localErrors.email = "Email is required.";
  } else if (email && typeof email === "string" && !email.includes("@")) {
    localErrors.email = "Invalid email format.";
  }

  if (!username) {
    localErrors.username = "Username is required.";
  }

  if (!password) {
    localErrors.password = "Password is required.";
  }

  if (!c_password) {
    localErrors.c_password = "Password confirmation is required.";
  }

  if (password && c_password && password !== c_password) {
    localErrors.c_password = "Passwords do not match.";
  }

  if (Object.keys(localErrors).length > 0) {
    return {
      error: localErrors,
      email: email,
      username: username,
      password: password,
      c_password: c_password,
      ...(first_name && { first_name: first_name }),
      ...(last_name && { last_name: last_name }),
      ...(phone_number && { phone_number: phone_number }),
      ...(is_staff && { is_staff: is_staff }),
    };
  }

  // Structural composition mapping payload variables cleanly
  const data: CreateUserData = {
    email: email,
    password: password,
    c_password: c_password,
    username: username,
    ...(first_name && { first_name: first_name }),
    ...(last_name && { last_name: last_name }),
    ...(phone_number && { phone_number: phone_number }),
    ...(is_staff && { is_staff: is_staff }),
  };

  try {
    const response = await createUser(data);

    // If response carries validation dictionary payload faults
    if (response && ("error" in response || !("success" in response))) {
      const backendError = await userError(response);
      return {
        error: backendError.error,
        email: email,
        username: username,
        password: password,
        c_password: c_password,
        ...(first_name && { first_name: first_name }),
        ...(last_name && { last_name: last_name }),
        ...(phone_number && { phone_number: phone_number }),
        ...(is_staff && { is_staff: is_staff }),
      };
    }

    return {
      success: response.success,
      email: email,
      username: username,
      password: password,
      c_password: c_password,
      ...(first_name && { first_name: first_name }),
      ...(last_name && { last_name: last_name }),
      ...(phone_number && { phone_number: phone_number }),
      ...(is_staff && { is_staff: is_staff }),
    };
  } catch (error: unknown) {
    console.error(error);
    return {
      error: { global: "Failed to create user." },
      email: email,
      username: username,
      password: password,
      c_password: c_password,
      ...(first_name && { first_name: first_name }),
      ...(last_name && { last_name: last_name }),
      ...(phone_number && { phone_number: phone_number }),
      ...(is_staff && { is_staff: is_staff }),
    };
  }
};
