import nextPlugin from "@next/eslint-plugin-next";
import globals from "globals";
import js from "@eslint/js";
import react from "eslint-plugin-react";

export default [
  js.configs.recommended, // Standard JavaScript rules
  {
    files: ["**/*.js", "**/*.mjs", "**/*.jsx", "**/*.ts", "**/*.tsx"],
    plugins: {
      "@next/next": nextPlugin,
      react,
    },
    rules: {
      ...nextPlugin.configs.recommended.rules, // Next.js recommended rules
      "no-unused-vars": "warn", // Custom rule for unused variables
      "react/jsx-uses-vars": "error",
    },
    languageOptions: {
      globals: {
        ...globals.browser, // Includes browser globals like `fetch`
        ...globals.node, // Includes Node.js globals like `process`
        myCustomGlobal: "readonly",
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
        sourceType: "module",
      },
    },
  },
];
