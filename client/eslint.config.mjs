import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import prettier from "eslint-config-prettier/flat";
import reactCompiler from "eslint-plugin-react-compiler";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  prettier,
  {
    plugins: {
      "react-compiler": reactCompiler,
    },
    rules: {
      // Custom Rules
      "no-unused-vars": "warn",
      "react/jsx-uses-vars": "error",
      "react-compiler/react-compiler": "error",
      "react-hooks/set-state-in-effect": "off",
      "react-hooks/immutability": "warn",
      "react/no-unescaped-entities": "off",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
  // Global Ignores
  globalIgnores([".next/**", "out/**", "build/**", "next-env.d.ts"]),
]);

export default eslintConfig;
