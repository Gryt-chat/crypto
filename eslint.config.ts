// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "**/*.js", "**/*.mjs", "**/*.cjs", "*.tgz"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  // Our own values get real types; existing debt is listed below, the goal is to empty it (GRYT-1792).
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-restricted-types": ["error", { types: { unknown: "Type it. If it's outside input being checked, list the file in the config with the reason." } }],
      "no-restricted-syntax": ["error", {
        selector: "TSAsExpression > TSAsExpression.expression[typeAnnotation.type='TSUnknownKeyword']",
        message: "Don't cast through unknown. Fix the types, or disable this line with the reason.",
      }],
      "no-nested-ternary": "error",
      eqeqeq: ["error", "smart"],
      "no-else-return": "error",
      "prefer-const": "error",
      "no-param-reassign": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports", disallowTypeAnnotations: false }],
    },
  },
  // unknown: socket payloads arrive unchecked and are validated there.
  {
    files: [
      "src/dm-key-binding.ts",
      "src/mls-person-key.ts",
    ],
    rules: { "@typescript-eslint/no-restricted-types": "off" },
  },
  // unknown: stored and parsed data arrives unchecked and is validated there.
  {
    files: [
      "src/history-chunks.ts",
      "src/identity-backup.ts",
      "src/pairing-envelope.ts",
    ],
    rules: { "@typescript-eslint/no-restricted-types": "off" },
  },
  // unknown: identity-vault checks a stored vault before using it; mls-provider's is inside the casts below.
  {
    files: [
      "src/identity-vault.ts",
      "src/mls-provider.ts",
    ],
    rules: { "@typescript-eslint/no-restricted-types": "off" },
  },
  // ts-mls types its keys as opaque, so mls-provider casts its raw x25519 keys to and from them.
  {
    files: [
      "src/mls-provider.ts",
    ],
    rules: { "no-restricted-syntax": "off" },
  },
);
