// ESLint flat config (ESLint 9 / Next 16). `eslint-config-next` ships a flat
// config array in Next 16, so it is spread directly — no FlatCompat shim.
// `next lint` is removed in Next 16; linting runs via the `lint` script
// (`eslint .`) and in CI.
import next from "eslint-config-next";

const eslintConfig = [
  ...next,
  {
    ignores: [".next/**", "node_modules/**", "next-env.d.ts"],
  },
];

export default eslintConfig;
