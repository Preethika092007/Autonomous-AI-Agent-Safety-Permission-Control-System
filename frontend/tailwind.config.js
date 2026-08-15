/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        darkBg: "#0a0b10",
        darkSurface: "#121420",
        darkBorder: "#1e2235",
      }
    },
  },
  plugins: [],
}
