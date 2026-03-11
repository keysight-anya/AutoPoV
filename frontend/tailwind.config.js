/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        gray: {
          850: '#1a2032',
          900: '#111827',
          950: '#090d1a',
        },
        primary: {
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
        },
        threat: {
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          900: '#1a0505',
        },
        warn: {
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          900: '#1a1005',
        },
        safe: {
          300: '#6ee7b7',
          400: '#34d399',
          500: '#10b981',
          900: '#051a10',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      }
    },
  },
  plugins: [],
}
