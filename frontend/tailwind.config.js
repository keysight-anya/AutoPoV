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
          // Deep slate-black backgrounds with a slight blue tint
          850: '#0e1222',
          900: '#0b0e1a',
          950: '#07090f',
        },
        // Primary accent → violet (replaces sky-blue)
        primary: {
          300: '#c4b5fd',
          400: '#a78bfa',
          500: '#8b5cf6',
          600: '#7c3aed',
          700: '#6d28d9',
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
        // All UI text: monospace — brutal hacker aesthetic
        sans:    ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
        mono:    ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
        // Headlines and hero text: condensed industrial
        display: ['"Barlow Condensed"', 'system-ui', 'sans-serif'],
      },
      letterSpacing: {
        widest: '.25em',
        code:   '.05em',
      },
      animation: {
        'fade-up':    'fadeUp .25s ease-out',
        'pulse-glow': 'pulseGlow 2s ease-in-out infinite',
        'blink':      'blink 1s step-start infinite',
      },
      keyframes: {
        fadeUp: {
          '0%':   { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseGlow: {
          '0%,100%': { opacity: '1' },
          '50%':     { opacity: '.4' },
        },
        blink: {
          '0%,100%': { opacity: '1' },
          '50%':     { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}
