// frontend/tailwind.config.js
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
        bg:       '#1a2330',
        surface1: '#1f2d3d',
        surface2: '#253545',
        accent:   '#fe7f2d',
        'accent-dim': 'rgba(254,127,45,0.12)',
        text1:    '#e8edf2',
        text2:    '#8ba3b8',
        text3:    '#4d6478',
        border1:  '#2a3a4a',
        border2:  '#334455',
        // severity
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#3b82f6',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
